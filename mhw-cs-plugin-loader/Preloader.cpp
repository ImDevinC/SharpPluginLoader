#include <algorithm>
#include <cstdint>
#include <string>
#include <cstring>
#include <sstream>
#include <thread>
#include <iomanip>
#include <iostream>

#include <wil/resource.h>
#include <wil/stl.h>
#include <wil/win32_helpers.h>
#include <windows.h>

#include <safetyhook/safetyhook.hpp>

#include "AddressRepository.h"
#include "NativePluginFramework.h"
#include "CoreClr.h"
#include "Log.h"
#include "Preloader.h"
#include "PatternScan.h"
#include "LoaderConfig.h"

#pragma intrinsic(_ReturnAddress)

#ifdef _WIN64
#define DEFAULT_SECURITY_COOKIE_64  (((ULONGLONG)0x00002b99 << 32) | 0x2ddfa232)
#endif
#define DEFAULT_SECURITY_COOKIE_32  0xbb40e64e
#define DEFAULT_SECURITY_COOKIE_16  (DEFAULT_SECURITY_COOKIE_32 >> 16)

SafetyHookInline g_get_system_time_as_file_time_hook{};
SafetyHookInline g_win_main_hook{};
SafetyHookInline g_scrt_common_main_hook{};
SafetyHookInline g_mh_main_ctor_hook{};

CoreClr* s_coreclr = nullptr;
NativePluginFramework* s_framework = nullptr;
AddressRepository* s_address_repository = nullptr;

// The default value that MSVC uses for the IMAGE_LOAD_CONFIG_DIRECTORY64.SecurityCookie.
const uint64_t MSVC_DEFAULT_SECURITY_COOKIE_VALUE = 0x2B992DDFA232L;

void open_console() {
    AllocConsole();
    FILE* cin_stream;
    FILE* cout_stream;
    FILE* cerr_stream;
    freopen_s(&cin_stream, "CONIN$", "r", stdin);
    freopen_s(&cout_stream, "CONOUT$", "w", stdout);
    freopen_s(&cerr_stream, "CONOUT$", "w", stderr);

    // From: https://stackoverflow.com/a/45622802 to deal with UTF8 CP:
    SetConsoleOutputCP(CP_UTF8);
    setvbuf(stdout, nullptr, _IOFBF, 1000);
}

// Returns pointer to the IMAGE_LOAD_CONFIG_DIRECTORY64.SecurityCookie value.
uint64_t* get_security_cookie_pointer() {
    auto image_base = (uint64_t)GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)image_base;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(image_base + dos_header->e_lfanew);
    if (nt_headers->OptionalHeader.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) {
        auto load_config_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
        if (load_config_directory.VirtualAddress != 0 && load_config_directory.Size != 0) {
            IMAGE_LOAD_CONFIG_DIRECTORY64* load_config = (IMAGE_LOAD_CONFIG_DIRECTORY64*)(image_base + load_config_directory.VirtualAddress);
            return (uint64_t*)load_config->SecurityCookie;
        }
    }

    return nullptr;
}

// This hooks the __scrt_common_main_seh MSVC function.
// This runs before all of the CRT initalization, static initalizers, and WinMain.
__declspec(noinline) int64_t hooked_scrt_common_main() {
    dlog::info("[Preloader] Initializing CLR / NativePluginFramework");
    s_coreclr = new CoreClr();
    s_framework = new NativePluginFramework(s_coreclr, s_address_repository);
    dlog::info("[Preloader] Initialized");

    s_framework->trigger_on_pre_main();

    return g_scrt_common_main_hook.call<int64_t>();
}

__declspec(noinline) int __stdcall hooked_win_main(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    s_framework->trigger_on_win_main();
    return g_win_main_hook.call<int>(hInstance, hPrevInstance, lpCmdLine, nShowCmd);
}

__declspec(noinline) void* hooked_mh_main_ctor(void* this_ptr) {
    auto result = g_mh_main_ctor_hook.call<void*>(this_ptr);
    s_framework->trigger_on_mh_main_ctor();
    return result;
}


// Checks if the given address is within the `__security_init_cookie` function (pre-MSVC).
//
// In order to verify that we are being called from within `__security_init_cookie`, we:
//
// 1. Validate that the return address is within the main .exe image address space.
// This is needed this cookie setup will happen within various DLLs that are either
// loaded as imports, or injected (overlays, anti-malware, etc).
//
// 2. Iterate backwards from the return address and check for the default cookie value
// The default cookie value will be directly embedded in one of the instructions prior
// to the GetSystemTimeAsFileTime call, (e.g. `mov rbx, 2B992DDFA232h`).
//
// We iterate (rather than using a fixed offset) for resilency in case the instructions
// get reordered/shifted across different builds.
bool is_main_game_security_init_cookie_call(uint64_t return_address) {
    const auto module = GetModuleHandleA(NULL);

    MODULEINFO module_info;
    if (!GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(module_info))) {
        dlog::error("[Preloader] GetModuleInformation failed in is_main_game_security_init_cookie_call!");
        return false;
    }

    const uint64_t exe_start = (uint64_t)module;
    const uint64_t exe_end = (uint64_t)module + module_info.SizeOfImage;

    if (return_address > exe_start && return_address < exe_end) {
        for (size_t i = 0; i < 64; i++) {
            if (*(uint64_t*)(return_address - i) == MSVC_DEFAULT_SECURITY_COOKIE_VALUE) {
                return true;
            }
        }
    }
    return false;
}

// Helper function for parsing a x86 relative call instruction.
uintptr_t resolve_x86_relative_call(uintptr_t call_address) {
    return (call_address + 5) + *(int32_t*)(call_address + 1);
}

std::string bytes_to_string(const std::vector<BYTE>& bytes) {
  auto out_stream = std::ostringstream();
  for (SIZE_T i = 0; i < bytes.size(); i++) {
    if (i > 0) out_stream << ",";
    out_stream << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << static_cast<const UINT32>(bytes[i]);
  }
  return out_stream.str();
}

// The hooked GetSystemTimeAsFileTime function.
// This function is called in many places, one of them being the
// `__security_init_cookie` function that is used to setup the security token(s)
// before SCRT_COMMON_MAIN_SEH is called.
void hooked_get_system_time_as_file_time(LPFILETIME lpSystemTimeAsFileTime) {
    uint64_t ret_address = (uint64_t)_ReturnAddress();
    if (true || is_main_game_security_init_cookie_call(ret_address)) {
        // The game has been unpacked in memory (for steam DRM or possibly Enigma in the future),
        // start scanning for the core/main functions we want to hook.
        s_address_repository = new AddressRepository();
        s_address_repository->initialize();

        const auto scrt_common_main_address = s_address_repository->get("Core::ScrtCommonMain");
        if (scrt_common_main_address == 0) {
            dlog::error("[Preloader] Failed to find __scrt_common_main_seh address");
            return;
        }
        dlog::debug("[Preloader] Resolved address for __scrt_common_main_seh: 0x{:X}", scrt_common_main_address);

        // We parse this one from the call to WinMain rather than searching for the WinMain code itself,
        // since that has changed drastically in previous patches (e.g. when they removed anti-debug stuff).
        const auto winmain_call_address = s_address_repository->get("Core::WinMainCall");
        if (winmain_call_address == 0) {
            dlog::error("[Preloader] Failed to find WinMain call address");
            return;
        }
        uintptr_t winmain_address = resolve_x86_relative_call(winmain_call_address);
        dlog::debug("[Preloader] Resolved address for WinMain: 0x{:X}", winmain_address);

        const auto mhmain_ctor_address = s_address_repository->get("Core::MhMainCtor");
        if (mhmain_ctor_address == 0) {
            dlog::error("[Preloader] Failed to find sMhMain::ctor address");
            return;
        }
        dlog::debug("[Preloader] Resolved address for sMhMain::ctor: 0x{:X}", mhmain_ctor_address);

        byte data[10];
        std::memcpy(data, (void*)scrt_common_main_address, 10);
        std::vector<byte> scrt_vec(data, data + sizeof(data) / sizeof(data[0]));
        dlog::debug("[Preloader] scrt_common_main_address: {:s}", bytes_to_string(scrt_vec));
        // Hook the functions.
        g_scrt_common_main_hook = safetyhook::create_inline(
            reinterpret_cast<void*>(scrt_common_main_address),
            reinterpret_cast<void*>(hooked_scrt_common_main)
        );
        std::memcpy(data, (void*)scrt_common_main_address, 10);
        std::vector<byte> scrt_hooked_vec(data, data + sizeof(data) / sizeof(data[0]));
        dlog::debug("[Preloader] hooked scrt_common_main_address: {:s}", bytes_to_string(scrt_hooked_vec));

        std::memcpy(data, (void*)winmain_address, 10);
        std::vector<byte> winmain_vec(data, data + sizeof(data) / sizeof(data[0]));
        dlog::debug("[Preloader] winmain_address: {:s}", bytes_to_string(winmain_vec));
        g_win_main_hook = safetyhook::create_inline(
            reinterpret_cast<void*>(winmain_address),
            reinterpret_cast<void*>(hooked_win_main)
        );
        std::memcpy(data, (void*)winmain_address, 10);
        std::vector<byte> winmain_hooked_vec(data, data + sizeof(data) / sizeof(data[0]));
        dlog::debug("[Preloader] hooked winmain_address: {:s}", bytes_to_string(winmain_hooked_vec));

        std::memcpy(data, (void*)mhmain_ctor_address, 10);
        std::vector<byte> mhmain_vec(data, data + sizeof(data) / sizeof(data[0]));
        dlog::debug("[Preloader] mhmain_ctor_address: {:s}", bytes_to_string(mhmain_vec));
        g_mh_main_ctor_hook = safetyhook::create_inline(
            reinterpret_cast<void*>(mhmain_ctor_address),
            reinterpret_cast<void*>(hooked_mh_main_ctor)
        );
        std::memcpy(data, (void*)mhmain_ctor_address, 10);
        std::vector<byte> mhmain_hooked_vec(data, data + sizeof(data) / sizeof(data[0]));
        dlog::debug("[Preloader] hooked mhmain_ctor_address: {:s}", bytes_to_string(mhmain_hooked_vec));

        // Unhook this function and call the original
        g_get_system_time_as_file_time_hook = {};
        GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
        return;
    }

    // Not the expected return address, just proxy to real function.
    g_get_system_time_as_file_time_hook.call<LPFILETIME>(lpSystemTimeAsFileTime);
}

ULONG WINAPI RtlRandom (PULONG seed)
{
    static ULONG saved_value[128] =
    { /*   0 */ 0x4c8bc0aa, 0x4c022957, 0x2232827a, 0x2f1e7626, 0x7f8bdafb, 0x5c37d02a, 0x0ab48f72, 0x2f0c4ffa,
      /*   8 */ 0x290e1954, 0x6b635f23, 0x5d3885c0, 0x74b49ff8, 0x5155fa54, 0x6214ad3f, 0x111e9c29, 0x242a3a09,
      /*  16 */ 0x75932ae1, 0x40ac432e, 0x54f7ba7a, 0x585ccbd5, 0x6df5c727, 0x0374dad1, 0x7112b3f1, 0x735fc311,
      /*  24 */ 0x404331a9, 0x74d97781, 0x64495118, 0x323e04be, 0x5974b425, 0x4862e393, 0x62389c1d, 0x28a68b82,
      /*  32 */ 0x0f95da37, 0x7a50bbc6, 0x09b0091c, 0x22cdb7b4, 0x4faaed26, 0x66417ccd, 0x189e4bfa, 0x1ce4e8dd,
      /*  40 */ 0x5274c742, 0x3bdcf4dc, 0x2d94e907, 0x32eac016, 0x26d33ca3, 0x60415a8a, 0x31f57880, 0x68c8aa52,
      /*  48 */ 0x23eb16da, 0x6204f4a1, 0x373927c1, 0x0d24eb7c, 0x06dd7379, 0x2b3be507, 0x0f9c55b1, 0x2c7925eb,
      /*  56 */ 0x36d67c9a, 0x42f831d9, 0x5e3961cb, 0x65d637a8, 0x24bb3820, 0x4d08e33d, 0x2188754f, 0x147e409e,
      /*  64 */ 0x6a9620a0, 0x62e26657, 0x7bd8ce81, 0x11da0abb, 0x5f9e7b50, 0x23e444b6, 0x25920c78, 0x5fc894f0,
      /*  72 */ 0x5e338cbb, 0x404237fd, 0x1d60f80f, 0x320a1743, 0x76013d2b, 0x070294ee, 0x695e243b, 0x56b177fd,
      /*  80 */ 0x752492e1, 0x6decd52f, 0x125f5219, 0x139d2e78, 0x1898d11e, 0x2f7ee785, 0x4db405d8, 0x1a028a35,
      /*  88 */ 0x63f6f323, 0x1f6d0078, 0x307cfd67, 0x3f32a78a, 0x6980796c, 0x462b3d83, 0x34b639f2, 0x53fce379,
      /*  96 */ 0x74ba50f4, 0x1abc2c4b, 0x5eeaeb8d, 0x335a7a0d, 0x3973dd20, 0x0462d66b, 0x159813ff, 0x1e4643fd,
      /* 104 */ 0x06bc5c62, 0x3115e3fc, 0x09101613, 0x47af2515, 0x4f11ec54, 0x78b99911, 0x3db8dd44, 0x1ec10b9b,
      /* 112 */ 0x5b5506ca, 0x773ce092, 0x567be81a, 0x5475b975, 0x7a2cde1a, 0x494536f5, 0x34737bb4, 0x76d9750b,
      /* 120 */ 0x2a1f6232, 0x2e49644d, 0x7dddcbe7, 0x500cebdb, 0x619dab9e, 0x48c626fe, 0x1cda3193, 0x52dabe9d };
    ULONG rand;
    int pos;
    ULONG result;

    rand = (*seed * 0x7fffffed + 0x7fffffc3) % 0x7fffffff;
    *seed = (rand * 0x7fffffed + 0x7fffffc3) % 0x7fffffff;
    pos = *seed & 0x7f;
    result = saved_value[pos];
    saved_value[pos] = rand;
    return(result);
}

static void set_security_cookie(uint64_t *cookie) {
  static ULONG seed;
  dlog::debug("[Preloader] Initializing security cookie {:p}", cookie);
  if (!seed) {
    //seed = NtGetTickCount() ^ GetCurrentProcessId();
    seed = GetCurrentProcessId();
  }
  for (;;) {
    if (*cookie == DEFAULT_SECURITY_COOKIE_16) {
      dlog::debug("[Preloader] Found a 16bit cookie");
      *cookie = RtlRandom(&seed) >> 16;
    } else if (*cookie == DEFAULT_SECURITY_COOKIE_32) {
      dlog::debug("[Preloader] Found a 32bit cookie");
      *cookie = RtlRandom(&seed);
#ifdef DEFAULT_SECURITY_COOKIE_64
    } else if (*cookie == DEFAULT_SECURITY_COOKIE_64) {
      dlog::debug("[Preloader] Found a 64bit cookie);
      *cookie = RtlRandom(&seed);
      *cookie ^= (ULONG_PTR)RtlRandom(&seed) << 16;
#endif
    } else {
      break;
    }
  }
}


// This function is called from the loader-locked DllMain.
// It does the bare-minimum to get control flow in the main thread
// by hooking a function called in the CRT startup (GetSystemTimeAsFileTime).
//
// This allows us to work with both the SteamDRM and Steamless unpacked
// binaries by detecting the first call to the hooked function _after_
// the executable is unpacked in memory.
void initialize_preloader() {
    auto& loader_config = preloader::LoaderConfig::get();
    if (loader_config.get_log_cmd()) {
        open_console();
    }

   uint64_t* security_cookie = get_security_cookie_pointer();
   if (security_cookie == nullptr) {
       dlog::error("[Preloader] Failed to get security cookie pointer from PE header!");
       return;
   }

    // Reset the processes' security cookie to the default value to make the
    // MSVC startup code to attempt to initalize it to a new value, which will 
    // cause our hooked GetSystemTimeAsFileTime to be called pre-CRT init.
  
   dlog::debug("[Preloader] security_cookie pointer: 0x{:p}", (void *)security_cookie);

   set_security_cookie(security_cookie);
   //DWORD old_protect;
   //if (!VirtualProtect((LPVOID)security_cookie, sizeof(security_cookie), PAGE_READWRITE, &old_protect)) {
   //  dlog::debug("[Preloader] Setting permissions (PAGE_READWRITE) on security_cookie memory failed");
   //  return;
   //}

   //uint64_t* security_cookie_complement = reinterpret_cast<uint64_t*>(0x144BF20E0);
   //*security_cookie = MSVC_DEFAULT_SECURITY_COOKIE_VALUE;
   //*security_cookie_complement = ~MSVC_DEFAULT_SECURITY_COOKIE_VALUE;

   //if (!VirtualProtect((LPVOID)security_cookie, sizeof(security_cookie), old_protect, &old_protect)) {
   //  dlog::debug("[Preloader] Restoring permissions on security_cookie memory failed");
   //  return;
   //}

    g_get_system_time_as_file_time_hook = safetyhook::create_inline(
        reinterpret_cast<void*>(GetSystemTimeAsFileTime),
        reinterpret_cast<void*>(hooked_get_system_time_as_file_time)
    );
}
