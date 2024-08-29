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
        std::vector<byte> vec(data, data + sizeof(data) / sizeof(data[0]));
        dlog::debug("[Preloader] scrt_common_main_address: %s", bytes_to_string(vec));
        // Hook the functions.
        g_scrt_common_main_hook = safetyhook::create_inline(
            reinterpret_cast<void*>(scrt_common_main_address),
            reinterpret_cast<void*>(hooked_scrt_common_main)
        );
        std::memcpy(data, (void*)scrt_common_main_address, 10);
        dlog::debug("[Preloader] hooked scrt_common_main_address: {:x}", *data);

        std::memcpy(data, (void*)winmain_address, 10);
        dlog::debug("[Preloader] winmain_address: {:x}", *data);
        g_win_main_hook = safetyhook::create_inline(
            reinterpret_cast<void*>(winmain_address),
            reinterpret_cast<void*>(hooked_win_main)
        );
        std::memcpy(data, (void*)winmain_address, 10);
        dlog::debug("[Preloader] hooked winmain_address: {:x}", *data);

        std::memcpy(data, (void*)mhmain_ctor_address, 10);
        dlog::debug("[Preloader] mhmain_ctor_address: {:x}", *data);
        g_mh_main_ctor_hook = safetyhook::create_inline(
            reinterpret_cast<void*>(mhmain_ctor_address),
            reinterpret_cast<void*>(hooked_mh_main_ctor)
        );
        std::memcpy(data, (void*)mhmain_ctor_address, 10);
        dlog::debug("[Preloader] hooked mhmain_ctor_address: {:x}", *data);

        // Unhook this function and call the original
        g_get_system_time_as_file_time_hook = {};
        GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
        return;
    }

    // Not the expected return address, just proxy to real function.
    g_get_system_time_as_file_time_hook.call<LPFILETIME>(lpSystemTimeAsFileTime);
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
  
   dlog::debug("[Preloader] security_cookie pointer: 0x{:X}", *security_cookie);

   DWORD old_protect;
   if (!VirtualProtect((LPVOID)security_cookie, sizeof(security_cookie), PAGE_READWRITE, &old_protect)) {
     dlog::debug("[Preloader] Setting permissions (PAGE_READWRITE) on security_cookie memory failed");
     return;
   }

   *security_cookie = MSVC_DEFAULT_SECURITY_COOKIE_VALUE;

   if (!VirtualProtect((LPVOID)security_cookie, sizeof(security_cookie), old_protect, &old_protect)) {
     dlog::debug("[Preloader] Restoring permissions on security_cookie memory failed");
     return;
   }

    g_get_system_time_as_file_time_hook = safetyhook::create_inline(
        reinterpret_cast<void*>(GetSystemTimeAsFileTime),
        reinterpret_cast<void*>(hooked_get_system_time_as_file_time)
    );
}
