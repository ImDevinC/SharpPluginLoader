#pragma once
#include "Log.h"

#include <intsafe.h>
#include <string>
#include <sstream>

class HResultHandler {
public:
    static inline void Handle(HRESULT hr, const char* file, int line) {
        if (FAILED(hr)) {
            std::ostringstream oss;
            oss << "0x" << std::hex << hr << std::endl;
            dlog::error("HRESULT failed: {:s} at {}:{}", oss.str(), file, line);
            std::terminate();
        }
    }

    static inline void Handle(HRESULT hr, const char* file, int line, const char* msg) {
        if (FAILED(hr)) {
            std::ostringstream oss;
            oss << "0x" << std::hex << hr << std::endl;
            dlog::error("HRESULT failed: {:s} at {}:{}", oss.str(), file, line);
            dlog::error("Message: {}", msg);
            std::terminate();
        }
    }
};

#define HandleResult(hr) HResultHandler::Handle(hr, __FILE__, __LINE__)
#define HandleResultMsg(hr, msg) HResultHandler::Handle(hr, __FILE__, __LINE__, msg)
