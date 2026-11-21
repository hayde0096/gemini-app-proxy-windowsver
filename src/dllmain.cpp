#include "config.h"
#include "hooks.h"
#include "logger.h"

#include <string>
#include <windows.h>

namespace {

std::wstring GetProcessTypeFromCmdLine() {
    const wchar_t* cmd = GetCommandLineW();
    if (!cmd) return {};
    std::wstring s(cmd);

    const std::wstring key = L"--type=";
    size_t pos = s.find(key);
    if (pos == std::wstring::npos) {
        return L"main";
    }
    pos += key.size();
    size_t end = s.find_first_of(L" \t\"", pos);
    return (end == std::wstring::npos) ? s.substr(pos) : s.substr(pos, end - pos);
}

bool ShouldHookCurrentProcess(const std::wstring& procType) {
    // Hook the main Electron process and utility processes (including Chromium NetworkService).
    // Skip renderer, gpu-process, crashpad-handler, zygote, etc. to avoid sandbox noise & overhead.
    if (procType == L"main") return true;
    if (procType == L"utility") return true;
    return false;
}

DWORD WINAPI DelayedInitThread(LPVOID) {
    gproxy::InstallHooks();
    return 0;
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)lpvReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);

        std::wstring procType = GetProcessTypeFromCmdLine();
        if (!ShouldHookCurrentProcess(procType)) {
            return TRUE;
        }

        bool hasConfig = gproxy::LoadConfig(hinstDLL);
        const auto& cfg = gproxy::GetConfig();

        gproxy::InitLogger(cfg.log_file, cfg.log_level);

        char typeBuf[64] = {};
        WideCharToMultiByte(CP_UTF8, 0, procType.c_str(), -1, typeBuf, sizeof(typeBuf), nullptr, nullptr);
        gproxy::LogInfo("gemini-app-proxy loaded in [%s] process (config=%s, enabled=%d, proxy=%s://%s:%u, quic_block=%d, remote_dns=%d)",
                        typeBuf,
                        hasConfig ? "found" : "defaults",
                        cfg.enabled ? 1 : 0,
                        cfg.type == gproxy::ProxyType::Http ? "http" : "socks5",
                        cfg.host.c_str(),
                        cfg.port,
                        cfg.block_quic ? 1 : 0,
                        cfg.remote_dns ? 1 : 0);

        if (!cfg.enabled) {
            return TRUE;
        }

        if (GetModuleHandleW(L"ws2_32.dll") != nullptr) {
            gproxy::InstallHooks();
        } else {
            HANDLE hThread = CreateThread(nullptr, 0, DelayedInitThread, nullptr, 0, nullptr);
            if (hThread) {
                CloseHandle(hThread);
            }
        }
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        if (lpvReserved == nullptr) {
            gproxy::RemoveHooks();
            gproxy::CloseLogger();
        }
    }
    return TRUE;
}
