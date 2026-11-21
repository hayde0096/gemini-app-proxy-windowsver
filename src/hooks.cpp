#include "hooks.h"

#include "config.h"
#include "logger.h"
#include "proxy_client.h"

#include <MinHook.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include <mutex>
#include <string>
#include <unordered_map>

namespace gproxy {

namespace {

// Thread-local re-entrancy guard to prevent double interception when Winsock APIs call each other
thread_local bool g_inHook = false;

struct HookGuard {
    bool entered = false;
    HookGuard() {
        if (!g_inHook) {
            g_inHook = true;
            entered = true;
        }
    }
    ~HookGuard() {
        if (entered) {
            g_inHook = false;
        }
    }
};

// Passive DNS cache: IP string -> resolved hostname (used for remote DNS over SOCKS5/HTTP)
std::mutex g_dnsMutex;
std::unordered_map<std::string, std::string> g_ipToHost;
constexpr size_t kMaxDnsCacheEntries = 2048;

std::string WideToUtf8(const wchar_t* ws) {
    if (!ws || !*ws) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return {};
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

bool IsIpLiteral(const std::string& host) {
    in_addr v4 = {};
    in6_addr v6 = {};
    return inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

void RecordDnsMapping(const std::string& host, const addrinfo* res) {
    if (host.empty() || IsIpLiteral(host)) return;
    std::lock_guard<std::mutex> lock(g_dnsMutex);
    if (g_ipToHost.size() > kMaxDnsCacheEntries) {
        g_ipToHost.clear();
    }
    for (const addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_addr && (p->ai_family == AF_INET || p->ai_family == AF_INET6)) {
            std::string ip = ExtractIpKey(p->ai_addr);
            if (!ip.empty()) {
                g_ipToHost[ip] = host;
            }
        }
    }
}

void RecordDnsMappingW(const std::wstring& hostW, const addrinfoW* res) {
    std::string host = WideToUtf8(hostW.c_str());
    if (host.empty() || IsIpLiteral(host)) return;
    std::lock_guard<std::mutex> lock(g_dnsMutex);
    if (g_ipToHost.size() > kMaxDnsCacheEntries) {
        g_ipToHost.clear();
    }
    for (const addrinfoW* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_addr && (p->ai_family == AF_INET || p->ai_family == AF_INET6)) {
            std::string ip = ExtractIpKey(p->ai_addr);
            if (!ip.empty()) {
                g_ipToHost[ip] = host;
            }
        }
    }
}

void RecordDnsMappingExW(const std::wstring& hostW, const ADDRINFOEXW* res) {
    std::string host = WideToUtf8(hostW.c_str());
    if (host.empty() || IsIpLiteral(host)) return;
    std::lock_guard<std::mutex> lock(g_dnsMutex);
    if (g_ipToHost.size() > kMaxDnsCacheEntries) {
        g_ipToHost.clear();
    }
    for (const ADDRINFOEXW* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_addr && (p->ai_family == AF_INET || p->ai_family == AF_INET6)) {
            std::string ip = ExtractIpKey(p->ai_addr);
            if (!ip.empty()) {
                g_ipToHost[ip] = host;
            }
        }
    }
}

std::string LookupCachedHost(const sockaddr* addr) {
    if (!GetConfig().remote_dns) return {};
    std::string ip = ExtractIpKey(addr);
    if (ip.empty()) return {};
    std::lock_guard<std::mutex> lock(g_dnsMutex);
    auto it = g_ipToHost.find(ip);
    return (it != g_ipToHost.end()) ? it->second : std::string{};
}

int GetSocketType(SOCKET s) {
    int sockType = 0;
    int len = sizeof(sockType);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&sockType), &len) == 0) {
        return sockType;
    }
    return 0;
}

// Original function pointers
using ConnectFnPtr = int (WSAAPI*)(SOCKET, const sockaddr*, int);
using WSAConnectFnPtr = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using WSAIoctlFnPtr = int (WSAAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using SendToFnPtr = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
using WSASendToFnPtr = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using GetAddrInfoAFnPtr = int (WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
using GetAddrInfoWFnPtr = int (WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
using GetAddrInfoExWFnPtr = int (WSAAPI*)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW*, PADDRINFOEXW*, timeval*, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);

ConnectFnPtr g_origConnect = nullptr;
WSAConnectFnPtr g_origWSAConnect = nullptr;
WSAIoctlFnPtr g_origWSAIoctl = nullptr;
SendToFnPtr g_origSendTo = nullptr;
WSASendToFnPtr g_origWSASendTo = nullptr;
GetAddrInfoAFnPtr g_origGetAddrInfoA = nullptr;
GetAddrInfoWFnPtr g_origGetAddrInfoW = nullptr;
GetAddrInfoExWFnPtr g_origGetAddrInfoExW = nullptr;
LPFN_CONNECTEX g_origConnectEx = nullptr;

int WSAAPI DetourConnect(SOCKET s, const sockaddr* name, int namelen) {
    HookGuard guard;
    const Config& cfg = GetConfig();
    if (!guard.entered || !cfg.enabled || ShouldBypassAddress(name, namelen, cfg)) {
        return g_origConnect(s, name, namelen);
    }

    int sockType = GetSocketType(s);
    if (sockType == SOCK_DGRAM) {
        if (cfg.block_quic && ExtractPort(name) == 443) {
            LogDebug("Blocked QUIC UDP connect -> %s", FormatSockAddr(name).c_str());
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
        return g_origConnect(s, name, namelen);
    }

    if (sockType != SOCK_STREAM) {
        return g_origConnect(s, name, namelen);
    }

    std::string domain = LookupCachedHost(name);
    LogDebug("connect -> %s%s%s via %s:%u",
             FormatSockAddr(name).c_str(),
             domain.empty() ? "" : " (",
             domain.empty() ? "" : (domain + ")").c_str(),
             cfg.host.c_str(), cfg.port);

    return ConnectViaProxy(s, name, namelen, domain, cfg, g_origConnect);
}

int WSAAPI DetourWSAConnect(SOCKET s, const sockaddr* name, int namelen,
                            LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                            LPQOS lpSQOS, LPQOS lpGQOS) {
    HookGuard guard;
    const Config& cfg = GetConfig();
    if (!guard.entered || !cfg.enabled || ShouldBypassAddress(name, namelen, cfg)) {
        return g_origWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    int sockType = GetSocketType(s);
    if (sockType == SOCK_DGRAM) {
        if (cfg.block_quic && ExtractPort(name) == 443) {
            LogDebug("Blocked QUIC UDP WSAConnect -> %s", FormatSockAddr(name).c_str());
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
        return g_origWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    if (sockType != SOCK_STREAM) {
        return g_origWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    std::string domain = LookupCachedHost(name);
    LogDebug("WSAConnect -> %s%s%s via %s:%u",
             FormatSockAddr(name).c_str(),
             domain.empty() ? "" : " (",
             domain.empty() ? "" : (domain + ")").c_str(),
             cfg.host.c_str(), cfg.port);

    return ConnectViaProxy(s, name, namelen, domain, cfg, g_origConnect);
}

BOOL PASCAL DetourConnectEx(SOCKET s, const sockaddr* name, int namelen,
                            PVOID lpSendBuffer, DWORD dwSendDataLength,
                            LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped) {
    HookGuard guard;
    const Config& cfg = GetConfig();
    if (!guard.entered || !cfg.enabled || ShouldBypassAddress(name, namelen, cfg)) {
        return g_origConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }

    std::string domain = LookupCachedHost(name);
    LogDebug("ConnectEx -> %s%s%s via %s:%u",
             FormatSockAddr(name).c_str(),
             domain.empty() ? "" : " (",
             domain.empty() ? "" : (domain + ")").c_str(),
             cfg.host.c_str(), cfg.port);

    if (ConnectViaProxy(s, name, namelen, domain, cfg, g_origConnect) != 0) {
        return FALSE;
    }

    // Complete the caller's OVERLAPPED / IOCP cleanly via a real overlapped WSASend
    // (0-byte WSASend when dwSendDataLength == 0 so libuv/IOCP receives the kernel completion packet)
    WSABUF wsaBuf = {};
    wsaBuf.buf = (dwSendDataLength > 0) ? reinterpret_cast<CHAR*>(lpSendBuffer) : nullptr;
    wsaBuf.len = dwSendDataLength;

    DWORD bytesSent = 0;
    int rc = WSASend(s, &wsaBuf, 1, &bytesSent, 0, lpOverlapped, nullptr);
    if (lpdwBytesSent) {
        *lpdwBytesSent = bytesSent;
    }
    if (rc == 0) {
        return TRUE;
    }
    // WSA_IO_PENDING is expected for async IOCP completion; caller checks GetLastError()
    return FALSE;
}

int WSAAPI DetourWSAIoctl(SOCKET s, DWORD dwIoControlCode,
                          LPVOID lpvInBuffer, DWORD cbInBuffer,
                          LPVOID lpvOutBuffer, DWORD cbOutBuffer,
                          LPDWORD lpcbBytesReturned,
                          LPWSAOVERLAPPED lpOverlapped,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int rc = g_origWSAIoctl(s, dwIoControlCode, lpvInBuffer, cbInBuffer,
                            lpvOutBuffer, cbOutBuffer, lpcbBytesReturned,
                            lpOverlapped, lpCompletionRoutine);

    if (rc == 0 &&
        dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        lpvInBuffer && cbInBuffer == sizeof(GUID) &&
        lpvOutBuffer && cbOutBuffer >= sizeof(LPFN_CONNECTEX)) {
        static const GUID kConnectExGuid = WSAID_CONNECTEX;
        if (IsEqualGUID(*reinterpret_cast<const GUID*>(lpvInBuffer), kConnectExGuid)) {
            auto* outFn = reinterpret_cast<LPFN_CONNECTEX*>(lpvOutBuffer);
            if (*outFn && *outFn != DetourConnectEx) {
                g_origConnectEx = *outFn;
                *outFn = DetourConnectEx;
                LogDebug("Intercepted WSAID_CONNECTEX via WSAIoctl");
            }
        }
    }

    return rc;
}

int WSAAPI DetourSendTo(SOCKET s, const char* buf, int len, int flags,
                        const sockaddr* to, int tolen) {
    const Config& cfg = GetConfig();
    if (cfg.enabled && cfg.block_quic && to && !ShouldBypassAddress(to, tolen, cfg)) {
        if (ExtractPort(to) == 443) {
            LogDebug("Blocked QUIC UDP sendto -> %s", FormatSockAddr(to).c_str());
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
    }
    return g_origSendTo(s, buf, len, flags, to, tolen);
}

int WSAAPI DetourWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                           LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                           const sockaddr* lpTo, int iTolen,
                           LPWSAOVERLAPPED lpOverlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    const Config& cfg = GetConfig();
    if (cfg.enabled && cfg.block_quic && lpTo && !ShouldBypassAddress(lpTo, iTolen, cfg)) {
        if (ExtractPort(lpTo) == 443) {
            LogDebug("Blocked QUIC UDP WSASendTo -> %s", FormatSockAddr(lpTo).c_str());
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
    }
    return g_origWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
                           lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

int WSAAPI DetourGetAddrInfoA(PCSTR pNodeName, PCSTR pServiceName,
                              const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    int rc = g_origGetAddrInfoA(pNodeName, pServiceName, pHints, ppResult);
    if (rc == 0 && pNodeName && ppResult && *ppResult) {
        RecordDnsMapping(pNodeName, *ppResult);
    }
    return rc;
}

int WSAAPI DetourGetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
                              const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    int rc = g_origGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
    if (rc == 0 && pNodeName && ppResult && *ppResult) {
        RecordDnsMappingW(pNodeName, *ppResult);
    }
    return rc;
}

int WSAAPI DetourGetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace,
                                LPGUID lpNspId, const ADDRINFOEXW* hints, PADDRINFOEXW* ppResult,
                                timeval* timeout, LPOVERLAPPED lpOverlapped,
                                LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
                                LPHANDLE lpHandle) {
    int rc = g_origGetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult,
                                  timeout, lpOverlapped, lpCompletionRoutine, lpHandle);
    if (rc == 0 && pName && ppResult && *ppResult) {
        RecordDnsMappingExW(pName, *ppResult);
    }
    return rc;
}

template <typename FnPtr>
bool CreateHookByName(HMODULE mod, const char* name, void* detour, FnPtr* orig) {
    FARPROC target = GetProcAddress(mod, name);
    if (!target) {
        LogError("GetProcAddress(%s) failed", name);
        return false;
    }
    MH_STATUS st = MH_CreateHook(reinterpret_cast<LPVOID>(target), detour, reinterpret_cast<LPVOID*>(orig));
    if (st != MH_OK) {
        LogError("MH_CreateHook(%s) failed: %d", name, static_cast<int>(st));
        return false;
    }
    return true;
}

} // namespace

bool InstallHooks() {
    HMODULE ws2 = GetModuleHandleW(L"ws2_32.dll");
    if (!ws2) {
        ws2 = LoadLibraryW(L"ws2_32.dll");
    }
    if (!ws2) {
        LogError("Failed to locate ws2_32.dll");
        return false;
    }

    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        LogError("MH_Initialize failed: %d", static_cast<int>(st));
        return false;
    }

    bool ok = true;
    ok &= CreateHookByName(ws2, "connect", reinterpret_cast<void*>(&DetourConnect), &g_origConnect);
    ok &= CreateHookByName(ws2, "WSAConnect", reinterpret_cast<void*>(&DetourWSAConnect), &g_origWSAConnect);
    ok &= CreateHookByName(ws2, "WSAIoctl", reinterpret_cast<void*>(&DetourWSAIoctl), &g_origWSAIoctl);
    ok &= CreateHookByName(ws2, "sendto", reinterpret_cast<void*>(&DetourSendTo), &g_origSendTo);
    ok &= CreateHookByName(ws2, "WSASendTo", reinterpret_cast<void*>(&DetourWSASendTo), &g_origWSASendTo);

    // Passive DNS hooks (best-effort; non-fatal if absent)
    CreateHookByName(ws2, "getaddrinfo", reinterpret_cast<void*>(&DetourGetAddrInfoA), &g_origGetAddrInfoA);
    CreateHookByName(ws2, "GetAddrInfoW", reinterpret_cast<void*>(&DetourGetAddrInfoW), &g_origGetAddrInfoW);
    CreateHookByName(ws2, "GetAddrInfoExW", reinterpret_cast<void*>(&DetourGetAddrInfoExW), &g_origGetAddrInfoExW);

    st = MH_EnableHook(MH_ALL_HOOKS);
    if (st != MH_OK) {
        LogError("MH_EnableHook failed: %d", static_cast<int>(st));
        return false;
    }

    LogInfo("Winsock hooks installed (core_ok=%d)", ok ? 1 : 0);
    return ok;
}

void RemoveHooks() {
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

} // namespace gproxy
