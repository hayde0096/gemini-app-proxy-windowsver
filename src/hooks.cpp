#include "hooks.h"

#include "config.h"
#include "logger.h"
#include "proxy_client.h"

#include <MinHook.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

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

// Fake-IP allocator (198.18.0.1 - 198.19.255.254, RFC 2544 benchmarking range)
// Eliminates local DNS poisoning & collisions by mapping each domain to a unique synthetic IPv4,
// then passing the real domain name to the SOCKS5/HTTP proxy for remote DNS resolution.
std::mutex g_dnsMutex;
std::unordered_map<std::string, uint32_t> g_hostToFakeIp; // lowercased host -> host-order IPv4
std::unordered_map<uint32_t, std::string> g_fakeIpToHost; // host-order IPv4 -> original host
std::unordered_map<std::string, std::string> g_ipToHost;  // fallback passive cache
std::unordered_set<void*> g_syntheticAddrInfos;
uint32_t g_nextFakeIp = 0xC6120001u; // 198.18.0.1
constexpr uint32_t kFakeIpStart = 0xC6120001u; // 198.18.0.1
constexpr uint32_t kFakeIpEnd   = 0xC613FFFEu; // 198.19.255.254

// Track WSAEventSelect FD_CONNECT registrations (Chromium TCPSocketWin requires connect()
// on a WSAEventSelect socket to return SOCKET_ERROR + WSAEWOULDBLOCK, otherwise it hits NOTREACHED())
struct EventSelectInfo {
    WSAEVENT hEvent = nullptr;
    long lNetworkEvents = 0;
};
std::mutex g_eventMutex;
std::unordered_map<SOCKET, EventSelectInfo> g_socketEvents;
std::unordered_map<SOCKET, bool> g_pendingConnectSuccess;

std::string WideToUtf8(const wchar_t* ws) {
    if (!ws || !*ws) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return {};
    std::string out(static_cast<size_t>(needed - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), needed, nullptr, nullptr);
    return out;
}

std::string ToLowerStr(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool IsIpLiteral(const std::string& host) {
    in_addr v4 = {};
    in6_addr v6 = {};
    return inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

bool ShouldUseFakeIpForHost(const std::string& host, const Config& cfg) {
    if (!cfg.enabled || !cfg.remote_dns) return false;
    if (host.empty() || host.size() > 253) return false;
    if (IsIpLiteral(host)) return false;

    std::string lower = ToLowerStr(host);
    if (lower == "localhost" || lower == "localhost.localdomain") return false;
    if (lower == ToLowerStr(cfg.host)) return false;
    if (lower.size() > 6 && lower.compare(lower.size() - 6, 6, ".local") == 0) return false;
    if (lower.size() > 10 && lower.compare(lower.size() - 10, 10, ".localhost") == 0) return false;
    // Must contain at least one dot (avoid single-label NetBIOS/intranet names)
    if (lower.find('.') == std::string::npos) return false;
    return true;
}

uint32_t AllocateFakeIpLocked(const std::string& host) {
    std::string key = ToLowerStr(host);
    auto it = g_hostToFakeIp.find(key);
    if (it != g_hostToFakeIp.end()) {
        return it->second;
    }
    uint32_t ip = g_nextFakeIp++;
    if (g_nextFakeIp > kFakeIpEnd) {
        g_nextFakeIp = kFakeIpStart;
    }
    g_hostToFakeIp[key] = ip;
    g_fakeIpToHost[ip] = host;
    return ip;
}

uint16_t ParseServicePortA(PCSTR svc) {
    if (!svc || !*svc) return 0;
    char* end = nullptr;
    unsigned long p = std::strtoul(svc, &end, 10);
    if (end && *end == '\0' && p <= 65535) {
        return static_cast<uint16_t>(p);
    }
    std::string l = ToLowerStr(svc);
    if (l == "https") return 443;
    if (l == "http") return 80;
    return 0;
}

uint16_t ParseServicePortW(PCWSTR svc) {
    if (!svc || !*svc) return 0;
    return ParseServicePortA(WideToUtf8(svc).c_str());
}

std::string LookupTargetDomain(const sockaddr* addr) {
    if (!addr || !GetConfig().remote_dns) return {};

    if (addr->sa_family == AF_INET) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(addr);
        uint32_t hostOrder = ntohl(sin->sin_addr.s_addr);
        if (hostOrder >= kFakeIpStart && hostOrder <= kFakeIpEnd) {
            std::lock_guard<std::mutex> lock(g_dnsMutex);
            auto it = g_fakeIpToHost.find(hostOrder);
            if (it != g_fakeIpToHost.end()) {
                return it->second;
            }
        }
    } else if (addr->sa_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            uint32_t netOrder = 0;
            std::memcpy(&netOrder, &sin6->sin6_addr.s6_bytes[12], 4);
            uint32_t hostOrder = ntohl(netOrder);
            if (hostOrder >= kFakeIpStart && hostOrder <= kFakeIpEnd) {
                std::lock_guard<std::mutex> lock(g_dnsMutex);
                auto it = g_fakeIpToHost.find(hostOrder);
                if (it != g_fakeIpToHost.end()) {
                    return it->second;
                }
            }
        }
    }

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
using FreeAddrInfoAFnPtr = void (WSAAPI*)(PADDRINFOA);
using FreeAddrInfoWFnPtr = void (WSAAPI*)(PADDRINFOW);
using FreeAddrInfoExWFnPtr = void (WSAAPI*)(PADDRINFOEXW);
using WSAEventSelectFnPtr = int (WSAAPI*)(SOCKET, WSAEVENT, long);
using WSAEnumNetworkEventsFnPtr = int (WSAAPI*)(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);
using CloseSocketFnPtr = int (WSAAPI*)(SOCKET);

ConnectFnPtr g_origConnect = nullptr;
WSAConnectFnPtr g_origWSAConnect = nullptr;
WSAIoctlFnPtr g_origWSAIoctl = nullptr;
SendToFnPtr g_origSendTo = nullptr;
WSASendToFnPtr g_origWSASendTo = nullptr;
GetAddrInfoAFnPtr g_origGetAddrInfoA = nullptr;
GetAddrInfoWFnPtr g_origGetAddrInfoW = nullptr;
GetAddrInfoExWFnPtr g_origGetAddrInfoExW = nullptr;
FreeAddrInfoAFnPtr g_origFreeAddrInfoA = nullptr;
FreeAddrInfoWFnPtr g_origFreeAddrInfoW = nullptr;
FreeAddrInfoExWFnPtr g_origFreeAddrInfoExW = nullptr;
WSAEventSelectFnPtr g_origWSAEventSelect = nullptr;
WSAEnumNetworkEventsFnPtr g_origWSAEnumNetworkEvents = nullptr;
CloseSocketFnPtr g_origCloseSocket = nullptr;
LPFN_CONNECTEX g_origConnectEx = nullptr;

// If the socket has an active WSAEventSelect(..., FD_CONNECT) (as Chromium's TCPSocketWin does),
// signal the event and return SOCKET_ERROR + WSAEWOULDBLOCK so Chromium doesn't hit NOTREACHED().
int FinalizeProxyConnectResult(SOCKET s, int rc) {
    if (rc != 0) {
        return rc;
    }

    WSAEVENT connectEvent = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_eventMutex);
        auto it = g_socketEvents.find(s);
        if (it != g_socketEvents.end() && it->second.hEvent != nullptr &&
            (it->second.lNetworkEvents & FD_CONNECT) != 0) {
            connectEvent = it->second.hEvent;
            g_pendingConnectSuccess[s] = true;
        }
    }

    if (connectEvent != nullptr) {
        WSASetEvent(connectEvent);
        WSASetLastError(WSAEWOULDBLOCK);
        return SOCKET_ERROR;
    }

    return 0;
}

bool ShouldBlockUdpTarget(const sockaddr* to, int tolen, const Config& cfg) {
    if (!cfg.enabled || !to) return false;
    uint16_t port = ExtractPort(to);

    // Block UDP port 53 (built-in Chromium async DNS) BEFORE LAN bypass so Chromium falls back
    // to OS GetAddrInfoW -> our Fake-IP resolver, preventing local ISP DNS poisoning.
    if (cfg.remote_dns && port == 53) {
        LogDebug("Blocked UDP DNS -> %s (forcing OS GetAddrInfoW fallback)", FormatSockAddr(to).c_str());
        return true;
    }

    // Block UDP port 443 (QUIC / HTTP3) on non-LAN targets so Chromium falls back to TCP over proxy
    if (cfg.block_quic && port == 443 && !ShouldBypassAddress(to, tolen, cfg)) {
        LogDebug("Blocked QUIC UDP -> %s", FormatSockAddr(to).c_str());
        return true;
    }

    return false;
}

int WSAAPI DetourConnect(SOCKET s, const sockaddr* name, int namelen) {
    HookGuard guard;
    const Config& cfg = GetConfig();
    if (!guard.entered || !cfg.enabled) {
        return g_origConnect(s, name, namelen);
    }

    int sockType = GetSocketType(s);
    if (sockType == SOCK_DGRAM) {
        if (ShouldBlockUdpTarget(name, namelen, cfg)) {
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
        return g_origConnect(s, name, namelen);
    }

    if (sockType != SOCK_STREAM || ShouldBypassAddress(name, namelen, cfg)) {
        return g_origConnect(s, name, namelen);
    }

    std::string domain = LookupTargetDomain(name);
    LogDebug("connect -> %s%s%s via %s:%u",
             FormatSockAddr(name).c_str(),
             domain.empty() ? "" : " (",
             domain.empty() ? "" : (domain + ")").c_str(),
             cfg.host.c_str(), cfg.port);

    int rc = ConnectViaProxy(s, name, namelen, domain, cfg, g_origConnect);
    return FinalizeProxyConnectResult(s, rc);
}

int WSAAPI DetourWSAConnect(SOCKET s, const sockaddr* name, int namelen,
                            LPWSABUF lpCallerData, LPWSABUF lpCalleeData,
                            LPQOS lpSQOS, LPQOS lpGQOS) {
    HookGuard guard;
    const Config& cfg = GetConfig();
    if (!guard.entered || !cfg.enabled) {
        return g_origWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    int sockType = GetSocketType(s);
    if (sockType == SOCK_DGRAM) {
        if (ShouldBlockUdpTarget(name, namelen, cfg)) {
            WSASetLastError(WSAECONNREFUSED);
            return SOCKET_ERROR;
        }
        return g_origWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    if (sockType != SOCK_STREAM || ShouldBypassAddress(name, namelen, cfg)) {
        return g_origWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
    }

    std::string domain = LookupTargetDomain(name);
    LogDebug("WSAConnect -> %s%s%s via %s:%u",
             FormatSockAddr(name).c_str(),
             domain.empty() ? "" : " (",
             domain.empty() ? "" : (domain + ")").c_str(),
             cfg.host.c_str(), cfg.port);

    int rc = ConnectViaProxy(s, name, namelen, domain, cfg, g_origConnect);
    return FinalizeProxyConnectResult(s, rc);
}

BOOL PASCAL DetourConnectEx(SOCKET s, const sockaddr* name, int namelen,
                            PVOID lpSendBuffer, DWORD dwSendDataLength,
                            LPDWORD lpdwBytesSent, LPOVERLAPPED lpOverlapped) {
    HookGuard guard;
    const Config& cfg = GetConfig();
    if (!guard.entered || !cfg.enabled || ShouldBypassAddress(name, namelen, cfg)) {
        return g_origConnectEx(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
    }

    std::string domain = LookupTargetDomain(name);
    LogDebug("ConnectEx -> %s%s%s via %s:%u",
             FormatSockAddr(name).c_str(),
             domain.empty() ? "" : " (",
             domain.empty() ? "" : (domain + ")").c_str(),
             cfg.host.c_str(), cfg.port);

    if (ConnectViaProxy(s, name, namelen, domain, cfg, g_origConnect) != 0) {
        return FALSE;
    }

    // Complete the caller's OVERLAPPED / IOCP cleanly via a real overlapped WSASend
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
    if (ShouldBlockUdpTarget(to, tolen, cfg)) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    return g_origSendTo(s, buf, len, flags, to, tolen);
}

int WSAAPI DetourWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount,
                           LPDWORD lpNumberOfBytesSent, DWORD dwFlags,
                           const sockaddr* lpTo, int iTolen,
                           LPWSAOVERLAPPED lpOverlapped,
                           LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    const Config& cfg = GetConfig();
    if (ShouldBlockUdpTarget(lpTo, iTolen, cfg)) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    return g_origWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags,
                           lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
}

int WSAAPI DetourGetAddrInfoA(PCSTR pNodeName, PCSTR pServiceName,
                              const ADDRINFOA* pHints, PADDRINFOA* ppResult) {
    const Config& cfg = GetConfig();
    if (pNodeName && ppResult &&
        (!pHints || ((pHints->ai_flags & AI_NUMERICHOST) == 0 &&
                     (pHints->ai_family == AF_UNSPEC || pHints->ai_family == AF_INET))) &&
        ShouldUseFakeIpForHost(pNodeName, cfg)) {
        uint32_t fakeIp = 0;
        auto* ai = new ADDRINFOA{};
        auto* sin = new sockaddr_in{};
        {
            std::lock_guard<std::mutex> lock(g_dnsMutex);
            fakeIp = AllocateFakeIpLocked(pNodeName);
            g_syntheticAddrInfos.insert(ai);
        }
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = htonl(fakeIp);
        sin->sin_port = htons(ParseServicePortA(pServiceName));

        ai->ai_family = AF_INET;
        ai->ai_socktype = (pHints && pHints->ai_socktype) ? pHints->ai_socktype : SOCK_STREAM;
        ai->ai_protocol = (pHints && pHints->ai_protocol) ? pHints->ai_protocol : IPPROTO_TCP;
        ai->ai_addrlen = sizeof(sockaddr_in);
        ai->ai_addr = reinterpret_cast<sockaddr*>(sin);
        if (pHints && (pHints->ai_flags & AI_CANONNAME)) {
            size_t len = std::strlen(pNodeName);
            ai->ai_canonname = new char[len + 1];
            std::memcpy(ai->ai_canonname, pNodeName, len + 1);
        }
        *ppResult = ai;
        LogDebug("FakeIP getaddrinfo(%s) -> %s", pNodeName, ExtractIpKey(ai->ai_addr).c_str());
        return 0;
    }
    return g_origGetAddrInfoA(pNodeName, pServiceName, pHints, ppResult);
}

int WSAAPI DetourGetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName,
                              const ADDRINFOW* pHints, PADDRINFOW* ppResult) {
    const Config& cfg = GetConfig();
    if (pNodeName && ppResult &&
        (!pHints || ((pHints->ai_flags & AI_NUMERICHOST) == 0 &&
                     (pHints->ai_family == AF_UNSPEC || pHints->ai_family == AF_INET)))) {
        std::string host = WideToUtf8(pNodeName);
        if (ShouldUseFakeIpForHost(host, cfg)) {
            uint32_t fakeIp = 0;
            auto* ai = new ADDRINFOW{};
            auto* sin = new sockaddr_in{};
            {
                std::lock_guard<std::mutex> lock(g_dnsMutex);
                fakeIp = AllocateFakeIpLocked(host);
                g_syntheticAddrInfos.insert(ai);
            }
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = htonl(fakeIp);
            sin->sin_port = htons(ParseServicePortW(pServiceName));

            ai->ai_family = AF_INET;
            ai->ai_socktype = (pHints && pHints->ai_socktype) ? pHints->ai_socktype : SOCK_STREAM;
            ai->ai_protocol = (pHints && pHints->ai_protocol) ? pHints->ai_protocol : IPPROTO_TCP;
            ai->ai_addrlen = sizeof(sockaddr_in);
            ai->ai_addr = reinterpret_cast<sockaddr*>(sin);
            if (pHints && (pHints->ai_flags & AI_CANONNAME)) {
                size_t len = wcslen(pNodeName);
                ai->ai_canonname = new wchar_t[len + 1];
                std::memcpy(ai->ai_canonname, pNodeName, (len + 1) * sizeof(wchar_t));
            }
            *ppResult = ai;
            LogDebug("FakeIP GetAddrInfoW(%s) -> %s", host.c_str(), ExtractIpKey(ai->ai_addr).c_str());
            return 0;
        }
    }
    return g_origGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

int WSAAPI DetourGetAddrInfoExW(PCWSTR pName, PCWSTR pServiceName, DWORD dwNameSpace,
                                LPGUID lpNspId, const ADDRINFOEXW* hints, PADDRINFOEXW* ppResult,
                                timeval* timeout, LPOVERLAPPED lpOverlapped,
                                LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
                                LPHANDLE lpHandle) {
    const Config& cfg = GetConfig();
    if (pName && ppResult && lpOverlapped == nullptr && lpCompletionRoutine == nullptr &&
        (!hints || ((hints->ai_flags & AI_NUMERICHOST) == 0 &&
                    (hints->ai_family == AF_UNSPEC || hints->ai_family == AF_INET)))) {
        std::string host = WideToUtf8(pName);
        if (ShouldUseFakeIpForHost(host, cfg)) {
            uint32_t fakeIp = 0;
            auto* ai = new ADDRINFOEXW{};
            auto* sin = new sockaddr_in{};
            {
                std::lock_guard<std::mutex> lock(g_dnsMutex);
                fakeIp = AllocateFakeIpLocked(host);
                g_syntheticAddrInfos.insert(ai);
            }
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = htonl(fakeIp);
            sin->sin_port = htons(ParseServicePortW(pServiceName));

            ai->ai_family = AF_INET;
            ai->ai_socktype = (hints && hints->ai_socktype) ? hints->ai_socktype : SOCK_STREAM;
            ai->ai_protocol = (hints && hints->ai_protocol) ? hints->ai_protocol : IPPROTO_TCP;
            ai->ai_addrlen = sizeof(sockaddr_in);
            ai->ai_addr = reinterpret_cast<sockaddr*>(sin);
            if (hints && (hints->ai_flags & AI_CANONNAME)) {
                size_t len = wcslen(pName);
                ai->ai_canonname = new wchar_t[len + 1];
                std::memcpy(ai->ai_canonname, pName, (len + 1) * sizeof(wchar_t));
            }
            *ppResult = ai;
            LogDebug("FakeIP GetAddrInfoExW(%s) -> %s", host.c_str(), ExtractIpKey(ai->ai_addr).c_str());
            return 0;
        }
    }
    return g_origGetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, hints, ppResult,
                                timeout, lpOverlapped, lpCompletionRoutine, lpHandle);
}

void WSAAPI DetourFreeAddrInfoA(PADDRINFOA pAddrInfo) {
    if (pAddrInfo) {
        bool isSynthetic = false;
        {
            std::lock_guard<std::mutex> lock(g_dnsMutex);
            isSynthetic = (g_syntheticAddrInfos.erase(pAddrInfo) > 0);
        }
        if (isSynthetic) {
            delete reinterpret_cast<sockaddr_in*>(pAddrInfo->ai_addr);
            delete[] pAddrInfo->ai_canonname;
            delete pAddrInfo;
            return;
        }
    }
    g_origFreeAddrInfoA(pAddrInfo);
}

void WSAAPI DetourFreeAddrInfoW(PADDRINFOW pAddrInfo) {
    if (pAddrInfo) {
        bool isSynthetic = false;
        {
            std::lock_guard<std::mutex> lock(g_dnsMutex);
            isSynthetic = (g_syntheticAddrInfos.erase(pAddrInfo) > 0);
        }
        if (isSynthetic) {
            delete reinterpret_cast<sockaddr_in*>(pAddrInfo->ai_addr);
            delete[] pAddrInfo->ai_canonname;
            delete pAddrInfo;
            return;
        }
    }
    g_origFreeAddrInfoW(pAddrInfo);
}

void WSAAPI DetourFreeAddrInfoExW(PADDRINFOEXW pAddrInfo) {
    if (pAddrInfo) {
        bool isSynthetic = false;
        {
            std::lock_guard<std::mutex> lock(g_dnsMutex);
            isSynthetic = (g_syntheticAddrInfos.erase(pAddrInfo) > 0);
        }
        if (isSynthetic) {
            delete reinterpret_cast<sockaddr_in*>(pAddrInfo->ai_addr);
            delete[] pAddrInfo->ai_canonname;
            delete pAddrInfo;
            return;
        }
    }
    g_origFreeAddrInfoExW(pAddrInfo);
}

int WSAAPI DetourWSAEventSelect(SOCKET s, WSAEVENT hEventObject, long lNetworkEvents) {
    int rc = g_origWSAEventSelect(s, hEventObject, lNetworkEvents);
    if (rc == 0) {
        std::lock_guard<std::mutex> lock(g_eventMutex);
        if (hEventObject == nullptr || lNetworkEvents == 0) {
            g_socketEvents.erase(s);
            g_pendingConnectSuccess.erase(s);
        } else {
            g_socketEvents[s] = EventSelectInfo{hEventObject, lNetworkEvents};
        }
    }
    return rc;
}

int WSAAPI DetourWSAEnumNetworkEvents(SOCKET s, WSAEVENT hEventObject, LPWSANETWORKEVENTS lpNetworkEvents) {
    int rc = g_origWSAEnumNetworkEvents(s, hEventObject, lpNetworkEvents);
    if (rc == 0 && lpNetworkEvents) {
        bool injectConnect = false;
        {
            std::lock_guard<std::mutex> lock(g_eventMutex);
            auto it = g_pendingConnectSuccess.find(s);
            if (it != g_pendingConnectSuccess.end()) {
                injectConnect = true;
                g_pendingConnectSuccess.erase(it);
            }
        }
        if (injectConnect) {
            lpNetworkEvents->lNetworkEvents |= FD_CONNECT;
            lpNetworkEvents->iErrorCode[FD_CONNECT_BIT] = 0;
            if (hEventObject) {
                WSAResetEvent(hEventObject);
            }
        }
    }
    return rc;
}

int WSAAPI DetourCloseSocket(SOCKET s) {
    {
        std::lock_guard<std::mutex> lock(g_eventMutex);
        g_socketEvents.erase(s);
        g_pendingConnectSuccess.erase(s);
    }
    return g_origCloseSocket(s);
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
    ok &= CreateHookByName(ws2, "WSAEventSelect", reinterpret_cast<void*>(&DetourWSAEventSelect), &g_origWSAEventSelect);
    ok &= CreateHookByName(ws2, "WSAEnumNetworkEvents", reinterpret_cast<void*>(&DetourWSAEnumNetworkEvents), &g_origWSAEnumNetworkEvents);
    ok &= CreateHookByName(ws2, "closesocket", reinterpret_cast<void*>(&DetourCloseSocket), &g_origCloseSocket);

    // Fake-IP DNS hooks (skip duplicate hook when FreeAddrInfoW aliases freeaddrinfo in ws2_32.dll)
    CreateHookByName(ws2, "getaddrinfo", reinterpret_cast<void*>(&DetourGetAddrInfoA), &g_origGetAddrInfoA);
    CreateHookByName(ws2, "GetAddrInfoW", reinterpret_cast<void*>(&DetourGetAddrInfoW), &g_origGetAddrInfoW);
    CreateHookByName(ws2, "GetAddrInfoExW", reinterpret_cast<void*>(&DetourGetAddrInfoExW), &g_origGetAddrInfoExW);

    FARPROC pFreeA = GetProcAddress(ws2, "freeaddrinfo");
    FARPROC pFreeW = GetProcAddress(ws2, "FreeAddrInfoW");
    FARPROC pFreeExW = GetProcAddress(ws2, "FreeAddrInfoExW");
    if (pFreeA) {
        CreateHookByName(ws2, "freeaddrinfo", reinterpret_cast<void*>(&DetourFreeAddrInfoA), &g_origFreeAddrInfoA);
    }
    if (pFreeW && pFreeW != pFreeA) {
        CreateHookByName(ws2, "FreeAddrInfoW", reinterpret_cast<void*>(&DetourFreeAddrInfoW), &g_origFreeAddrInfoW);
    }
    if (pFreeExW && pFreeExW != pFreeA && pFreeExW != pFreeW) {
        CreateHookByName(ws2, "FreeAddrInfoExW", reinterpret_cast<void*>(&DetourFreeAddrInfoExW), &g_origFreeAddrInfoExW);
    }

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
