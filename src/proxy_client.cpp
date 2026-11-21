#include "proxy_client.h"
#include "logger.h"

#include <cstring>
#include <vector>

namespace gproxy {

namespace {

bool IsPrivateOrLocalIPv4(const in_addr& addr) {
    uint32_t ip = ntohl(addr.s_addr);
    uint8_t a = static_cast<uint8_t>((ip >> 24) & 0xFF);
    uint8_t b = static_cast<uint8_t>((ip >> 16) & 0xFF);

    if (a == 0) return true;                         // 0.0.0.0/8
    if (a == 127) return true;                       // 127.0.0.0/8 loopback
    if (a == 10) return true;                        // 10.0.0.0/8 private
    if (a == 172 && (b >= 16 && b <= 31)) return true; // 172.16.0.0/12 private
    if (a == 192 && b == 168) return true;           // 192.168.0.0/16 private
    if (a == 169 && b == 254) return true;           // 169.254.0.0/16 link-local
    if (a >= 224) return true;                       // multicast / broadcast / reserved
    return false;
}

bool IsPrivateOrLocalIPv6(const in6_addr& addr) {
    if (IN6_IS_ADDR_UNSPECIFIED(&addr)) return true;
    if (IN6_IS_ADDR_LOOPBACK(&addr)) return true;
    if (IN6_IS_ADDR_LINKLOCAL(&addr)) return true;
    if (IN6_IS_ADDR_MULTICAST(&addr)) return true;
    // fc00::/7 Unique Local Address
    if ((addr.s6_bytes[0] & 0xFE) == 0xFC) return true;
    // IPv4-mapped IPv6 ::ffff:x.x.x.x
    if (IN6_IS_ADDR_V4MAPPED(&addr)) {
        in_addr v4 = {};
        std::memcpy(&v4, &addr.s6_bytes[12], 4);
        return IsPrivateOrLocalIPv4(v4);
    }
    return false;
}

bool IsLoopbackOnly(const sockaddr* addr) {
    if (addr->sa_family == AF_INET) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(addr);
        uint32_t ip = ntohl(sin->sin_addr.s_addr);
        return ((ip >> 24) & 0xFF) == 127 || ip == 0;
    }
    if (addr->sa_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr) || IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr);
    }
    return true;
}

bool WaitSocket(SOCKET s, bool forWrite, int timeoutMs) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(s, &fds);

    fd_set exceptFds;
    FD_ZERO(&exceptFds);
    FD_SET(s, &exceptFds);

    timeval tv = {};
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;

    int rc = select(0, forWrite ? nullptr : &fds, forWrite ? &fds : nullptr, &exceptFds, &tv);
    if (rc <= 0) {
        return false;
    }
    if (FD_ISSET(s, &exceptFds)) {
        return false;
    }
    return FD_ISSET(s, &fds) != 0;
}

bool SendAll(SOCKET s, const uint8_t* data, size_t len, int timeoutMs) {
    size_t sent = 0;
    ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);

    while (sent < len) {
        int rc = send(s, reinterpret_cast<const char*>(data + sent), static_cast<int>(len - sent), 0);
        if (rc > 0) {
            sent += static_cast<size_t>(rc);
            continue;
        }
        int err = WSAGetLastError();
        if (rc == SOCKET_ERROR && err == WSAEWOULDBLOCK) {
            ULONGLONG now = GetTickCount64();
            if (now >= deadline) return false;
            if (!WaitSocket(s, true, static_cast<int>(deadline - now))) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

bool RecvExact(SOCKET s, uint8_t* buf, size_t len, int timeoutMs) {
    size_t got = 0;
    ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);

    while (got < len) {
        int rc = recv(s, reinterpret_cast<char*>(buf + got), static_cast<int>(len - got), 0);
        if (rc > 0) {
            got += static_cast<size_t>(rc);
            continue;
        }
        if (rc == 0) {
            return false; // Peer closed
        }
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            ULONGLONG now = GetTickCount64();
            if (now >= deadline) return false;
            if (!WaitSocket(s, false, static_cast<int>(deadline - now))) {
                return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

std::string Base64Encode(const std::string& in) {
    static constexpr char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);

    int val = 0;
    int valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kTable[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(kTable[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }
    return out;
}

bool ConnectToProxyEndpoint(SOCKET s, int socketFamily, const Config& cfg, ConnectFn origConnect) {
    sockaddr_storage proxySs = {};
    int proxyLen = 0;

    in_addr proxyV4 = {};
    in6_addr proxyV6 = {};
    bool proxyIsV4 = (inet_pton(AF_INET, cfg.host.c_str(), &proxyV4) == 1);
    bool proxyIsV6 = (!proxyIsV4 && inet_pton(AF_INET6, cfg.host.c_str(), &proxyV6) == 1);

    if (!proxyIsV4 && !proxyIsV6) {
        LogError("Invalid proxy host IP in config: %s", cfg.host.c_str());
        return false;
    }

    if (socketFamily == AF_INET) {
        if (!proxyIsV4) {
            LogError("Cannot connect AF_INET socket to IPv6 proxy %s", cfg.host.c_str());
            return false;
        }
        auto* sin = reinterpret_cast<sockaddr_in*>(&proxySs);
        sin->sin_family = AF_INET;
        sin->sin_port = htons(cfg.port);
        sin->sin_addr = proxyV4;
        proxyLen = sizeof(sockaddr_in);
    } else if (socketFamily == AF_INET6) {
        auto* sin6 = reinterpret_cast<sockaddr_in6*>(&proxySs);
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(cfg.port);
        if (proxyIsV6) {
            sin6->sin6_addr = proxyV6;
        } else {
            // Enable dual-stack so an AF_INET6 socket can connect to an IPv4 local proxy via ::ffff:x.x.x.x
            DWORD v6only = 0;
            setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof(v6only));
            sin6->sin6_addr.s6_bytes[10] = 0xFF;
            sin6->sin6_addr.s6_bytes[11] = 0xFF;
            std::memcpy(&sin6->sin6_addr.s6_bytes[12], &proxyV4, 4);
        }
        proxyLen = sizeof(sockaddr_in6);
    } else {
        return false;
    }

    int rc = origConnect(s, reinterpret_cast<const sockaddr*>(&proxySs), proxyLen);
    if (rc == 0) {
        return true;
    }

    int err = WSAGetLastError();
    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        LogError("Connect to proxy %s:%u failed immediately (WSA=%d)", cfg.host.c_str(), cfg.port, err);
        return false;
    }

    if (!WaitSocket(s, true, cfg.timeout_ms)) {
        LogError("Connect to proxy %s:%u timed out", cfg.host.c_str(), cfg.port);
        return false;
    }

    int soErr = 0;
    int soLen = sizeof(soErr);
    if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soErr), &soLen) != 0 || soErr != 0) {
        LogError("Connect to proxy %s:%u failed after wait (SO_ERROR=%d)", cfg.host.c_str(), cfg.port, soErr);
        return false;
    }

    return true;
}

bool HandshakeSocks5(SOCKET s,
                     const sockaddr* targetAddr,
                     const std::string& targetDomain,
                     const Config& cfg) {
    bool useAuth = !cfg.username.empty();

    // 1. Greeting
    std::vector<uint8_t> greeting;
    greeting.push_back(0x05); // VER
    if (useAuth) {
        greeting.push_back(0x02); // NMETHODS
        greeting.push_back(0x00); // NO AUTH
        greeting.push_back(0x02); // USER/PASS
    } else {
        greeting.push_back(0x01);
        greeting.push_back(0x00);
    }

    if (!SendAll(s, greeting.data(), greeting.size(), cfg.timeout_ms)) {
        LogError("SOCKS5 greeting send failed");
        return false;
    }

    uint8_t methodResp[2] = {};
    if (!RecvExact(s, methodResp, 2, cfg.timeout_ms) || methodResp[0] != 0x05) {
        LogError("SOCKS5 greeting recv failed");
        return false;
    }

    // 2. Optional Username/Password auth (RFC 1929)
    if (methodResp[1] == 0x02) {
        if (!useAuth || cfg.username.size() > 255 || cfg.password.size() > 255) {
            LogError("SOCKS5 proxy requires auth but credentials missing/invalid");
            return false;
        }
        std::vector<uint8_t> auth;
        auth.push_back(0x01);
        auth.push_back(static_cast<uint8_t>(cfg.username.size()));
        auth.insert(auth.end(), cfg.username.begin(), cfg.username.end());
        auth.push_back(static_cast<uint8_t>(cfg.password.size()));
        auth.insert(auth.end(), cfg.password.begin(), cfg.password.end());

        if (!SendAll(s, auth.data(), auth.size(), cfg.timeout_ms)) {
            LogError("SOCKS5 auth send failed");
            return false;
        }
        uint8_t authResp[2] = {};
        if (!RecvExact(s, authResp, 2, cfg.timeout_ms) || authResp[1] != 0x00) {
            LogError("SOCKS5 auth rejected (status=%u)", authResp[1]);
            return false;
        }
    } else if (methodResp[1] != 0x00) {
        LogError("SOCKS5 unsupported auth method: 0x%02X", methodResp[1]);
        return false;
    }

    // 3. CONNECT request
    std::vector<uint8_t> req;
    req.push_back(0x05); // VER
    req.push_back(0x01); // CMD = CONNECT
    req.push_back(0x00); // RSV

    uint16_t portNet = 0;
    if (cfg.remote_dns && !targetDomain.empty() && targetDomain.size() <= 255) {
        req.push_back(0x03); // ATYP = DOMAINNAME
        req.push_back(static_cast<uint8_t>(targetDomain.size()));
        req.insert(req.end(), targetDomain.begin(), targetDomain.end());
        portNet = htons(ExtractPort(targetAddr));
    } else if (targetAddr->sa_family == AF_INET) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(targetAddr);
        req.push_back(0x01); // ATYP = IPv4
        const auto* b = reinterpret_cast<const uint8_t*>(&sin->sin_addr);
        req.insert(req.end(), b, b + 4);
        portNet = sin->sin_port;
    } else if (targetAddr->sa_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(targetAddr);
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            req.push_back(0x01); // ATYP = IPv4
            req.insert(req.end(), &sin6->sin6_addr.s6_bytes[12], &sin6->sin6_addr.s6_bytes[16]);
        } else {
            req.push_back(0x04); // ATYP = IPv6
            req.insert(req.end(), sin6->sin6_addr.s6_bytes, sin6->sin6_addr.s6_bytes + 16);
        }
        portNet = sin6->sin6_port;
    } else {
        return false;
    }

    const auto* portBytes = reinterpret_cast<const uint8_t*>(&portNet);
    req.push_back(portBytes[0]);
    req.push_back(portBytes[1]);

    if (!SendAll(s, req.data(), req.size(), cfg.timeout_ms)) {
        LogError("SOCKS5 CONNECT request send failed");
        return false;
    }

    // 4. CONNECT reply
    uint8_t hdr[4] = {};
    if (!RecvExact(s, hdr, 4, cfg.timeout_ms)) {
        LogError("SOCKS5 CONNECT reply header recv failed");
        return false;
    }
    if (hdr[0] != 0x05 || hdr[1] != 0x00) {
        LogError("SOCKS5 CONNECT rejected (VER=%u, REP=0x%02X)", hdr[0], hdr[1]);
        return false;
    }

    size_t addrLen = 0;
    if (hdr[3] == 0x01) {
        addrLen = 4;
    } else if (hdr[3] == 0x04) {
        addrLen = 16;
    } else if (hdr[3] == 0x03) {
        uint8_t domLen = 0;
        if (!RecvExact(s, &domLen, 1, cfg.timeout_ms)) return false;
        addrLen = domLen;
    } else {
        return false;
    }

    std::vector<uint8_t> discard(addrLen + 2);
    if (!RecvExact(s, discard.data(), discard.size(), cfg.timeout_ms)) {
        return false;
    }

    return true;
}

bool HandshakeHttpConnect(SOCKET s,
                          const sockaddr* targetAddr,
                          const std::string& targetDomain,
                          const Config& cfg) {
    uint16_t port = ExtractPort(targetAddr);
    std::string hostStr;

    if (cfg.remote_dns && !targetDomain.empty()) {
        hostStr = targetDomain;
    } else if (targetAddr->sa_family == AF_INET) {
        hostStr = ExtractIpKey(targetAddr);
    } else if (targetAddr->sa_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(targetAddr);
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            char ipBuf[INET_ADDRSTRLEN] = {};
            in_addr v4 = {};
            std::memcpy(&v4, &sin6->sin6_addr.s6_bytes[12], 4);
            inet_ntop(AF_INET, &v4, ipBuf, sizeof(ipBuf));
            hostStr = ipBuf;
        } else {
            hostStr = "[" + ExtractIpKey(targetAddr) + "]";
        }
    } else {
        return false;
    }

    std::string authority = hostStr + ":" + std::to_string(port);
    std::string req = "CONNECT " + authority + " HTTP/1.1\r\n"
                      "Host: " + authority + "\r\n"
                      "Proxy-Connection: keep-alive\r\n";

    if (!cfg.username.empty()) {
        std::string creds = cfg.username + ":" + cfg.password;
        req += "Proxy-Authorization: Basic " + Base64Encode(creds) + "\r\n";
    }
    req += "\r\n";

    if (!SendAll(s, reinterpret_cast<const uint8_t*>(req.data()), req.size(), cfg.timeout_ms)) {
        LogError("HTTP CONNECT send failed");
        return false;
    }

    // Read response byte-by-byte until "\r\n\r\n" so we never over-read application TLS bytes!
    std::string resp;
    resp.reserve(256);
    while (resp.size() < 8192) {
        uint8_t ch = 0;
        if (!RecvExact(s, &ch, 1, cfg.timeout_ms)) {
            LogError("HTTP CONNECT reply recv failed");
            return false;
        }
        resp.push_back(static_cast<char>(ch));
        if (resp.size() >= 4 &&
            resp[resp.size() - 4] == '\r' &&
            resp[resp.size() - 3] == '\n' &&
            resp[resp.size() - 2] == '\r' &&
            resp[resp.size() - 1] == '\n') {
            break;
        }
    }

    // Expect "HTTP/1.x 200 ..."
    size_t sp = resp.find(' ');
    if (sp == std::string::npos || sp + 4 > resp.size() || resp.compare(sp + 1, 3, "200") != 0) {
        size_t eol = resp.find("\r\n");
        std::string statusLine = (eol == std::string::npos) ? resp : resp.substr(0, eol);
        LogError("HTTP CONNECT rejected: %s", statusLine.c_str());
        return false;
    }

    return true;
}

} // namespace

bool ShouldBypassAddress(const sockaddr* addr, int namelen, const Config& cfg) {
    if (!addr) return true;
    if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) {
        return true;
    }
    if (addr->sa_family == AF_INET && namelen < static_cast<int>(sizeof(sockaddr_in))) {
        return true;
    }
    if (addr->sa_family == AF_INET6 && namelen < static_cast<int>(sizeof(sockaddr_in6))) {
        return true;
    }

    if (ExtractPort(addr) == 0) {
        return true;
    }

    // Always bypass loopback and the proxy server itself to prevent infinite recursion
    if (IsLoopbackOnly(addr)) {
        return true;
    }
    if (ExtractIpKey(addr) == cfg.host && ExtractPort(addr) == cfg.port) {
        return true;
    }

    if (cfg.bypass_lan) {
        if (addr->sa_family == AF_INET) {
            const auto* sin = reinterpret_cast<const sockaddr_in*>(addr);
            if (IsPrivateOrLocalIPv4(sin->sin_addr)) return true;
        } else if (addr->sa_family == AF_INET6) {
            const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
            if (IsPrivateOrLocalIPv6(sin6->sin6_addr)) return true;
        }
    }

    return false;
}

std::string ExtractIpKey(const sockaddr* addr) {
    if (!addr) return {};
    char buf[INET6_ADDRSTRLEN] = {};
    if (addr->sa_family == AF_INET) {
        const auto* sin = reinterpret_cast<const sockaddr_in*>(addr);
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        return buf;
    }
    if (addr->sa_family == AF_INET6) {
        const auto* sin6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
            in_addr v4 = {};
            std::memcpy(&v4, &sin6->sin6_addr.s6_bytes[12], 4);
            inet_ntop(AF_INET, &v4, buf, sizeof(buf));
            return buf;
        }
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
        return buf;
    }
    return {};
}

uint16_t ExtractPort(const sockaddr* addr) {
    if (!addr) return 0;
    if (addr->sa_family == AF_INET) {
        return ntohs(reinterpret_cast<const sockaddr_in*>(addr)->sin_port);
    }
    if (addr->sa_family == AF_INET6) {
        return ntohs(reinterpret_cast<const sockaddr_in6*>(addr)->sin6_port);
    }
    return 0;
}

std::string FormatSockAddr(const sockaddr* addr) {
    std::string ip = ExtractIpKey(addr);
    uint16_t port = ExtractPort(addr);
    if (addr && addr->sa_family == AF_INET6 && ip.find(':') != std::string::npos) {
        return "[" + ip + "]:" + std::to_string(port);
    }
    return ip + ":" + std::to_string(port);
}

int ConnectViaProxy(SOCKET s,
                    const sockaddr* targetAddr,
                    int targetLen,
                    const std::string& targetDomain,
                    const Config& cfg,
                    ConnectFn origConnect) {
    (void)targetLen;
    if (!ConnectToProxyEndpoint(s, targetAddr->sa_family, cfg, origConnect)) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }

    bool ok = false;
    if (cfg.type == ProxyType::Http) {
        ok = HandshakeHttpConnect(s, targetAddr, targetDomain, cfg);
    } else {
        ok = HandshakeSocks5(s, targetAddr, targetDomain, cfg);
    }

    if (!ok) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }

    return 0;
}

} // namespace gproxy
