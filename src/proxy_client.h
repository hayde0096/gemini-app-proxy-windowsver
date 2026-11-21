#pragma once

#include "config.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

namespace gproxy {

using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);

// Returns true if the destination address should bypass the proxy (loopback, LAN, proxy itself, etc.)
bool ShouldBypassAddress(const sockaddr* addr, int namelen, const Config& cfg);

// Formats a sockaddr into "ip:port" for logging
std::string FormatSockAddr(const sockaddr* addr);

// Extracts IP key string (IPv4 or IPv6) from sockaddr for DNS cache lookup
std::string ExtractIpKey(const sockaddr* addr);

// Extracts destination port (host byte order) from sockaddr
uint16_t ExtractPort(const sockaddr* addr);

// Connects socket `s` to the configured proxy using `origConnect`, then performs
// SOCKS5 or HTTP CONNECT handshake to reach `targetAddr` (using `targetDomain` if non-empty
// and remote_dns is enabled). Works safely on both blocking and non-blocking sockets.
// Returns 0 on success, or SOCKET_ERROR (with WSASetLastError set) on failure.
int ConnectViaProxy(SOCKET s,
                    const sockaddr* targetAddr,
                    int targetLen,
                    const std::string& targetDomain,
                    const Config& cfg,
                    ConnectFn origConnect);

} // namespace gproxy
