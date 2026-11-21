#pragma once

#include <cstdint>
#include <string>
#include <windows.h>

namespace gproxy {

enum class ProxyType {
    Socks5,
    Http,
};

struct Config {
    bool enabled = true;
    ProxyType type = ProxyType::Socks5;
    std::string host = "127.0.0.1";
    uint16_t port = 7890;
    std::string username;
    std::string password;

    bool block_quic = true;
    bool bypass_lan = true;
    bool remote_dns = true;
    int timeout_ms = 10000;

    int log_level = 1; // 0 = off, 1 = info, 2 = debug
    std::wstring log_file;
    std::wstring config_path;
};

const Config& GetConfig();
bool LoadConfig(HMODULE selfModule);

} // namespace gproxy
