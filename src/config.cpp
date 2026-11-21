#include "config.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace gproxy {

namespace {

Config g_config;

std::string Trim(std::string s) {
    auto notSpace = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
    return s;
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

bool ParseBool(const std::string& val, bool defaultVal) {
    std::string l = ToLower(Trim(val));
    if (l == "1" || l == "true" || l == "yes" || l == "on") return true;
    if (l == "0" || l == "false" || l == "no" || l == "off") return false;
    return defaultVal;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(needed, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), out.data(), needed);
    return out;
}

std::wstring GetParentDir(const std::wstring& path) {
    size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return {};
    return path.substr(0, pos);
}

bool FileExists(const std::wstring& path) {
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool ParseIniFile(const std::wstring& path, Config& cfg) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0 || fileSize.QuadPart > 1024 * 1024) {
        CloseHandle(hFile);
        return false;
    }

    std::string content(static_cast<size_t>(fileSize.QuadPart), '\0');
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, content.data(), static_cast<DWORD>(content.size()), &bytesRead, nullptr);
    CloseHandle(hFile);
    if (!ok) {
        return false;
    }
    content.resize(bytesRead);

    // Strip UTF-8 BOM if present
    if (content.size() >= 3 &&
        static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB &&
        static_cast<unsigned char>(content[2]) == 0xBF) {
        content.erase(0, 3);
    }

    std::istringstream iss(content);
    std::string line;
    std::string section;

    while (std::getline(iss, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') {
            continue;
        }
        if (line.front() == '[' && line.back() == ']') {
            section = ToLower(Trim(line.substr(1, line.size() - 2)));
            continue;
        }

        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        std::string key = ToLower(Trim(line.substr(0, eq)));
        std::string val = Trim(line.substr(eq + 1));

        if (section == "proxy" || section.empty()) {
            if (key == "enabled") {
                cfg.enabled = ParseBool(val, cfg.enabled);
            } else if (key == "type" || key == "protocol") {
                std::string t = ToLower(val);
                if (t == "http" || t == "https") {
                    cfg.type = ProxyType::Http;
                } else {
                    cfg.type = ProxyType::Socks5;
                }
            } else if (key == "host") {
                if (!val.empty()) cfg.host = val;
            } else if (key == "port") {
                try {
                    int p = std::stoi(val);
                    if (p > 0 && p <= 65535) cfg.port = static_cast<uint16_t>(p);
                } catch (...) {}
            } else if (key == "username" || key == "user") {
                cfg.username = val;
            } else if (key == "password" || key == "pass") {
                cfg.password = val;
            }
        } else if (section == "network") {
            if (key == "block_quic") {
                cfg.block_quic = ParseBool(val, cfg.block_quic);
            } else if (key == "bypass_lan") {
                cfg.bypass_lan = ParseBool(val, cfg.bypass_lan);
            } else if (key == "remote_dns") {
                cfg.remote_dns = ParseBool(val, cfg.remote_dns);
            } else if (key == "timeout_ms") {
                try {
                    int t = std::stoi(val);
                    if (t >= 500 && t <= 120000) cfg.timeout_ms = t;
                } catch (...) {}
            }
        } else if (section == "logging") {
            if (key == "level") {
                try {
                    cfg.log_level = std::stoi(val);
                } catch (...) {}
            } else if (key == "file") {
                if (!val.empty()) cfg.log_file = Utf8ToWide(val);
            }
        }
    }

    cfg.config_path = path;
    return true;
}

} // namespace

const Config& GetConfig() {
    return g_config;
}

bool LoadConfig(HMODULE selfModule) {
    Config cfg;

    wchar_t modulePath[MAX_PATH] = {};
    if (GetModuleFileNameW(selfModule, modulePath, MAX_PATH) == 0) {
        g_config = cfg;
        return false;
    }

    std::wstring dllDir = GetParentDir(modulePath);
    std::wstring parentDir = GetParentDir(dllDir);

    // Priority:
    // 1. Same directory as version.dll (e.g. app-1.19.0\gemini-proxy.ini)
    // 2. Parent directory (e.g. %LocalAppData%\Google\Gemini\gemini-proxy.ini) - survives app updates!
    std::wstring candidate1 = dllDir + L"\\gemini-proxy.ini";
    std::wstring candidate2 = parentDir + L"\\gemini-proxy.ini";

    bool loaded = false;
    if (FileExists(candidate1)) {
        loaded = ParseIniFile(candidate1, cfg);
    } else if (!parentDir.empty() && FileExists(candidate2)) {
        loaded = ParseIniFile(candidate2, cfg);
    }

    if (cfg.log_file.empty() && !parentDir.empty()) {
        std::wstring logsDir = parentDir + L"\\logs";
        DWORD attr = GetFileAttributesW(logsDir.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
            cfg.log_file = logsDir + L"\\gemini-proxy.log";
        } else {
            cfg.log_file = dllDir + L"\\gemini-proxy.log";
        }
    }

    g_config = std::move(cfg);
    return loaded;
}

} // namespace gproxy
