#pragma once

#include <string>

namespace gproxy {

void InitLogger(const std::wstring& logPath, int level);
void CloseLogger();

void LogInfo(const char* fmt, ...);
void LogDebug(const char* fmt, ...);
void LogError(const char* fmt, ...);

} // namespace gproxy
