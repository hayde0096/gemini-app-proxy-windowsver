#include "logger.h"

#include <cstdarg>
#include <cstdio>
#include <windows.h>

namespace gproxy {

namespace {

CRITICAL_SECTION g_logLock;
bool g_lockInit = false;
HANDLE g_logFile = INVALID_HANDLE_VALUE;
int g_logLevel = 0;
DWORD g_pid = 0;

void WriteLogLine(const char* tag, const char* fmt, va_list args) {
    if (!g_lockInit || g_logFile == INVALID_HANDLE_VALUE) {
        return;
    }

    char msg[1024];
    int n = vsnprintf(msg, sizeof(msg), fmt, args);
    if (n <= 0) return;

    SYSTEMTIME st = {};
    GetLocalTime(&st);

    char line[1200];
    int total = snprintf(line, sizeof(line),
                         "[%04u-%02u-%02u %02u:%02u:%02u.%03u][PID:%lu][%s] %s\r\n",
                         st.wYear, st.wMonth, st.wDay,
                         st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                         g_pid, tag, msg);
    if (total <= 0) return;

    EnterCriticalSection(&g_logLock);
    if (g_logFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER zero = {};
        SetFilePointerEx(g_logFile, zero, nullptr, FILE_END);
        DWORD written = 0;
        WriteFile(g_logFile, line, static_cast<DWORD>(total), &written, nullptr);
    }
    LeaveCriticalSection(&g_logLock);
}

} // namespace

void InitLogger(const std::wstring& logPath, int level) {
    g_logLevel = level;
    g_pid = GetCurrentProcessId();
    if (level <= 0 || logPath.empty()) {
        return;
    }
    if (!g_lockInit) {
        InitializeCriticalSection(&g_logLock);
        g_lockInit = true;
    }
    // FILE_APPEND_DATA allows safe concurrent appends across main + utility processes
    g_logFile = CreateFileW(logPath.c_str(),
                            FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr,
                            OPEN_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr);
}

void CloseLogger() {
    if (!g_lockInit) return;
    EnterCriticalSection(&g_logLock);
    if (g_logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_logLock);
}

void LogInfo(const char* fmt, ...) {
    if (g_logLevel < 1) return;
    va_list args;
    va_start(args, fmt);
    WriteLogLine("INFO", fmt, args);
    va_end(args);
}

void LogDebug(const char* fmt, ...) {
    if (g_logLevel < 2) return;
    va_list args;
    va_start(args, fmt);
    WriteLogLine("DEBUG", fmt, args);
    va_end(args);
}

void LogError(const char* fmt, ...) {
    if (g_logLevel < 1) return;
    va_list args;
    va_start(args, fmt);
    WriteLogLine("ERROR", fmt, args);
    va_end(args);
}

} // namespace gproxy
