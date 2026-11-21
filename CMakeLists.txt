cmake_minimum_required(VERSION 3.20)
project(gemini_app_proxy LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "gemini-app-proxy only supports Windows (x64).")
endif()

# Static MSVC runtime (/MT) so version.dll has zero external VC++ redistributable dependencies
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_subdirectory(third_party/minhook)

add_library(version SHARED
    src/dllmain.cpp
    src/version_exports.cpp
    src/version.def
    src/config.cpp
    src/logger.cpp
    src/proxy_client.cpp
    src/hooks.cpp
)

set_target_properties(version PROPERTIES
    OUTPUT_NAME "version"
    PREFIX ""
    SUFFIX ".dll"
)

target_include_directories(version PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(version PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(version PRIVATE
    minhook
    ws2_32
)
