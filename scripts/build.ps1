<#
.SYNOPSIS
    Build gemini-app-proxy (version.dll, x64 Release) using Visual Studio 2022 CMake + Ninja (or MSBuild fallback).
#>
[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Config = "Release",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$BuildDir = Join-Path $RepoRoot "build"
$DistDir  = Join-Path $RepoRoot "dist"

function Find-VSInstall {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsPath) { return $vsPath }
        $vsPath = & $vswhere -latest -property installationPath
        if ($vsPath) { return $vsPath }
    }
    return $null
}

$vsPath = Find-VSInstall
$cmakeCmd = Get-Command cmake -ErrorAction SilentlyContinue
$cmake = if ($cmakeCmd) { $cmakeCmd.Source } else { $null }
if (-not $cmake -and $vsPath) {
    $candidate = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
    if (Test-Path $candidate) { $cmake = $candidate }
}
if (-not $cmake) {
    throw "CMake not found. Please install CMake or Visual Studio 2022 with C++ Desktop Development."
}

$ninjaCmd = Get-Command ninja -ErrorAction SilentlyContinue
$ninja = if ($ninjaCmd) { $ninjaCmd.Source } else { $null }
if (-not $ninja -and $vsPath) {
    $candidate = Join-Path $vsPath "Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
    if (Test-Path $candidate) { $ninja = $candidate }
}

$vcvars = $null
if ($vsPath) {
    $candidate = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
    if (Test-Path $candidate) { $vcvars = $candidate }
}

Write-Host "[build] Using CMake: $cmake" -ForegroundColor Cyan

if ($Clean -and (Test-Path $BuildDir)) {
    Write-Host "[build] Cleaning $BuildDir ..."
    Remove-Item -Recurse -Force $BuildDir
}

if ($ninja -and $vcvars) {
    # Clean MSBuild cache if switching generators
    $cacheFile = Join-Path $BuildDir "CMakeCache.txt"
    if ((Test-Path $cacheFile) -and -not (Select-String -Path $cacheFile -Pattern "CMAKE_GENERATOR:INTERNAL=Ninja" -Quiet)) {
        Remove-Item -Recurse -Force $BuildDir
    }

    Write-Host "[build] Using Ninja: $ninja ($Config, x64)" -ForegroundColor Cyan
    $cmdLine = "`"$vcvars`" && `"$cmake`" -S `"$RepoRoot`" -B `"$BuildDir`" -G Ninja -DCMAKE_MAKE_PROGRAM=`"$ninja`" -DCMAKE_BUILD_TYPE=$Config -DCMAKE_POLICY_VERSION_MINIMUM=3.5 && `"$cmake`" --build `"$BuildDir`" --parallel"
    cmd.exe /c $cmdLine
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $dllPath = Join-Path $BuildDir "version.dll"
} else {
    Write-Host "[build] Configuring (Visual Studio 17 2022, x64)..." -ForegroundColor Cyan
    & $cmake -S $RepoRoot -B $BuildDir -G "Visual Studio 17 2022" -A x64 -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    Write-Host "[build] Building ($Config)..." -ForegroundColor Cyan
    & $cmake --build $BuildDir --config $Config --parallel
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $dllPath = Join-Path $BuildDir "$Config\version.dll"
}

if (-not (Test-Path $dllPath)) {
    throw "Build succeeded but $dllPath was not found."
}

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
Copy-Item -Force $dllPath (Join-Path $DistDir "version.dll")
$exampleIni = Join-Path $RepoRoot "config\gemini-proxy.ini.example"
if (Test-Path $exampleIni) {
    Copy-Item -Force $exampleIni (Join-Path $DistDir "gemini-proxy.ini.example")
}

$info = Get-Item (Join-Path $DistDir "version.dll")
Write-Host "[build] Done! Output: $($info.FullName) ($([math]::Round($info.Length / 1KB, 1)) KB)" -ForegroundColor Green
