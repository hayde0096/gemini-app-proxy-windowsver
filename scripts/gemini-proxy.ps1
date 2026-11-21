<#
.SYNOPSIS
    CLI manager for gemini-app-proxy (install / uninstall / status / test / logs).
.EXAMPLE
    .\scripts\gemini-proxy.ps1 install -ProxyType socks5 -ProxyHost 127.0.0.1 -ProxyPort 7890
    .\scripts\gemini-proxy.ps1 status
    .\scripts\gemini-proxy.ps1 test
    .\scripts\gemini-proxy.ps1 logs -Tail 40
    .\scripts\gemini-proxy.ps1 uninstall
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("install", "uninstall", "status", "test", "logs")]
    [string]$Action = "status",

    [ValidateSet("socks5", "http")]
    [string]$ProxyType = "socks5",

    [string]$ProxyHost = "127.0.0.1",
    [int]$ProxyPort = 7890,
    [string]$Username = "",
    [string]$Password = "",
    [int]$LogLevel = 1,

    [string]$GeminiDir = (Join-Path $env:LOCALAPPDATA "Google\Gemini"),
    [string]$DllPath = "",

    [switch]$ForceConfig,
    [switch]$RemoveConfig,
    [switch]$Restart,
    [int]$Tail = 30
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($DllPath)) {
    $DllPath = Join-Path $RepoRoot "dist\version.dll"
}

function Get-LatestAppDir {
    param([string]$Root)
    if (-not (Test-Path $Root)) {
        return $null
    }
    $dirs = Get-ChildItem -Path $Root -Directory -Filter "app-*" | Sort-Object {
        $verStr = $_.Name -replace '^app-', ''
        try { [version]$verStr } catch { [version]"0.0.0.0" }
    } -Descending
    return ($dirs | Select-Object -First 1)
}

function Get-AllAppDirs {
    param([string]$Root)
    if (-not (Test-Path $Root)) { return @() }
    return @(Get-ChildItem -Path $Root -Directory -Filter "app-*")
}

function Stop-GeminiIfRunning {
    $procs = Get-Process -Name "Gemini" -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Host "[gemini-proxy] Stopping running Gemini processes ($($procs.Count))..." -ForegroundColor Yellow
        $procs | Stop-Process -Force
        Start-Sleep -Milliseconds 800
        return $true
    }
    return $false
}

function Start-GeminiApp {
    param([string]$Root)
    $launcher = Join-Path $Root "Gemini.exe"
    if (Test-Path $launcher) {
        Write-Host "[gemini-proxy] Launching Gemini App..." -ForegroundColor Cyan
        Start-Process -FilePath $launcher
    }
}

function Read-IniValue {
    param([string]$Path, [string]$Key, [string]$Default = "")
    if (-not (Test-Path $Path)) { return $Default }
    foreach ($line in Get-Content $Path) {
        $t = $line.Trim()
        if ($t -match "^$Key\s*=\s*(.*)$") {
            return $Matches[1].Trim()
        }
    }
    return $Default
}

switch ($Action) {
    "install" {
        if (-not (Test-Path $DllPath)) {
            throw "version.dll not found at '$DllPath'. Run .\scripts\build.ps1 first."
        }
        $latest = Get-LatestAppDir -Root $GeminiDir
        if (-not $latest) {
            throw "No Gemini app-* directory found under '$GeminiDir'. Specify -GeminiDir if installed elsewhere."
        }

        $wasRunning = Stop-GeminiIfRunning

        $targetDll = Join-Path $latest.FullName "version.dll"
        Copy-Item -Force $DllPath $targetDll
        Write-Host "[gemini-proxy] Installed version.dll -> $targetDll" -ForegroundColor Green

        $configPath = Join-Path $GeminiDir "gemini-proxy.ini"
        if ($ForceConfig -or -not (Test-Path $configPath)) {
            $ini = @"
[proxy]
enabled=1
type=$ProxyType
host=$ProxyHost
port=$ProxyPort
username=$Username
password=$Password

[network]
block_quic=1
bypass_lan=1
remote_dns=1
timeout_ms=10000

[logging]
level=$LogLevel
file=
"@
            Set-Content -Path $configPath -Value $ini -Encoding UTF8
            Write-Host "[gemini-proxy] Wrote config -> $configPath ($ProxyType`://$ProxyHost`:$ProxyPort)" -ForegroundColor Green
        } else {
            Write-Host "[gemini-proxy] Kept existing config -> $configPath (use -ForceConfig to overwrite)" -ForegroundColor Cyan
        }

        if ($Restart -or $wasRunning) {
            Start-GeminiApp -Root $GeminiDir
        } else {
            Write-Host "[gemini-proxy] Done! Start Gemini App to take effect." -ForegroundColor Green
        }
    }

    "uninstall" {
        $wasRunning = Stop-GeminiIfRunning
        $removed = 0
        foreach ($dir in (Get-AllAppDirs -Root $GeminiDir)) {
            $dll = Join-Path $dir.FullName "version.dll"
            if (Test-Path $dll) {
                Remove-Item -Force $dll
                Write-Host "[gemini-proxy] Removed $dll" -ForegroundColor Green
                $removed++
            }
        }
        if ($removed -eq 0) {
            Write-Host "[gemini-proxy] No version.dll patch found." -ForegroundColor Yellow
        }
        if ($RemoveConfig) {
            $configPath = Join-Path $GeminiDir "gemini-proxy.ini"
            if (Test-Path $configPath) {
                Remove-Item -Force $configPath
                Write-Host "[gemini-proxy] Removed $configPath" -ForegroundColor Green
            }
        }
        if ($Restart -and $wasRunning) {
            Start-GeminiApp -Root $GeminiDir
        }
    }

    "status" {
        Write-Host "=== gemini-app-proxy status ===" -ForegroundColor Cyan
        Write-Host "Gemini Dir : $GeminiDir"
        $latest = Get-LatestAppDir -Root $GeminiDir
        if ($latest) {
            $dll = Join-Path $latest.FullName "version.dll"
            $patched = Test-Path $dll
            Write-Host "Latest App : $($latest.Name)"
            Write-Host "Patch DLL  : $(if ($patched) { "INSTALLED ($dll)" } else { "NOT INSTALLED" })" -ForegroundColor $(if ($patched) { "Green" } else { "Yellow" })
        } else {
            Write-Host "Latest App : NOT FOUND" -ForegroundColor Red
        }

        $configPath = Join-Path $GeminiDir "gemini-proxy.ini"
        if (Test-Path $configPath) {
            $en   = Read-IniValue $configPath "enabled" "1"
            $type = Read-IniValue $configPath "type" "socks5"
            $hostVal = Read-IniValue $configPath "host" "127.0.0.1"
            $portVal = Read-IniValue $configPath "port" "7890"
            Write-Host "Config     : $configPath"
            Write-Host "Endpoint   : $type`://$hostVal`:$portVal (enabled=$en)"
        } else {
            Write-Host "Config     : NOT FOUND" -ForegroundColor Yellow
        }

        $procs = Get-Process -Name "Gemini" -ErrorAction SilentlyContinue
        Write-Host "Running    : $(if ($procs) { "YES ($($procs.Count) processes)" } else { "NO" })"
    }

    "test" {
        $configPath = Join-Path $GeminiDir "gemini-proxy.ini"
        $hostVal = if (Test-Path $configPath) { Read-IniValue $configPath "host" $ProxyHost } else { $ProxyHost }
        $portVal = if (Test-Path $configPath) { [int](Read-IniValue $configPath "port" "$ProxyPort") } else { $ProxyPort }
        $typeVal = if (Test-Path $configPath) { Read-IniValue $configPath "type" $ProxyType } else { $ProxyType }

        Write-Host "[gemini-proxy] Testing TCP reachability to $typeVal`://$hostVal`:$portVal ..." -ForegroundColor Cyan
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $ar = $tcp.BeginConnect($hostVal, $portVal, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne(3000, $false)) {
                $tcp.Close()
                throw "Connection timed out"
            }
            $tcp.EndConnect($ar)
            $tcp.Close()
            Write-Host "[gemini-proxy] Proxy port $hostVal`:$portVal is REACHABLE!" -ForegroundColor Green
        } catch {
            Write-Host "[gemini-proxy] FAILED to connect to $hostVal`:$portVal : $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }

    "logs" {
        $logPath = Join-Path $GeminiDir "logs\gemini-proxy.log"
        if (-not (Test-Path $logPath)) {
            Write-Host "[gemini-proxy] Log file not found yet: $logPath" -ForegroundColor Yellow
            exit 0
        }
        Write-Host "=== $logPath (last $Tail lines) ===" -ForegroundColor Cyan
        Get-Content -Path $logPath -Tail $Tail
    }
}
