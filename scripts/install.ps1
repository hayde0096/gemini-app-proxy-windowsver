<#
.SYNOPSIS
    One-line remote installer for gemini-app-proxy (Windows x64).
.EXAMPLE
    # Default interactive install from latest GitHub Release:
    irm https://raw.githubusercontent.com/hayde0096/gemini-app-proxy-windowsver/main/scripts/install.ps1 | iex

    # Non-interactive install with custom proxy:
    $env:GEMINI_PROXY="socks5://127.0.0.1:7897"; irm https://raw.githubusercontent.com/hayde0096/gemini-app-proxy-windowsver/main/scripts/install.ps1 | iex

    # Uninstall:
    $env:GEMINI_PROXY_UNINSTALL="1"; irm https://raw.githubusercontent.com/hayde0096/gemini-app-proxy-windowsver/main/scripts/install.ps1 | iex
#>

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Repo       = if ($env:GEMINI_PROXY_REPO) { $env:GEMINI_PROXY_REPO } else { "hayde0096/gemini-app-proxy-windowsver" }
$Version    = if ($env:GEMINI_PROXY_VERSION) { $env:GEMINI_PROXY_VERSION } else { "latest" }
$Mirror     = if ($env:GH_MIRROR) { $env:GH_MIRROR.TrimEnd('/') + "/" } else { "" }
$GeminiDir  = if ($env:GEMINI_APP_DIR) { $env:GEMINI_APP_DIR } else { Join-Path $env:LOCALAPPDATA "Google\Gemini" }
$Uninstall  = ($env:GEMINI_PROXY_UNINSTALL -eq "1" -or $env:GEMINI_PROXY_UNINSTALL -eq "true")

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  gemini-app-proxy Installer (Win x64)   " -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "Only 64-bit Windows (x64) is supported."
}

if (-not (Test-Path $GeminiDir)) {
    throw "Gemini Desktop App directory not found: $GeminiDir`nPlease install Google Gemini Desktop App first, or set `$env:GEMINI_APP_DIR."
}

$appDirs = @(Get-ChildItem -Path $GeminiDir -Directory -Filter "app-*" | Sort-Object {
    $v = $_.Name -replace '^app-', ''
    try { [version]$v } catch { [version]"0.0.0.0" }
} -Descending)

if ($appDirs.Count -eq 0) {
    throw "No app-* directory found under $GeminiDir."
}

$latestAppDir = $appDirs[0]
Write-Host "[+] Detected Gemini App: $($latestAppDir.FullName)" -ForegroundColor Green

function Stop-GeminiProcesses {
    $procs = Get-Process -Name "Gemini" -ErrorAction SilentlyContinue
    if ($procs) {
        Write-Host "[*] Stopping running Gemini processes ($($procs.Count))..." -ForegroundColor Yellow
        $procs | Stop-Process -Force
        Start-Sleep -Milliseconds 800
        return $true
    }
    return $false
}

if ($Uninstall) {
    $wasRunning = Stop-GeminiProcesses
    $removed = 0
    foreach ($d in $appDirs) {
        $dll = Join-Path $d.FullName "version.dll"
        if (Test-Path $dll) {
            Remove-Item -Force $dll
            Write-Host "[+] Removed $dll" -ForegroundColor Green
            $removed++
        }
    }
    if ($removed -eq 0) {
        Write-Host "[!] No version.dll patch was installed." -ForegroundColor Yellow
    }
    Write-Host "[+] Uninstall complete. Config (if any) kept at: $(Join-Path $GeminiDir 'gemini-proxy.ini')" -ForegroundColor Green
    if ($wasRunning) {
        $launcher = Join-Path $GeminiDir "Gemini.exe"
        if (Test-Path $launcher) { Start-Process -FilePath $launcher }
    }
    return
}

# Resolve download URLs
if ($Version -eq "latest") {
    $dllUrl  = "${Mirror}https://github.com/$Repo/releases/latest/download/version.dll"
    $hashUrl = "${Mirror}https://github.com/$Repo/releases/latest/download/SHA256SUMS.txt"
} else {
    $dllUrl  = "${Mirror}https://github.com/$Repo/releases/download/$Version/version.dll"
    $hashUrl = "${Mirror}https://github.com/$Repo/releases/download/$Version/SHA256SUMS.txt"
}

$tempDir = Join-Path $env:TEMP ("gemini-app-proxy-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
$tempDll = Join-Path $tempDir "version.dll"
$tempSum = Join-Path $tempDir "SHA256SUMS.txt"

$dlProxy = if ($env:HTTPS_PROXY) { $env:HTTPS_PROXY } elseif ($env:HTTP_PROXY) { $env:HTTP_PROXY } elseif ($env:GEMINI_PROXY -match '^https?://') { $env:GEMINI_PROXY } else { $null }
$iwrCommon = @{ UseBasicParsing = $true }
if ($dlProxy) {
    $iwrCommon["Proxy"] = $dlProxy
    Write-Host "[*] Using download proxy: $dlProxy" -ForegroundColor DarkGray
}

try {
    Write-Host "[*] Downloading version.dll ($Version)..." -ForegroundColor Cyan
    Write-Host "    URL: $dllUrl" -ForegroundColor DarkGray
    Invoke-WebRequest -Uri $dllUrl -OutFile $tempDll @iwrCommon

    # Optional SHA256 verification
    try {
        Invoke-WebRequest -Uri $hashUrl -OutFile $tempSum @iwrCommon
        $expectedLine = Get-Content $tempSum | Where-Object { $_ -match '\bversion\.dll$' } | Select-Object -First 1
        if ($expectedLine) {
            $expectedHash = ($expectedLine -split '\s+')[0].ToLower()
            $actualHash   = (Get-FileHash $tempDll -Algorithm SHA256).Hash.ToLower()
            if ($expectedHash -ne $actualHash) {
                throw "SHA256 mismatch! Expected $expectedHash, got $actualHash."
            }
            Write-Host "[+] SHA256 verified: $actualHash" -ForegroundColor Green
        }
    } catch {
        if ($_.Exception.Message -like "SHA256 mismatch*") { throw }
        Write-Host "[!] Skipped SHA256 verification (checksum file unavailable)." -ForegroundColor Yellow
    }

    # Configure gemini-proxy.ini
    $configPath = Join-Path $GeminiDir "gemini-proxy.ini"
    $needConfig = (-not (Test-Path $configPath)) -or ($env:GEMINI_PROXY_RECONFIG -eq "1") -or (-not [string]::IsNullOrWhiteSpace($env:GEMINI_PROXY))

    if ($needConfig) {
        $proxyType = "socks5"
        $proxyHost = "127.0.0.1"
        $proxyPort = 7890
        $proxyUser = ""
        $proxyPass = ""

        if (-not [string]::IsNullOrWhiteSpace($env:GEMINI_PROXY)) {
            if ($env:GEMINI_PROXY -match '^(socks5|http|https)://(?:([^:@]+):([^@]*)@)?([^:]+):(\d+)$') {
                $proxyType = if ($Matches[1] -eq "socks5") { "socks5" } else { "http" }
                $proxyUser = $Matches[2]
                $proxyPass = $Matches[3]
                $proxyHost = $Matches[4]
                $proxyPort = [int]$Matches[5]
            } else {
                Write-Host "[!] Invalid GEMINI_PROXY format '$($env:GEMINI_PROXY)', expected e.g. socks5://127.0.0.1:7890" -ForegroundColor Yellow
            }
        } elseif ([Environment]::UserInteractive) {
            Write-Host ""
            $inType = Read-Host "Proxy type [socks5/http] (default: socks5)"
            if ($inType -eq "http") { $proxyType = "http" }

            $inHost = Read-Host "Proxy host (default: 127.0.0.1)"
            if (-not [string]::IsNullOrWhiteSpace($inHost)) { $proxyHost = $inHost.Trim() }

            $inPort = Read-Host "Proxy port (default: 7890)"
            if (-not [string]::IsNullOrWhiteSpace($inPort)) { $proxyPort = [int]$inPort.Trim() }
        }

        $iniContent = @"
[proxy]
enabled=1
type=$proxyType
host=$proxyHost
port=$proxyPort
username=$proxyUser
password=$proxyPass

[network]
block_quic=1
bypass_lan=1
remote_dns=1
timeout_ms=10000

[logging]
level=1
file=
"@
        Set-Content -Path $configPath -Value $iniContent -Encoding UTF8
        Write-Host "[+] Wrote config: $configPath ($proxyType`://$proxyHost`:$proxyPort)" -ForegroundColor Green
    } else {
        Write-Host "[+] Keeping existing config: $configPath" -ForegroundColor Cyan
    }

    $wasRunning = Stop-GeminiProcesses
    $targetDll = Join-Path $latestAppDir.FullName "version.dll"
    Copy-Item -Force $tempDll $targetDll
    Write-Host "[+] Installed version.dll -> $targetDll" -ForegroundColor Green

    $launcher = Join-Path $GeminiDir "Gemini.exe"
    if ($wasRunning -and (Test-Path $launcher)) {
        Write-Host "[*] Restarting Gemini App..." -ForegroundColor Cyan
        Start-Process -FilePath $launcher
    } else {
        Write-Host "[+] Done! Launch Gemini App to start proxying." -ForegroundColor Green
    }
    Write-Host "    Logs: $(Join-Path $GeminiDir 'logs\gemini-proxy.log')" -ForegroundColor DarkGray
} finally {
    Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
}
