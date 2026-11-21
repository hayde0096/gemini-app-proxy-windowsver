# gemini-app-proxy (Windows)

> 免 TUN、免管理员权限的 **Google Gemini Windows 桌面客户端** 透明代理补丁（`version.dll` + MinHook）。
>
> A lightweight, TUN-free, zero-privilege transparent proxy injector (`version.dll` + MinHook) for the official **Google Gemini Desktop App** on Windows (x64).

---

## 一键远程安装 / Quick Install (Recommended)

无需安装编译环境，直接在 PowerShell 中运行：

```powershell
# 交互式安装（自动从 GitHub Release 下载最新 version.dll 并校验 SHA256）
irm https://raw.githubusercontent.com/hayde0096/gemini-app-proxy-windowsver/main/scripts/install.ps1 | iex

# 若终端未开启系统全局代理，可直接通过 -Proxy 指定本地 HTTP 代理拉取并安装（如 1080 / 7890 / 7897）
$env:HTTPS_PROXY="http://127.0.0.1:1080"; irm -Proxy $env:HTTPS_PROXY https://raw.githubusercontent.com/hayde0096/gemini-app-proxy-windowsver/main/scripts/install.ps1 | iex
```

如需一步指定代理地址（非交互模式）：

```powershell
# SOCKS5 示例（Clash / Mihomo 7890 或 7897，v2rayN 10808）
$env:GEMINI_PROXY="socks5://127.0.0.1:7890"
irm https://raw.githubusercontent.com/hayde0096/gemini-app-proxy-windowsver/main/scripts/install.ps1 | iex

# HTTP 代理示例
$env:GEMINI_PROXY="http://127.0.0.1:7897"
irm https://raw.githubusercontent.com/hayde0096/gemini-app-proxy-windowsver/main/scripts/install.ps1 | iex
```

一键卸载：

```powershell
$env:GEMINI_PROXY_UNINSTALL="1"
irm https://raw.githubusercontent.com/hayde0096/gemini-app-proxy-windowsver/main/scripts/install.ps1 | iex
```

---

## 特性 / Features

- **免 TUN 模式 / 免全局代理**：仅接管 Gemini App 进程流量，不影响系统其他软件。
- **免管理员权限**：Gemini Desktop App 安装在 `%LocalAppData%\Google\Gemini`，补丁和配置全程用户态操作。
- **支持 SOCKS5 & HTTP CONNECT**：兼容 Clash / Mihomo / v2rayN / sing-box 等常见本地代理端口，支持用户名/密码认证。
- **覆盖全子进程**：自动拦截 Electron 主进程（Node.js `libuv` / `ConnectEx`）与 Chromium `NetworkService` 进程（`connect` / `WSAConnect`），并跳过 Renderer / GPU 进程以保持零开销。
- **自动阻断 QUIC (UDP 443)**：防止 Chromium 通过 HTTP/3 (UDP) 绕过代理，强制平滑回退到 TCP 走代理通道。
- **防本地 DNS 污染（Remote DNS）**：被动缓存 `getaddrinfo` / `GetAddrInfoW` / `GetAddrInfoExW` 的 `IP -> 域名` 映射，向 SOCKS5（`ATYP=0x03`）或 HTTP `CONNECT` 直接发送真实域名由远端代理解析。
- **配置跨更新保留**：默认将 `gemini-proxy.ini` 放在 `%LocalAppData%\Google\Gemini\` 根目录，Gemini 升级 `app-x.y.z` 后只需重新执行一键安装即可无缝恢复。

---

## 工作原理 / How It Works

```text
Gemini.exe (Electron 42 / Chromium + Node.js)
   │
   ├── 静态导入 version.dll ──▶ 加载同目录下的补丁 version.dll
   │                              ├── 17 个原生导出函数透明转发至 System32\version.dll
   │                              └── 仅在 Main / Utility(NetworkService) 进程启用 MinHook
   │
   ├── Winsock TCP (connect / WSAConnect / ConnectEx)
   │      ├── 局域网 / 回环 / 代理自身地址 ──▶ 直连放行
   │      └── 外网流量 ──▶ SOCKS5 / HTTP CONNECT 隧道 ──▶ 本地代理端口
   │
   ├── Winsock UDP (sendto / WSASendTo / connect)
   │      └── 443 端口 (QUIC) ──▶ 返回 WSAECONNREFUSED，触发回退 TCP
   │
   └── DNS (getaddrinfo / GetAddrInfoW / GetAddrInfoExW)
          └── 被动记录 IP -> 域名 映射，供代理远端解析
```

---

## 从源码编译与本地 CLI 管理 / Build from Source

需要 Visual Studio 2022（C++ 桌面开发工具链）与 CMake：

```powershell
# 克隆仓库（含 MinHook 子模块）
git clone --recursive https://github.com/hayde0096/gemini-app-proxy-windowsver.git
cd gemini-app-proxy-windowsver

# 一键编译 x64 Release（产出 dist\version.dll）
.\scripts\build.ps1

# 安装到本机 Gemini App
.\scripts\gemini-proxy.ps1 install -ProxyType socks5 -ProxyHost 127.0.0.1 -ProxyPort 7890

# 查看状态 / 测试端口 / 查看日志 / 卸载
.\scripts\gemini-proxy.ps1 status
.\scripts\gemini-proxy.ps1 test
.\scripts\gemini-proxy.ps1 logs -Tail 50
.\scripts\gemini-proxy.ps1 uninstall
```

---

## 配置文件说明 / Configuration

配置文件默认位于 `%LocalAppData%\Google\Gemini\gemini-proxy.ini`（也支持放在 `app-x.y.z\gemini-proxy.ini` 覆盖）：

```ini
[proxy]
enabled=1
type=socks5          ; socks5 或 http
host=127.0.0.1
port=7890
username=
password=

[network]
block_quic=1         ; 阻断 UDP 443 (QUIC)，强制走 TCP 代理
bypass_lan=1         ; 放行回环与内网地址
remote_dns=1         ; 优先向代理传递域名进行远端解析
timeout_ms=10000

[logging]
level=1              ; 0=关闭, 1=信息/错误, 2=详细调试(记录每条连接)
file=                ; 留空默认写入 %LocalAppData%\Google\Gemini\logs\gemini-proxy.log
```

---

## 常见问题 / Troubleshooting

1. **Gemini App 自动更新后代理失效了？**
   - Gemini 更新后会新建 `app-x.y.z` 目录，重新运行一键安装命令即可自动定位新目录并写入 `version.dll`，原有 `gemini-proxy.ini` 配置会自动保留。
2. **如何确认流量确实走了代理？**
   - 将 `gemini-proxy.ini` 中 `[logging]` 的 `level` 改为 `2`，重启 Gemini App 后查看 `%LocalAppData%\Google\Gemini\logs\gemini-proxy.log`，即可看到所有转发连接和 QUIC 拦截记录。
3. **杀毒软件误报？**
   - 由于采用 DLL 侧载 + API Hook 机制，部分安全软件可能误报。所有 Release 产物均由本仓库 [GitHub Actions](https://github.com/hayde0096/gemini-app-proxy-windowsver/actions) 公开透明构建，并附带 `SHA256SUMS.txt` 校验，也可自行从源码编译。

---

## 致谢 / Acknowledgements

- Inspired by [yuaotian/antigravity-proxy](https://github.com/yuaotian/antigravity-proxy)
- API Hooking powered by [TsudaKageyu/minhook](https://github.com/TsudaKageyu/minhook) (BSD-2-Clause)

## License

[MIT License](LICENSE)
