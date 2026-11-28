# zt

[![CI & Release](https://github.com/ArakawaHenri/zt/actions/workflows/ci.yml/badge.svg)](https://github.com/ArakawaHenri/zt/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ArakawaHenri/zt)](https://github.com/ArakawaHenri/zt/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[English](README.md) | 中文

**zt** 将三款国内企业零信任 VPN 客户端——**奇安信 TrustAgent**、**深信服 aTrust**、**深信服 EasyConnect**——封装在隔离的 Linux 容器中，支持 **macOS**、**Linux** 与 **Windows**（`arm64` / `amd64` 双架构）。

每个客户端提供一个基于 KasmVNC 的浏览器桌面和一条直通 VPN 隧道的多路复用 SOCKS5 代理端口（由容器内原生 `GuestMux` 直接承接 TCP `CONNECT` 与单播 UDP `UDP ASSOCIATE`，无需容器内无认证代理常驻端口），彻底隔离厂商后台常驻服务、全局路由劫持、DNS 篡改与系统根证书污染。

- **零依赖单文件分发**：除 Python 3 解释器外零第三方依赖、无需 `git`，单文件 `zipapp`（macOS / Linux 为 `zt`，Windows 为 `zt.pyz`）。
- **极简命令封装**：仅暴露 `up`、`down`、`status`、`doctor`、`purge`、`accept`、`password`、`use`、`update`。
- **默认本机免密**：默认仅监听 `127.0.0.1` 且无需密码，开箱即用；按需切换 `zt accept lan`（宿主机源 IP 过滤的局域网模式）或 `zt accept all`（`0.0.0.0` 全网监听，必填 6–128 位密码并启用单源 IP 限流），并可随时通过 `zt password [--clear]` 设密或清密。
- **重建容器不丢登录态与设备指纹**：VPN 登录凭据、Cookie、确定性设备身份（`/etc/machine-id`、合成只读 SMBIOS/DMI、持久 MAC）与自签桌面 TLS 证书保存在独立数据卷（`zt-state-<client>`）与宿主机私有状态中，执行 `zt down`、升级镜像、切换 `zt accept` 或修改密码重建容器时自动保留。
- **先验后用**：每个新构建镜像必须先通过双启动有状态实机校验才晋升启用，全面覆盖安全边界、跨重建持久化与对抗性网络不变量（iptables 篡改自愈、VPN 接管默认路由下的回程策略路由、`route_localnet=1` 回环隔离、SOCKS5 SSRF 拦截、最小权限与资源上限、ELF/动态库完整性、X11 窗口渲染等）。

## 快速开始

### 环境要求

- **容器引擎**：[Apple Container](https://github.com/apple/container)（`container`，macOS Apple Silicon）或 Docker / Podman（`docker`，macOS / Linux / Windows）。
- **Python**：3.9 及以上（仅使用标准库）。
- **目标架构**：自动识别 `linux/arm64` 或 `linux/amd64`（可通过 `ZT_ARCH=arm64|amd64` 覆盖）。

### 安装

**macOS & Linux**

```sh
curl -fsSL https://raw.githubusercontent.com/ArakawaHenri/zt/master/install.sh | sh
```

安装脚本会自动识别系统与架构（`arm64` / `amd64`）、校验 Python 3.9+、拉取最新 **stable** Release、核对 `SHA256SUMS`，并安装到 `~/.local/bin/zt`（可用 `ZT_INSTALL_DIR` 指定目录或 `ZT_VERSION=v1.0.0` 指定版本）。

**Windows（PowerShell）**

```powershell
irm https://raw.githubusercontent.com/ArakawaHenri/zt/master/install.ps1 | iex
```

安装脚本会自动识别架构（`amd64` / `arm64`）、检测本机 Python 3.9+（缺失则报错并提示安装方式）、核对 `SHA256SUMS`、将 `zt.pyz` 与 `zt.cmd` 安装到 `%LOCALAPPDATA%\zt\bin` 并加入用户 `PATH`，安装完成后在 PowerShell 与 CMD 中均可直接运行 `zt`。

**从源码构建**

```sh
git clone https://github.com/ArakawaHenri/zt.git
cd zt
make && PREFIX=~/.local make install   # Windows 可执行 `python tools/mkzt.py -o zt.pyz`
```

### 启动与使用

```sh
zt up atrust          # 首次运行自动下载官方包（SHA256 校验）、构建、实机校验并启动
zt status             # 查看实时 VPN 状态、桌面地址、SOCKS5 代理端口及待处理 SSO 链接
```

浏览器打开 `zt status` 显示的 HTTPS 桌面地址登录 VPN，之后即可通过对应的 SOCKS5 端口访问内网：

```sh
ALL_PROXY=socks5h://127.0.0.1:16912 curl https://internal.corp.example
```

## 支持的客户端与端口

| 客户端 | VPN 产品与版本 | Web 桌面（默认） | SOCKS5 代理（默认） |
|---|---|---|---|
| `trustagent` | 奇安信 TrustAgent 3.5.1.1003.62 | `https://127.0.0.1:16901` | `127.0.0.1:16902` |
| `atrust` | 深信服 aTrust 2.5.16.20 | `https://127.0.0.1:16911` | `127.0.0.1:16912` |
| `easyconnect` | 深信服 EasyConnect 7.6.7 | `https://127.0.0.1:16921` | `127.0.0.1:16922` |

## 命令一览

```sh
zt up [all | client]            按需构建与校验镜像，启动容器和 SOCKS5 桥接
zt down [all | client]          停止桥接与容器（保留登录态）
zt status [all | client]        查看容器引擎、访问模式、架构、实时 VPN 状态、桌面地址与 SOCKS5 端口
zt doctor                       全面体检容器引擎、内核/平台前置条件、配置、镜像、端口、桌面与桥接状态
zt purge [all | client]         停止并删除容器、登录态数据卷、已构建镜像与宿主机缓存
zt accept [local|lan|all]       设置允许访问范围（默认 local）；无参数时显示当前模式
zt password [--clear]           设置、修改或清除密码（6–128 位；accept all 模式下必填）
zt use [container|docker|auto]  选择容器引擎（默认 auto）；无参数时显示当前引擎
zt update [--check]             在线自更新到最新稳定版 GitHub Release
```

## 访问范围与认证（`zt accept`）

`zt accept` 对 **Web 桌面（`169x1`）与 SOCKS5 代理（`169x2`）同步生效**，且容器桌面始终只发布在宿主机回环地址 `127.0.0.1`：

| 模式 | 监听地址 | 密码 | 说明 |
|---|---|---|---|
| `local` *（默认）* | `127.0.0.1` | 可选 | 仅本机访问，未设密码时开箱免密。 |
| `lan` | `0.0.0.0` | 可选 | 容器桌面仍只绑定本机回环（`127.0.0.1:169x6`），由宿主机桥接统一对外监听 `0.0.0.0:169x1` 和 `0.0.0.0:169x2` 并按源 IP 过滤，仅放行私网/局域网/Tailscale 网段（`127/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`100.64/10`、`::1`、`fc00::/7`、`fe80::/10`）。切换 Wi-Fi / DHCP 无需重建容器。 |
| `all` | `0.0.0.0` | 必填（6–128 位） | 容器桌面仍仅绑定本机回环（`127.0.0.1:169x6`）并保持最严格的 `gateway` 防火墙模式；由宿主机桥接统一对外代理 `0.0.0.0:169x1` 和 `0.0.0.0:169x2`，强制使用 `kasm_user` 与 `zt password` 密码（HTTPS Basic Auth + SOCKS5 RFC 1929），并附带单源 IP 连接与认证失败限流。 |

```sh
# 仅本机（默认）
ALL_PROXY=socks5h://127.0.0.1:16912 curl https://internal.corp.example

# 局域网（执行 `zt accept lan && zt up` 后）
ALL_PROXY=socks5h://<局域网宿主机IP>:16912 curl https://internal.corp.example

# 启用密码认证（执行 `zt password && zt up` 或 `zt accept all && zt up` 后）
ALL_PROXY=socks5h://kasm_user:<password>@<host>:16912 curl https://internal.corp.example
```

修改 `zt accept` 或 `zt password` 后执行 `zt up`，运行中的容器与桥接会自动收敛，**且不会丢失已登录的 VPN 会话**。

## 浏览器 SSO 登录与实时状态

- **零延迟 `zt status`**：宿主机桥接会周期性持久化 VPN 健康快照（`connected`、`disconnected`、`dns-err`、`daemon-down`、`sso-pending`），并在客户端状态卷使用率达到 85% 时主动告警。
- **宿主机浏览器安全 SSO（`xdg-open`）**：任意 VPN 客户端拉起外部 SSO 登录链接时，`zt` 会校验 `http(s)://` 协议、将链接写入 KasmVNC 剪贴板并弹出桌面通知，同时在 `zt status` 展示该链接，并按需开启 5 分钟（`300s`）仅限本机回环（`127.0.0.1`）的白名单回调端口转发（`trustagent: 39301`、`atrust: 54631`、`easyconnect: 54530`，也可从 Openbox 右键菜单手动开启）。用户可安全地在宿主机浏览器完成 SSO，且 `zt` 绝不自动拉起宿主机浏览器或暴露容器内部端口。

## 登录态与设备指纹持久化

每个客户端挂载独立数据卷 `zt-state-<client>` 至容器内 `/var/lib/zt-state`。每次容器启动时，`zt-init` 与 `zt-identity` 在移交 `systemd` 前自动恢复：

- 独立且持久的 `/etc/machine-id`（与 `/var/lib/dbus/machine-id` 保持一致），配合固定主机名 `zt-<client>`；
- 基于 `/etc/machine-id` 确定性合成的只读 SMBIOS 3.0 表与 sysfs DMI 字段（`/sys/devices/virtual/dmi/id/*`），既隔离宿主机真实 DMI 信息，又确保零信任设备指纹跨重建稳定不变；
- 持久化的本地管理 MAC 地址（`02:7a:74:xx:xx:xx`，以 `0600` 权限保存在宿主机状态目录；在 Docker、rootful Podman 与 Apple Container 生效，rootless Podman 自动跳过）；
- KasmVNC 自签 TLS 证书（重建基础镜像后浏览器不必重新确认证书）；
- 各客户端在 `state-paths.conf` 中声明的状态目录（含系统级数据库、设备证书、EasyConnect 直接挂卷的 `conf` 目录、用户 `~/.config`、`~/.local`、`~/.pki` 等），同时每次启动自动从镜像刷新 Openbox 菜单配置。

如需彻底重置（清除容器、登录态数据卷、镜像与全部下载/构建缓存），执行 `zt purge <client>` 或 `zt purge all`。

## 配置与文件位置

| 项目 | macOS / Linux | Windows | 环境变量覆盖 |
|---|---|---|---|
| 配置文件（`KEY=VALUE`） | `~/.config/zt/config`（`0600`） | `%APPDATA%\zt\config` | `ZT_CONFIG` |
| SHA256 安装包与构建缓存 | `~/.cache/zt` | `%LOCALAPPDATA%\zt\cache` | `ZT_CACHE` |
| 桥接 PID、日志、健康快照与身份 | `~/.local/state/zt`（`0700`） | `%LOCALAPPDATA%\zt\state` | `ZT_STATE` |

可用配置项（均可通过 `ZT_<KEY>` 环境变量单次覆盖）：

- `ACCEPT`：`local`（默认）、`lan` 或 `all`。
- `VNC_PW`：6–128 位可打印 ASCII 密码，通过 `zt password` / `zt password --clear` 管理（只要设置即在所有模式下生效，`ACCEPT=all` 时必填）。
- `TRUSTAGENT_BYPASS_ROUTES`：可选，逗号分隔的 CIDR 列表，配置后 TrustAgent 策略路由表（`100 bypass`）会将对应网段走容器默认网关而非 VPN 隧道。
- `CAPS`：容器能力配置——Docker 引擎默认 `least`（先 `--cap-drop ALL` 再按最小白名单加权，配合 `/dev/net/tun` 只给 `:rw` 与 `--pids-limit 1024`），Apple Container 独立微虚拟机默认 `all`；可手动指定 `least` 或 `all`。
- `ZT_ENGINE`：临时指定容器引擎（`container` 或 `docker`）。
- `ZT_ARCH`：临时指定目标镜像架构（`arm64` 或 `amd64`）。

## 官方软件源与供应链

所有镜像均在用户本机基于自包含的 `overlay/` 与宿主机缓存构建，每次构建都会对缓存安装包重新核对锁定的 SHA256 摘要（支持下载进度、自动重试以及硬链接零拷贝去重）。本仓库不分发任何商业 VPN 二进制文件；GitHub Release 构建流程均锁定 Action Commit SHA 并附带构建溯源证明（Build Provenance Attestation）。

| 组件 | `arm64` 来源 | `amd64` 来源 |
|---|---|---|
| 基础系统 | 官方 `ubuntu:24.04` | 官方 `ubuntu:24.04` |
| Web 桌面 | 官方 `kasmtech/KasmVNC` 1.5.2 arm64 `.deb` | 官方 `kasmtech/KasmVNC` 1.5.2 amd64 `.deb` |
| TrustAgent 兼容库 | 官方 `ports.ubuntu.com` `libssl1.1` arm64 `.deb` | 官方 `security.ubuntu.com` `libssl1.1` + `libevent-2.1-6` amd64 `.deb` |
| 深信服 aTrust 2.5.16.20 | 官方 `atrustcdn.sangfor.com` UOS arm64 `.deb` | 官方 `atrustcdn.sangfor.com` UOS amd64 `.deb` |
| 深信服 EasyConnect 7.6.7 | 官方 `download.sangfor.com.cn` UOS arm64 压缩包 + 官方 Electron 1.8.8 arm64 | 官方 `download.sangfor.com.cn` x64 `.deb` + 官方 Electron 1.8.8 x64 |
| 奇安信 TrustAgent 3.5.1.1003.62 | SHA256 锁定镜像 *（奇安信暂无匿名公网 CDN）* | SHA256 锁定镜像 *（同左）* |

## 安全模型

每次构建新镜像后、`zt up` 将其从 `-unverified` 暂存标签晋升启用前（亦可在 CI 中通过 `python3 -m zt.verify` 手动运行），会在回环地址上执行双启动有状态实机校验：

- **`auth` 与 `persistence`**：验证回环桌面认证策略（未设密码直连 `HTTP 200`；设密后无认证 `401`、带密码 `200`），并挂载同一状态卷重建容器进行二次启动，确认 `/etc/machine-id`、D-Bus ID、SMBIOS/DMI 序列号与 UUID、确定性 MAC 及 KasmVNC TLS 证书均零漂移。
- **网络隔离与自愈（`policy`、`routing`、`loopback_isolation`、`tunnel`、`reachability`）**：统一的 `zt-iptables` 后端分发器（自动探测 `nft`/`legacy`，消除分裂脑）在 `INPUT`/`OUTPUT` 第 1 条挂载 `ZT-INPUT`/`ZT-OUTPUT`（IPv4 & IPv6），对厂商 `iptables` 及全表 `iptables-restore` 篡改原子自愈；实测在 `route_localnet=1` 下非 `lo` 访问 `127.0.0.0/8` 与 `::1/128` 仍被 `zt: loopback guard` 拦截；实测模拟 VPN 接管默认路由时 KasmVNC `:6901` 经由 `table 90` + `CONNMARK` + `$wan.rp_filter=2` 保持回程可达；双栈两阶段 `TCPMSS` 钳制（`1340`/`1220`）；并通过两轮撤回/恢复对照实验验证同网段容器与隧道入站隔离。
- **多路复用 SOCKS5 隔离（`mux_e2e`）**：容器内 `GuestMux` 以 `nobody` 身份直接运行在单条 `exec` stdio 管道上，彻底移除 `microsocks` 与无认证 `127.0.0.1:1080` 监听端口；对域名解析后结果实施回环与未指定地址 SSRF 拦截（免疫 DNS Rebinding，返回 RFC 1928 `REP=0x02`）；严格限定 `CALLBACK_OPEN` 静态白名单端口；内置 IPv4 优先 Happy Eyeballs（配合 `/etc/gai.conf`）、15 秒心跳与宿主机休眠唤醒自动重建及被动空闲保活。
- **权限、身份与资源加固（`privilege`、`limits`、`identity`、`setuid`、`ownership`、`programs`）**：基础镜像不装 `sudo`；所有 GUI 均以 `kasm-user` 零能力（`CapEff=0`）且 `NoNewPrivs=1` 运行（深信服守护进程与桌面 UI 拆分为独立 systemd unit）；全部 systemd unit 强制 `NoNewPrivileges=true`、`RLIMIT_NOFILE <= 65536` 与 `RLIMIT_CORE=0`；厂商守护进程通过 `CapabilityBoundingSet` 剥离 `CAP_SYS_ADMIN`、`CAP_SYS_CHROOT`、`CAP_SYS_MODULE`、`CAP_SYS_RAWIO`、`CAP_SYS_PTRACE`；Docker 下保持 `/proc/sys/net/core` 只读；校验只读 SMBIOS/DMI 身份挂载、全部 root 执行路径与符号链接链及 `kasm-user` 文件属主边界。
- **运行时完整性（`units`、`ui`、`libraries`、`timezone`、`log`）**：校验服务活跃、X11 实际渲染出业务窗口、原生 ELF `e_machine` 与 `ldd` 依赖无缺失、宿主机时区同步、TrustAgent `get_mid` 设备 UUID 返回非空以及无致命报错日志。

### 信任边界与架构限制

- **`accept local`**：仅监听 `127.0.0.1` 免密访问；在浏览器信任自签 HTTPS 证书后，建议避免在同一浏览器配置中打开不可信网页。
- **`accept lan`**：同一私网 / 局域网 / Tailscale 网段内设备可免密访问桌面与 SOCKS5，仅适用于可信家庭/办公局域网或加密私网，请勿在公共 Wi-Fi 下开启。
- **`accept all`**：对 Web 桌面与 SOCKS5 强制要求 6–128 位密码并启用单源 IP 限流，但 SOCKS5 RFC 1929 协议本身不带 TLS 加密；跨不可信网络建议配合 Tailscale / WireGuard 等加密隧道使用。
- **Linux rootful Docker 隔离边界**：在原生 Linux 下使用 rootful Docker 时容器共享宿主机内核（命名空间边界，而非 macOS / Windows 下的虚拟机边界）。`zt` 对 Docker 默认启用 `CAPS=least`（`--cap-drop ALL` + 最小能力白名单，剥离 `SYS_MODULE`、`SYS_RAWIO`、`SYS_PTRACE`、`BPF`、`DAC_READ_SEARCH`、`MKNOD` 等高危能力）、`/dev/net/tun` 仅赋予 `:rw`、保持 `/proc/sys/net/core` 只读（仅对 `/proc/sys/net/ipv4/conf` 局部可写重挂）、强制 `--pids-limit 1024` / `--shm-size 256m` / `nofile=1024:65536` / `core=0`、收紧 `/run` tmpfs，且仅在检测到 SELinux 或 AppArmor 时按需放宽对应 MAC 约束（`label=disable` / `apparmor=unconfined`）以允许 `systemd` 与挂载运行。在 Linux 上如需额外的用户命名空间隔离层，优先推荐使用 rootless Docker 或 rootless Podman。
- **SOCKS5 UDP 与吞吐边界**：SOCKS5 支持 TCP `CONNECT` 与单播 `UDP ASSOCIATE`（适配 Clash / sing-box / Surge TUN 分流、QUIC、内网 DNS、UDP RPC 等），严格绑定源 IP 与 TCP 控制连接生命周期，具备解析后回环 SSRF 防护、单流信用窗口流控（`WINDOW_UPDATE`）、连接数上限与有界 drop-on-full UDP 队列，确保单条停读连接或 UDP 突发绝不拖慢其他流或新握手。组播/广播发现与外部主动入站 P2P UDP 不经过 SOCKS5 与容器防火墙，这类应用请直接使用 KasmVNC 浏览器桌面。所有代理流量复用单条 stdio 管道，适合交互式办公 / SSH / Git / 网页场景，并非面向高吞吐大文件传输设计。

## 开发与测试

```sh
make          # 构建可复现单文件 ./zt
make zt.pyz   # 构建 Windows 版 ./zt.pyz（与 ./zt 逐字节一致）
make lint     # 对 install.sh 及全部 overlay shell 脚本运行 shellcheck
make test     # 构建 ./zt 并运行 shellcheck 与 python3 -W error 单元测试套件
make clean    # 清理 ./zt、./zt.pyz 与 Python 字节码缓存
```

## 许可证

[MIT](LICENSE)
