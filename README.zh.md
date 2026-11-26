# zt

[![CI & Release](https://github.com/ArakawaHenri/zt/actions/workflows/ci.yml/badge.svg)](https://github.com/ArakawaHenri/zt/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ArakawaHenri/zt)](https://github.com/ArakawaHenri/zt/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[English](README.md) | 中文

**zt** 将三款国内企业零信任 VPN 客户端——**奇安信 TrustAgent**、**深信服 aTrust**、**深信服 EasyConnect**——封装在隔离的 Linux 容器中，支持 **macOS**、**Linux** 与 **Windows**（`arm64` / `amd64` 双架构）。

每个客户端提供一个基于 KasmVNC 的浏览器桌面和一条直通 VPN 隧道的多路复用 SOCKS5 代理端口，彻底隔离厂商后台常驻服务、全局路由劫持、DNS 篡改与系统根证书污染。

- **零依赖单文件分发**：除 Python 3 解释器外零第三方依赖、无需 `git`，单文件 `zipapp`（macOS / Linux 为 `zt`，Windows 为 `zt.pyz`）。
- **极简 7 命令封装**：仅暴露 `up`、`down`、`status`、`doctor`、`purge`、`accept`、`password`。
- **默认本机免密**：默认仅监听 `127.0.0.1` 且无需密码，开箱即用；按需切换 `zt accept lan`（宿主机源 IP 过滤的免密局域网模式）或 `zt accept all`（`0.0.0.0` 全网监听，桌面与 SOCKS5 共用同一套密码认证）。
- **重建容器不丢登录态**：VPN 登录凭据、Cookie、设备指纹（`/etc/machine-id`）与自签桌面 TLS 证书保存在独立数据卷（`zt-state-<client>`），执行 `zt down`、升级镜像、切换 `zt accept` 或修改密码重建容器时自动保留。
- **先验后用**：每个新构建镜像首次启动前自动执行 13 项实机安全与运行不变量校验（iptables 隔离正反对照实验、最小权限与 `NoNewPrivileges`、ELF 架构与动态库完整性、X11 窗口渲染等）。

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
zt up atrust          # 首次运行自动下载官方包（SHA256 校验）、构建、13 项实机校验并启动
zt status             # 查看桌面地址与 SOCKS5 代理端口
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
zt up [all | client]        按需构建与校验镜像，启动容器和 SOCKS5 桥接
zt down [all | client]      停止桥接与容器（保留登录态）
zt status [all | client]    查看访问模式、目标架构、容器状态、桌面地址与 SOCKS5 端口
zt doctor                   全面体检容器引擎、架构、配置、镜像、端口、桌面与桥接状态
zt purge [all | client]     停止并删除容器、登录态数据卷、已构建镜像与宿主机缓存
zt accept [local|lan|all]   设置允许访问范围（默认 local）；无参数时显示当前模式
zt password                 设置或修改密码（accept all 模式下必需）
```

## 访问范围与认证（`zt accept`）

`zt accept` 对 **Web 桌面（`169x1`）与 SOCKS5 代理（`169x2`）同步生效**：

| 模式 | 监听地址 | 密码 | 说明 |
|---|---|---|---|
| `local` *（默认）* | `127.0.0.1` | 免密 | 仅本机访问，打开浏览器桌面和使用 SOCKS5 均零阻力。 |
| `lan` | `0.0.0.0` | 免密 | 容器桌面仍只绑定本机回环（`127.0.0.1:169x6`），由宿主机桥接统一对外监听 `0.0.0.0:169x1` 和 `0.0.0.0:169x2` 并按源 IP 过滤，仅放行私网/局域网/Tailscale 网段（`127/8`、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`、`100.64/10`、`::1`、`fc00::/7`、`fe80::/10`）。切换 Wi-Fi / DHCP 无需重建容器。 |
| `all` | `0.0.0.0` | 必填（6–8 位） | Web 桌面启用 HTTPS Basic Auth、SOCKS5 启用 RFC 1929 用户名密码认证，统一使用 `kasm_user` 与 `zt password` 设置的密码。 |

```sh
# 仅本机（默认）
ALL_PROXY=socks5h://127.0.0.1:16912 curl https://internal.corp.example

# 局域网免密（执行 `zt accept lan && zt up` 后）
ALL_PROXY=socks5h://<局域网宿主机IP>:16912 curl https://internal.corp.example

# 全网密码认证（执行 `zt accept all && zt up` 后）
ALL_PROXY=socks5h://kasm_user:<password>@<host>:16912 curl https://internal.corp.example
```

修改 `zt accept` 或 `zt password` 后执行 `zt up`，运行中的容器与桥接会自动收敛，**且不会丢失已登录的 VPN 会话**。

## 登录态持久化

每个客户端挂载独立数据卷 `zt-state-<client>` 至容器内 `/var/lib/zt-state`。每次容器启动时，`zt-init` 在移交 `systemd` 前自动恢复：

- 独立且持久的 `/etc/machine-id`（配合固定主机名 `zt-<client>`，确保零信任设备信任关系不失效）；
- KasmVNC 自签 TLS 证书（重建基础镜像后浏览器不必重新确认证书）；
- 各客户端在 `state-paths.conf` 中声明的状态目录（含系统级数据库、设备证书、用户 `~/.config`、`~/.local`、`~/.pki` 等），同时每次启动自动从镜像刷新 Openbox 菜单配置。

如需彻底重置（清除容器、登录态数据卷、镜像与全部下载/构建缓存），执行 `zt purge <client>` 或 `zt purge all`。

## 配置与文件位置

| 项目 | macOS / Linux | Windows | 环境变量覆盖 |
|---|---|---|---|
| 配置文件（`KEY=VALUE`） | `~/.config/zt/config`（`0600`） | `%APPDATA%\zt\config` | `ZT_CONFIG` |
| SHA256 安装包与构建缓存 | `~/.cache/zt` | `%LOCALAPPDATA%\zt\cache` | `ZT_CACHE` |
| 桥接 PID 与日志 | `~/.local/state/zt` | `%LOCALAPPDATA%\zt\state` | `ZT_STATE` |

可用配置项（均可通过 `ZT_<KEY>` 环境变量单次覆盖）：

- `ACCEPT`：`local`（默认）、`lan` 或 `all`。
- `VNC_PW`：6–8 位密码，由 `zt password` 写入（`ACCEPT=all` 时生效）。
- `TRUSTAGENT_BYPASS_ROUTES`：可选，逗号分隔的 CIDR 列表，配置后 TrustAgent 策略路由表（`100 bypass`）会将对应网段走容器默认网关而非 VPN 隧道。
- `CAPS`：容器能力配置——`all`（默认）或 `least`（仅 `NET_ADMIN` + `SYS_ADMIN`）。
- `ZT_ENGINE`：临时指定容器引擎（`container` 或 `docker`）。
- `ZT_ARCH`：临时指定目标镜像架构（`arm64` 或 `amd64`）。

## 官方软件源与构建架构

所有镜像均在用户本机基于自包含的 `overlay/` 与宿主机缓存的 SHA256 校验包构建（支持下载进度、自动重试以及硬链接零拷贝去重）。本仓库不分发任何商业 VPN 二进制文件。

| 组件 | `arm64` 来源 | `amd64` 来源 |
|---|---|---|
| 基础系统 | 官方 `ubuntu:24.04` | 官方 `ubuntu:24.04` |
| Web 桌面 | 官方 `kasmtech/KasmVNC` 1.5.2 arm64 `.deb` | 官方 `kasmtech/KasmVNC` 1.5.2 amd64 `.deb` |
| TrustAgent 兼容库 | 官方 `ports.ubuntu.com` `libssl1.1` arm64 `.deb` | 官方 `security.ubuntu.com` `libssl1.1` + `libevent-2.1-6` amd64 `.deb` |
| 深信服 aTrust 2.5.16.20 | 官方 `atrustcdn.sangfor.com` UOS arm64 `.deb` | 官方 `atrustcdn.sangfor.com` UOS amd64 `.deb` |
| 深信服 EasyConnect 7.6.7 | 官方 `download.sangfor.com.cn` UOS arm64 压缩包 + 官方 Electron 1.8.8 arm64 | 官方 `download.sangfor.com.cn` x64 `.deb` + 官方 Electron 1.8.8 x64 |
| 奇安信 TrustAgent 3.5.1.1003.62 | SHA256 锁定镜像 *（奇安信暂无匿名公网 CDN）* | SHA256 锁定镜像 *（同左）* |

## 安全模型

每次构建新镜像后、`zt up` 正式启用前，会先在回环地址上启动校验容器跑完 13 项实机检查：

- **`auth`**：`local`/`lan` 模式下确认直连返回 `HTTP 200`；`all` 模式下确认无密码返回 `401`、带密码返回 `200`。
- **网络隔离（`policy`、`tunnel`、`reachability`）**：在 `INPUT` 第 1 条挂载独立 `ZT-INPUT` 链（IPv4 & IPv6），丢弃来自同网段其他容器及 VPN 隧道接口（`tun+`、`utun+`、`vnic+`）的主动 TCP/UDP 入站连接，并通过两轮撤回/恢复对照实测确认。
- **权限隔离（`privilege`、`setuid`、`ownership`、`programs`）**：基础镜像不装 `sudo`；所有 GUI 均以 `kasm-user` 零能力（`CapEff=0`）且 `NoNewPrivs=1` 运行；全部 systemd unit 强制 `NoNewPrivileges=true`；审计所有 root 执行路径与符号链接链；校验 `kasm-user` 在声明目录外不拥有任何系统文件。
- **运行时完整性（`units`、`ui`、`libraries`、`timezone`、`log`）**：校验服务活跃、X11 实际渲染出业务窗口、原生 ELF `e_machine` 与 `ldd` 依赖无缺失、宿主机时区同步以及无致命报错日志。

### 信任边界说明

- **`accept local`**：仅监听 `127.0.0.1` 免密访问；在浏览器信任自签 HTTPS 证书后，建议避免在同一浏览器配置中打开不可信网页。
- **`accept lan`**：同一私网 / 局域网 / Tailscale 网段内设备可免密访问桌面与 SOCKS5，仅适用于可信家庭/办公局域网或加密私网，请勿在公共 Wi-Fi 下开启。
- **`accept all`**：SOCKS5 RFC 1929 提供账号密码认证，但 SOCKS5 协议本身不带 TLS 加密；跨不可信网络建议配合 Tailscale / WireGuard 等加密隧道使用。

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
