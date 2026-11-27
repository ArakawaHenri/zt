# zt

[![CI & Release](https://github.com/ArakawaHenri/zt/actions/workflows/ci.yml/badge.svg)](https://github.com/ArakawaHenri/zt/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ArakawaHenri/zt)](https://github.com/ArakawaHenri/zt/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

English | [中文](README.zh.md)

**zt** runs enterprise zero-trust VPN clients — **Qianxin TrustAgent**, **Sangfor aTrust**, and **Sangfor EasyConnect** — inside isolated Linux containers on **macOS**, **Linux**, and **Windows** (`arm64` & `amd64`).

Each client gives you a browser-based KasmVNC desktop and a multiplexed SOCKS5 proxy (TCP `CONNECT` + unicast UDP `UDP ASSOCIATE`) into its VPN tunnel, keeping proprietary VPN daemons, kernel routes, DNS hooks, and root certificates off your host OS.

- **Single-file, zero-dependency CLI**: one self-contained Python `zipapp` (`zt` on macOS/Linux, `zt.pyz` on Windows; Python stdlib only, no `git` required).
- **7 clean commands**: `up`, `down`, `status`, `doctor`, `purge`, `accept`, `password`.
- **Passwordless local default**: binds `127.0.0.1` with no password out of the box; switch to `zt accept lan` (source-IP filtered LAN, no password) or `zt accept all` (`0.0.0.0` with unified password auth on both desktop & SOCKS5).
- **Persistent login state**: VPN tokens, cookies, device identity (`/etc/machine-id`), and self-signed desktop TLS certs live in per-client engine volumes (`zt-state-<client>`), surviving `zt down`, image upgrades, and `zt accept` / `zt password` switches.
- **Verified before first use**: every freshly built image is automatically verified against 13 live security & runtime invariants (iptables peer/tunnel drop controls, privilege separation, `NoNewPrivileges`, ELF/library integrity, X11 UI rendering).

## Quick Start

### Requirements

- **Container engine**: [Apple Container](https://github.com/apple/container) (`container`, macOS Apple Silicon) or Docker / Podman (`docker`, macOS / Linux / Windows).
- **Python**: 3.9 or later (stdlib only).
- **Architecture**: auto-detected (`linux/arm64` or `linux/amd64`; override with `ZT_ARCH=arm64|amd64`).

### Install

**macOS & Linux**

```sh
curl -fsSL https://raw.githubusercontent.com/ArakawaHenri/zt/master/install.sh | sh
```

The installer detects your OS/CPU (`arm64` / `amd64`), verifies Python 3.9+, fetches the latest stable release, checks `SHA256SUMS`, and installs `zt` to `~/.local/bin/zt` (override with `ZT_INSTALL_DIR` or `ZT_VERSION=v1.0.0`).

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/ArakawaHenri/zt/master/install.ps1 | iex
```

The installer detects your architecture (`amd64` / `arm64`), checks for Python 3.9+ (prompting with install instructions if missing), verifies `SHA256SUMS`, installs `zt.pyz` + `zt.cmd` to `%LOCALAPPDATA%\zt\bin`, and adds it to your user `PATH` so `zt` works immediately in both PowerShell and Command Prompt.

**Build from source**

```sh
git clone https://github.com/ArakawaHenri/zt.git
cd zt
make && PREFIX=~/.local make install   # or `python tools/mkzt.py -o zt.pyz` on Windows
```

### Run

```sh
zt up atrust          # first run downloads official installer (SHA256-verified), builds, verifies, and starts
zt status             # check desktop URL and SOCKS5 port
```

Open the web desktop URL shown by `zt status`, sign in to your VPN, then route traffic through its SOCKS5 proxy:

```sh
ALL_PROXY=socks5h://127.0.0.1:16912 curl https://internal.corp.example
```

## Supported Clients & Ports

| Client | VPN Product | Web Desktop (default) | SOCKS5 (default) |
|---|---|---|---|
| `trustagent` | 奇安信 TrustAgent 3.5.1.1003.62 | `https://127.0.0.1:16901` | `127.0.0.1:16902` |
| `atrust` | 深信服 aTrust 2.5.16.20 | `https://127.0.0.1:16911` | `127.0.0.1:16912` |
| `easyconnect` | 深信服 EasyConnect 7.6.7 | `https://127.0.0.1:16921` | `127.0.0.1:16922` |

## Commands

```sh
zt up [all | client]        build & verify if needed, start clients and SOCKS5 bridges
zt down [all | client]      stop bridges and containers (keeps login state)
zt status [all | client]    show accept mode, platform, container state, desktop URLs, and SOCKS5
zt doctor                   check host engine, platform, settings, images, ports, desktops, and bridges
zt purge [all | client]     stop and delete containers, login state volumes, built images, and host cache
zt accept [local|lan|all]   set bind scope (default: local); omit argument to show current mode
zt password                 set or change the password (required for accept all)
```

## Access Modes (`zt accept`)

`zt accept` applies uniformly to **both** the web desktop (`169x1`) and SOCKS5 (`169x2`) ports:

| Mode | Bind | Password | Behavior |
|---|---|---|---|
| `local` *(default)* | `127.0.0.1` | None | Local machine only — open desktop and use SOCKS5 with zero friction. |
| `lan` | `0.0.0.0` | None | Containers stay bound to loopback (`127.0.0.1:169x6`); the host bridge exposes `0.0.0.0:169x1` & `0.0.0.0:169x2` and drops any peer outside private/LAN/Tailscale ranges (`127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `100.64/10`, `::1`, `fc00::/7`, `fe80::/10`). Survives Wi-Fi/DHCP changes without recreating containers. |
| `all` | `0.0.0.0` | Required (6–8 chars) | Enforces unified credentials (`kasm_user` + password from `zt password`) via HTTPS Basic Auth on desktops and RFC 1929 username/password auth on SOCKS5. |

```sh
# Local (default)
ALL_PROXY=socks5h://127.0.0.1:16912 curl https://internal.corp.example

# LAN (after `zt accept lan && zt up`)
ALL_PROXY=socks5h://<lan-host-ip>:16912 curl https://internal.corp.example

# Remote with auth (after `zt accept all && zt up`)
ALL_PROXY=socks5h://kasm_user:<password>@<host>:16912 curl https://internal.corp.example
```

Run `zt up` after changing `zt accept` or `zt password` to converge running containers and bridges automatically — **your VPN login state is preserved across container recreation**.

## Login State Persistence

Each client mounts a managed engine volume (`zt-state-<client>`) at `/var/lib/zt-state`. Before `systemd` boots, `zt-init` restores:

- A unique, persistent `/etc/machine-id` (combined with a stable container hostname `zt-<client>`).
- The client's self-signed KasmVNC TLS certificate.
- Each VPN client's declared state directories (`state-paths.conf`), including system databases, device trust stores, `~/.config`, `~/.local`, and `~/.pki`, while refreshing image-managed Openbox menus on every boot.

To wipe everything for a clean slate (containers, state volumes, built images, and cached downloads), run `zt purge <client>` or `zt purge all`.

## Settings & File Locations

| Item | macOS / Linux | Windows | Override Env |
|---|---|---|---|
| Config (`KEY=VALUE`) | `~/.config/zt/config` (`0600`) | `%APPDATA%\zt\config` | `ZT_CONFIG` |
| SHA256 blob & build cache | `~/.cache/zt` | `%LOCALAPPDATA%\zt\cache` | `ZT_CACHE` |
| Bridge PIDs & logs | `~/.local/state/zt` | `%LOCALAPPDATA%\zt\state` | `ZT_STATE` |

Settings (each overrideable per invocation via `ZT_<KEY>`):

- `ACCEPT`: `local` (default), `lan`, or `all`.
- `VNC_PW`: 6–8 character password set via `zt password` (used when `ACCEPT=all`).
- `TRUSTAGENT_BYPASS_ROUTES`: optional comma-separated CIDRs routed via the container's default gateway instead of the TrustAgent VPN tunnel (`table 100 bypass`).
- `CAPS`: root capability profile — defaults to `least` on Docker (`--cap-drop ALL` + explicit minimal allowlist, `:rw` `/dev/net/tun`, `--pids-limit 1024`) and `all` on Apple Container (per-container microVM); override with `least` or `all`.
- `ZT_ENGINE`: per-call engine override (`container` or `docker`).
- `ZT_ARCH`: per-call target container architecture override (`arm64` or `amd64`).

## Official Sources & Supply Chain

All images are built locally from the self-contained `overlay/` plus host-cached, SHA256-verified downloads (with live progress, automatic retries, and hardlink deduplication into build contexts). No proprietary VPN binaries are redistributed in this repository.

| Component | `arm64` Source | `amd64` Source |
|---|---|---|
| Base OS | Official `ubuntu:24.04` | Official `ubuntu:24.04` |
| Web Desktop | Official `kasmtech/KasmVNC` 1.5.2 arm64 `.deb` | Official `kasmtech/KasmVNC` 1.5.2 amd64 `.deb` |
| TrustAgent Compat Libs | Official `ports.ubuntu.com` `libssl1.1` arm64 `.deb` | Official `security.ubuntu.com` `libssl1.1` + `libevent-2.1-6` amd64 `.deb` |
| Sangfor aTrust 2.5.16.20 | Official `atrustcdn.sangfor.com` UOS arm64 `.deb` | Official `atrustcdn.sangfor.com` UOS amd64 `.deb` |
| Sangfor EasyConnect 7.6.7 | Official `download.sangfor.com.cn` UOS arm64 zip + official Electron 1.8.8 arm64 | Official `download.sangfor.com.cn` x64 `.deb` + official Electron 1.8.8 x64 |
| Qianxin TrustAgent 3.5.1.1003.62 | SHA256-pinned mirror *(Qianxin has no anonymous public CDN)* | SHA256-pinned mirror *(same)* |

## Security Model

Before any newly built image is started, `zt` boots it once on loopback and verifies 13 live invariants:

- **`auth`**: `HTTP 200` directly in `local`/`lan` modes; `401` unauthenticated and `200` authenticated in `all` mode.
- **Network isolation (`policy`, `tunnel`, `reachability`)**: dedicated `ZT-INPUT` chain at `INPUT` #1 (IPv4 & IPv6) drops unsolicited TCP and UDP from peer containers and VPN tunnels (`tun+`, `utun+`, `vnic+`), verified with two-round positive/negative controls.
- **Privilege separation (`privilege`, `setuid`, `ownership`, `programs`)**: no `sudo` in base; all desktop UIs run as `kasm-user` with `CapEff=0` and `NoNewPrivs=1`; every systemd unit enforces `NoNewPrivileges=true`; root-executed paths and symlink chains are audited; `kasm-user` owns nothing outside `/home/kasm-user` and declared vendor shared directories.
- **Runtime integrity (`units`, `ui`, `libraries`, `timezone`, `log`)**: active units, live X11 window checks, native ELF `e_machine` + `ldd` verification, host timezone sync, and clean boot logs.

### Trust Boundaries & Architectural Limits

- **`accept local`**: passwordless on `127.0.0.1` for frictionless local use; avoid untrusted web pages in the same browser profile after trusting the self-signed HTTPS certificate.
- **`accept lan`**: passwordless for any peer on the same private/LAN/Tailscale subnet; use only on trusted home/office networks or private overlays, not shared public Wi-Fi.
- **`accept all`**: SOCKS5 RFC 1929 enforces password authentication, but SOCKS5 itself is not TLS-encrypted; prefer `accept lan` or an encrypted overlay (Tailscale / WireGuard) over untrusted networks.
- **Linux rootful Docker**: on native Linux with rootful Docker, containers share the host kernel (namespace boundary rather than a VM like macOS Apple Container or Docker Desktop). `zt` defaults Docker to `CAPS=least` (`--cap-drop ALL` + explicit minimal allowlist, excluding `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE`, `BPF`, `DAC_READ_SEARCH`, `MKNOD`, etc.), mounts `/dev/net/tun` read-write only (`:rw`), enforces `--pids-limit 1024`, hardens `/run` tmpfs mounts, and only sets `label=disable` when SELinux is active. For an additional user-namespace boundary on Linux, prefer rootless Docker or rootless Podman.
- **SOCKS5 UDP & throughput**: SOCKS5 supports TCP `CONNECT` and unicast `UDP ASSOCIATE` (for TUN clients such as Clash/sing-box/Surge, QUIC, internal DNS, and UDP RPC), with peer-IP enforcement, TCP-control lifecycle binding, per-stream TCP credit flow control (`WINDOW_UPDATE`) so a stalled client never blocks other streams or new handshakes, and drop-on-full bounded UDP queues so UDP bursts never stall TCP streams. Multicast/broadcast discovery and unsolicited inbound P2P UDP do not traverse SOCKS5 or the container firewall — use the KasmVNC web desktop for such apps. Traffic shares a single multiplexed stdio pipe, optimized for interactive office/SSH/Git/web workloads rather than bulk high-throughput transfers.

## Development

```sh
make          # build deterministic single-file ./zt
make zt.pyz   # build Windows zipapp ./zt.pyz (identical bytes)
make lint     # run shellcheck on install.sh and all overlay shell scripts
make test     # build ./zt, run shellcheck + python3 -W error unit suite
make clean    # remove ./zt, ./zt.pyz, and bytecode caches
```

## License

[MIT](LICENSE)
