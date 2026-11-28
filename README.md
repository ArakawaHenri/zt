# zt

[![CI & Release](https://github.com/ArakawaHenri/zt/actions/workflows/ci.yml/badge.svg)](https://github.com/ArakawaHenri/zt/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ArakawaHenri/zt)](https://github.com/ArakawaHenri/zt/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

English | [中文](README.zh.md)

**zt** runs enterprise zero-trust VPN clients — **Qianxin TrustAgent**, **Sangfor aTrust**, and **Sangfor EasyConnect** — inside isolated Linux containers on **macOS**, **Linux**, and **Windows** (`arm64` & `amd64`).

Each client gives you a browser-based KasmVNC desktop and a multiplexed SOCKS5 proxy (TCP `CONNECT` + unicast UDP `UDP ASSOCIATE`, handled natively inside the guest without an unauthenticated local proxy daemon) into its VPN tunnel, keeping proprietary VPN daemons, kernel routes, DNS hooks, and root certificates off your host OS.

- **Single-file, zero-dependency CLI**: one self-contained Python `zipapp` (`zt` on macOS/Linux, `zt.pyz` on Windows; Python stdlib only, no `git` required).
- **Clean CLI**: `up`, `down`, `status`, `doctor`, `purge`, `accept`, `password`, `use`, `update`.
- **Passwordless local default**: binds `127.0.0.1` with no password out of the box; switch to `zt accept lan` (source-IP filtered LAN) or `zt accept all` (`0.0.0.0`, 6–128 char password required with per-IP rate limiting), and set or clear a password anytime with `zt password [--clear]`.
- **Persistent login state & device identity**: VPN tokens, cookies, deterministic device identity (`/etc/machine-id`, synthesized read-only SMBIOS/DMI, persistent MAC), and self-signed desktop TLS certs live in per-client engine volumes (`zt-state-<client>`) and private host state, surviving `zt down`, image upgrades, and `zt accept` / `zt password` switches.
- **Verified before first use**: every freshly built image is promoted only after passing a two-boot stateful verification suite covering live security, persistence, and adversarial network invariants (iptables tamper self-healing, active-tunnel asymmetric routing, `route_localnet=1` loopback isolation, SOCKS5 SSRF controls, privilege & resource limits, ELF/library integrity, X11 UI rendering).

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
zt status             # check live VPN state, desktop URL, SOCKS5 port, and any pending SSO URL
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
zt up [all | client]            build & verify if needed, start clients and SOCKS5 bridges
zt down [all | client]          stop bridges and containers (keeps login state)
zt status [all | client]        show engine, accept mode, platform, live VPN state, desktop URLs, and SOCKS5
zt doctor                       check host engine, kernel/platform prechecks, settings, images, ports, desktops, and bridges
zt purge [all | client]         stop and delete containers, login state volumes, built images, and host cache
zt accept [local|lan|all]       set bind scope (default: local); omit argument to show current mode
zt password [--clear]           set, change, or clear the password (6–128 chars; required for accept all)
zt use [container|docker|auto]  choose container engine (default: auto); omit to show active engine
zt update [--check]             self-update zt to the latest stable GitHub release
```

## Access Modes (`zt accept`)

`zt accept` applies uniformly to **both** the web desktop (`169x1`) and SOCKS5 (`169x2`) ports. Containers always publish KasmVNC on host loopback (`127.0.0.1`) only:

| Mode | Bind | Password | Behavior |
|---|---|---|---|
| `local` *(default)* | `127.0.0.1` | Optional | Local machine only — open desktop and use SOCKS5 with zero friction. |
| `lan` | `0.0.0.0` | Optional | Containers stay bound to loopback (`127.0.0.1:169x6`); the host bridge fronts `0.0.0.0:169x1` & `0.0.0.0:169x2` and drops any peer outside private/LAN/Tailscale ranges (`127/8`, `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `100.64/10`, `::1`, `fc00::/7`, `fe80::/10`). Survives Wi-Fi/DHCP changes without recreating containers. |
| `all` | `0.0.0.0` | Required (6–128 chars) | Containers stay bound to loopback (`127.0.0.1:169x6`) in strictest `gateway` firewall mode; the host bridge fronts `0.0.0.0:169x1` & `0.0.0.0:169x2` with unified credentials (`kasm_user` via HTTPS Basic Auth & SOCKS5 RFC 1929) plus per-source-IP connection and auth-failure rate limiting. |

```sh
# Local (default)
ALL_PROXY=socks5h://127.0.0.1:16912 curl https://internal.corp.example

# LAN (after `zt accept lan && zt up`)
ALL_PROXY=socks5h://<lan-host-ip>:16912 curl https://internal.corp.example

# With password (after `zt password && zt up`, or `zt accept all && zt up`)
ALL_PROXY=socks5h://kasm_user:<password>@<host>:16912 curl https://internal.corp.example
```

Run `zt up` after changing `zt accept` or `zt password` to converge running containers and bridges automatically — **your VPN login state is preserved across container recreation**.

## Browser SSO & Live Status

- **Zero-latency `zt status`**: the host bridge records passive VPN health snapshots (`connected`, `disconnected`, `dns-err`, `daemon-down`, `sso-pending`) and warns when a client's state volume reaches 85% capacity.
- **Safe host-browser SSO (`xdg-open`)**: when any VPN client opens an external SSO URL, `zt` validates `http(s)://`, copies the URL to the KasmVNC clipboard with a desktop notification, surfaces it in `zt status`, and opens an on-demand 5-minute (`300s`) loopback-only (`127.0.0.1`) callback forwarder for that client's static allowlisted port (`trustagent: 39301`, `atrust: 54631`, `easyconnect: 54530`, also triggerable from the Openbox menu). Your host browser completes SSO without `zt` ever auto-launching a browser or exposing container ports.

## Login State & Device Identity Persistence

Each client mounts a managed engine volume (`zt-state-<client>`) at `/var/lib/zt-state`. Before `systemd` boots, `zt-init` and `zt-identity` restore:

- A unique, persistent `/etc/machine-id` (synced with `/var/lib/dbus/machine-id`) and stable container hostname `zt-<client>`.
- Synthesized, read-only SMBIOS 3.0 tables and sysfs DMI fields (`/sys/devices/virtual/dmi/id/*`) derived deterministically from `/etc/machine-id`, preventing host DMI leakage while keeping zero-trust device fingerprints stable.
- A persistent locally-administered MAC address (`02:7a:74:xx:xx:xx`, stored `0600` in host state; applied on Docker, rootful Podman, and Apple Container, skipped on rootless Podman).
- The client's self-signed KasmVNC TLS certificate.
- Each VPN client's declared state directories (`state-paths.conf`), including system databases, device trust stores, EasyConnect `conf` (mounted directly on the state volume), `~/.config`, `~/.local`, and `~/.pki`, while refreshing image-managed Openbox menus on every boot.

To wipe everything for a clean slate (containers, state volumes, built images, and cached downloads), run `zt purge <client>` or `zt purge all`.

## Settings & File Locations

| Item | macOS / Linux | Windows | Override Env |
|---|---|---|---|
| Config (`KEY=VALUE`) | `~/.config/zt/config` (`0600`) | `%APPDATA%\zt\config` | `ZT_CONFIG` |
| SHA256 blob & build cache | `~/.cache/zt` | `%LOCALAPPDATA%\zt\cache` | `ZT_CACHE` |
| Bridge PIDs, logs, health & identity | `~/.local/state/zt` (`0700`) | `%LOCALAPPDATA%\zt\state` | `ZT_STATE` |

Settings (each overrideable per invocation via `ZT_<KEY>`):

- `ACCEPT`: `local` (default), `lan`, or `all`.
- `VNC_PW`: 6–128 printable ASCII character password managed by `zt password` / `zt password --clear` (enforced in all modes when set; required when `ACCEPT=all`).
- `TRUSTAGENT_BYPASS_ROUTES`: optional comma-separated CIDRs routed via the container's default gateway instead of the TrustAgent VPN tunnel (`table 100 bypass`).
- `CAPS`: root capability profile — defaults to `least` on Docker (`--cap-drop ALL` + explicit minimal allowlist, `:rw` `/dev/net/tun`, `--pids-limit 1024`) and `all` on Apple Container (per-container microVM); override with `least` or `all`.
- `ZT_ENGINE`: per-call engine override (`container` or `docker`).
- `ZT_ARCH`: per-call target container architecture override (`arm64` or `amd64`).

## Official Sources & Supply Chain

All images are built locally from the self-contained `overlay/` plus host-cached downloads whose pinned SHA-256 digests are re-verified on every build (with live progress, automatic retries, and hardlink deduplication into build contexts). No proprietary VPN binaries are redistributed in this repository; GitHub Releases are built with pinned workflow actions and build provenance attestations.

| Component | `arm64` Source | `amd64` Source |
|---|---|---|
| Base OS | Official `ubuntu:24.04` | Official `ubuntu:24.04` |
| Web Desktop | Official `kasmtech/KasmVNC` 1.5.2 arm64 `.deb` | Official `kasmtech/KasmVNC` 1.5.2 amd64 `.deb` |
| TrustAgent Compat Libs | Official `ports.ubuntu.com` `libssl1.1` arm64 `.deb` | Official `security.ubuntu.com` `libssl1.1` + `libevent-2.1-6` amd64 `.deb` |
| Sangfor aTrust 2.5.16.20 | Official `atrustcdn.sangfor.com` UOS arm64 `.deb` | Official `atrustcdn.sangfor.com` UOS amd64 `.deb` |
| Sangfor EasyConnect 7.6.7 | Official `download.sangfor.com.cn` UOS arm64 zip + official Electron 1.8.8 arm64 | Official `download.sangfor.com.cn` x64 `.deb` + official Electron 1.8.8 x64 |
| Qianxin TrustAgent 3.5.1.1003.62 | SHA256-pinned mirror *(Qianxin has no anonymous public CDN)* | SHA256-pinned mirror *(same)* |

## Security Model

Before any newly built image is promoted from its `-unverified` staging tag (and runnable anytime in CI via `python3 -m zt.verify`), `zt` boots it across two stateful boots on loopback and verifies live security, persistence, and adversarial invariants:

- **`auth` & `persistence`**: verifies loopback desktop auth (`HTTP 200` without password; `401`/`200` with password) and confirms across a container recreate on the same state volume that `/etc/machine-id`, D-Bus machine-id, SMBIOS/DMI serial/UUID, deterministic MAC, and KasmVNC TLS cert do not drift.
- **Network isolation & self-healing (`policy`, `routing`, `loopback_isolation`, `tunnel`, `reachability`)**: unified `zt-iptables` backend (`nft`/`legacy` auto-detection, zero split-brain) enforces `ZT-INPUT` #1 and `ZT-OUTPUT` #1 (IPv4 & IPv6), atomically self-heals vendor `iptables` and full-table `iptables-restore` tampering, drops non-`lo` traffic to `127.0.0.0/8` and `::1/128` even under `route_localnet=1`, preserves KasmVNC `:6901` return routing under VPN default-route hijacks via `table 90` + `CONNMARK` + `$wan.rp_filter=2`, applies dual-stack two-stage `TCPMSS` clamping (`1340`/`1220`), and passes two-round positive/negative peer-container and tunnel drop controls.
- **Multiplexed SOCKS5 isolation (`mux_e2e`)**: native `GuestMux` runs as `nobody` over the single `exec` stdio pipe with no `microsocks` daemon or unauthenticated `127.0.0.1:1080` listener, blocks post-resolve loopback/unspecified SSRF targets (including DNS rebinding, returning RFC 1928 `REP=0x02`), restricts `CALLBACK_OPEN` to static allowlisted ports, uses IPv4-first Happy Eyeballs (`/etc/gai.conf`), and auto-recovers across host sleep/wake via 15s heartbeats and passive idle keepalive.
- **Privilege, identity & resource hardening (`privilege`, `limits`, `identity`, `setuid`, `ownership`, `programs`)**: no `sudo` in base; all desktop UIs run as `kasm-user` with `CapEff=0` and `NoNewPrivs=1` (Sangfor daemons and UIs run in separate systemd units); every systemd unit enforces `NoNewPrivileges=true`, `RLIMIT_NOFILE <= 65536`, and `RLIMIT_CORE=0`; vendor daemons drop `CAP_SYS_ADMIN`, `CAP_SYS_CHROOT`, `CAP_SYS_MODULE`, `CAP_SYS_RAWIO`, and `CAP_SYS_PTRACE` via `CapabilityBoundingSet`; `/proc/sys/net/core` stays read-only on Docker; SMBIOS/DMI identity mounts are read-only; root-executed paths and symlink chains are audited; `kasm-user` owns nothing outside `/home/kasm-user` and declared vendor shared directories.
- **Runtime integrity (`units`, `ui`, `libraries`, `timezone`, `log`)**: active units, live X11 window checks, native ELF `e_machine` + `ldd` verification, host timezone sync, TrustAgent `get_mid` device UUID verification, and clean boot logs.

### Trust Boundaries & Architectural Limits

- **`accept local`**: passwordless on `127.0.0.1` for frictionless local use; avoid untrusted web pages in the same browser profile after trusting the self-signed HTTPS certificate.
- **`accept lan`**: passwordless for any peer on the same private/LAN/Tailscale subnet; use only on trusted home/office networks or private overlays, not shared public Wi-Fi.
- **`accept all`**: enforces a 6–128 char password and per-source-IP rate limiting on desktop and SOCKS5, but SOCKS5 RFC 1929 itself is not TLS-encrypted; prefer `accept lan` or an encrypted overlay (Tailscale / WireGuard) over untrusted networks.
- **Linux rootful Docker**: on native Linux with rootful Docker, containers share the host kernel (namespace boundary rather than a VM like macOS Apple Container or Docker Desktop). `zt` defaults Docker to `CAPS=least` (`--cap-drop ALL` + explicit minimal allowlist, excluding `SYS_MODULE`, `SYS_RAWIO`, `SYS_PTRACE`, `BPF`, `DAC_READ_SEARCH`, `MKNOD`, etc.), mounts `/dev/net/tun` read-write only (`:rw`), keeps `/proc/sys/net/core` read-only (remounting only `/proc/sys/net/ipv4/conf`), enforces `--pids-limit 1024`, `--shm-size 256m`, `nofile=1024:65536`, and `core=0`, hardens `/run` tmpfs mounts, and only relaxes MAC confinement (`label=disable` / `apparmor=unconfined`) when SELinux or AppArmor is active so `systemd` and bind mounts can run. For an additional user-namespace boundary on Linux, prefer rootless Docker or rootless Podman.
- **SOCKS5 UDP & throughput**: SOCKS5 supports TCP `CONNECT` and unicast `UDP ASSOCIATE` (for TUN clients such as Clash/sing-box/Surge, QUIC, internal DNS, and UDP RPC), with peer-IP enforcement, TCP-control lifecycle binding, post-resolve loopback SSRF blocking, per-stream TCP credit flow control (`WINDOW_UPDATE`) so a stalled client never blocks other streams or new handshakes, bounded stream limits, and drop-on-full bounded UDP queues so UDP bursts never stall TCP streams. Multicast/broadcast discovery and unsolicited inbound P2P UDP do not traverse SOCKS5 or the container firewall — use the KasmVNC web desktop for such apps. Traffic shares a single multiplexed stdio pipe, optimized for interactive office/SSH/Git/web workloads rather than bulk high-throughput transfers.

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
