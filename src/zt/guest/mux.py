#!/usr/bin/env python3
"""Minimal stdlib asyncio TCP + UDP + Callback multiplexer for the zt SOCKS5 bridge (proto v3).

Runs standalone inside the container as `nobody` via `python3 -c <source> [--profile P]
[--callback-ports p1,p2]` over a single persistent `exec -i` pipe. Stdlib ONLY.

Key capabilities (BRIDGE_PROTO = 3):
- Native SOCKS5 TCP `CONNECT` (`TCP_OPEN` -> `OPEN_OK` / `OPEN_ERR`), eliminating `microsocks`
  and its per-connection pthread pool & unauthenticated 127.0.0.1:1080 listener.
- Shared post-resolve, pre-connect SSRF guard rejecting `is_loopback` and `is_unspecified`
  targets (including IPv4-mapped IPv6 and DNS rebinding) with explicit RFC 1928 `REP=0x02`.
- Simplified RFC 8305 Happy Eyeballs (IPv4 preferred, staggered fallback across addresses)
  backed by a bounded ThreadPoolExecutor(16) with in-flight DNS deduplication.
- SOCKS5 `UDP ASSOCIATE` with non-blocking DNS resolution, idle association reaping (300s),
  and rate-limited `EMSGSIZE` diagnostics.
- `PING`/`PONG` heartbeat carrying compact JSON health telemetry (`vpn`, `iface`, `dns_ok`,
  `daemon_ok`, `state_used_pct`, pending `sso_url`).
- `/run/zt-events/latest.json` watcher emitting `OPEN_URL` / `CALLBACK_REQ` control frames
  and `CALLBACK_OPEN` dialing ONLY container `127.0.0.1:<port>` intersected with the static
  hard allowlist `{39301, 54631, 54530}`.

Frame layout (big-endian, 9-byte header):
    uint32 stream_id | uint8 frame_type | uint32 length | <length bytes>
"""
import argparse
import asyncio
import collections
import concurrent.futures
import contextlib
import errno
import ipaddress
import json
import os
import re
import socket
import struct
import sys
import time

HEADER = struct.Struct('>IBI')
WIN_STRUCT = struct.Struct('>I')
PORT_STRUCT = struct.Struct('!H')

OPEN = 1
DATA = 2
EOF = 3
RST = 4
UDP_OPEN = 5
UDP_DATA = 6
UDP_CLOSE = 7
WINDOW_UPDATE = 8
TCP_OPEN = 9
OPEN_OK = 10
OPEN_ERR = 11
PING = 12
PONG = 13
OPEN_URL = 14
CALLBACK_REQ = 15
CALLBACK_OPEN = 16

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_NOT_ALLOWED = 0x02
REP_NET_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONN_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08

MAX_FRAME = 1 << 20                 # 1 MiB safety bound
MAX_TCP_STREAMS = 512               # Bounded concurrent TCP + callback streams
MAX_UDP_ASSOCS = 128                # Bounded concurrent UDP associations
STREAM_WINDOW = 4 * 1024 * 1024     # 4 MiB initial per-stream send window
WINDOW_REPLENISH = 1 * 1024 * 1024  # Send WINDOW_UPDATE once >= 1 MiB drained
MAX_STREAM_BUFFER = STREAM_WINDOW + (1 * 1024 * 1024)  # 5 MiB hard receive cap

MAX_UDP_PAYLOAD = 65507             # Max IPv4 UDP datagram payload
UDP_QUEUE_SIZE = 256                # Bounded per-direction UDP queue (drop-on-full)
UDP_PEER_TTL = 300.0                # Seconds an outbound UDP peer may send replies
UDP_PEER_MAX = 512                  # Max tracked remote UDP peers per association
UDP_IDLE_TTL = 300.0                # Reap idle UDP associations after 300s
UDP_MAX_PENDING_DNS = 32            # Max concurrent async DNS sends per UDP assoc

DNS_CACHE_TTL = 30.0                # Seconds to cache successful resolutions
DNS_NEG_TTL = 5.0                   # Seconds to cache failed/blocked resolutions
DNS_CACHE_MAX = 256
DNS_WORKERS = 16
DNS_TIMEOUT = 5.0

TCP_CONNECT_TIMEOUT = 15.0
HAPPY_EYEBALLS_DELAY = 0.25         # RFC 8305 staggered attempt delay (250ms)
EMSGSIZE_LOG_INTERVAL = 30.0
KEEPALIVE_IDLE_SECONDS = 180.0      # Zero-config passive idle tunnel keepalive window
KEEPALIVE_PROBE_TIMEOUT = 2.0

EVENTS_PATH = '/run/zt-events/latest.json'
PROC_DIR = '/proc'
STATE_MOUNT_PATH = '/var/lib/zt-state'
SSO_URL_FRESH_SECONDS = 300
STATIC_CALLBACK_ALLOWLIST = frozenset((39301, 54631, 54530))

# Minimal 17-byte RFC 1035 DNS query for root `.` NS (QTYPE=2, QCLASS=1, RD=0).
_DNS_KEEPALIVE_QUERY = b'\x7a\x74\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01'

_SSO_URL_RE = re.compile(r'^https?://[A-Za-z0-9._:%\[\]-]+(?:[/?#][!-~]*)?$')
_TUNNEL_PREFIXES = ('tun', 'utun', 'vnic', 'sdpvnic', 'sangforvnic', 'tap')
_PROFILE_DAEMONS = {
    'trustagent': frozenset(('trustdservice', 'trustservice')),
    'atrust': frozenset(('aTrustAgent', 'aTrustDaemon')),
    'easyconnect': frozenset(('ECAgent', 'svpnservice')),
}


def encode_frame(stream_id, kind, payload=b''):
    return HEADER.pack(stream_id, kind, len(payload)) + payload


async def read_frame(reader):
    try:
        raw_header = await reader.readexactly(HEADER.size)
    except asyncio.IncompleteReadError:
        return None
    stream_id, kind, length = HEADER.unpack(raw_header)
    if length > MAX_FRAME:
        raise ValueError(f'frame length {length} exceeds limit')
    payload = await reader.readexactly(length) if length else b''
    return stream_id, kind, payload


def sanitize_sso_url(raw):
    """Return validated http(s) URL (<= 4096 printable non-whitespace ASCII) or None."""
    if not isinstance(raw, str):
        return None
    if not raw or len(raw) > 4096:
        return None
    if not _SSO_URL_RE.fullmatch(raw):
        return None
    return raw


class StreamState:
    """Per-stream non-blocking receive buffer + credit-based send window.

    Demux loops NEVER await on a stream: `push_data` is O(1) synchronous and
    returns False if the peer exceeds `MAX_STREAM_BUFFER` (triggering per-stream
    RST without stalling other streams). `push_eof`, `close_rst`, and
    `add_window` never block or fail and always wake waiting coroutines.
    """

    __slots__ = (
        '_items', '_buffered', '_rx_event', '_rst',
        '_send_window', '_tx_event',
    )

    def __init__(self, initial_window=STREAM_WINDOW):
        self._items = collections.deque()
        self._buffered = 0
        self._rx_event = asyncio.Event()
        self._rst = False
        self._send_window = initial_window
        self._tx_event = asyncio.Event()
        if initial_window > 0:
            self._tx_event.set()

    def push_data(self, payload):
        if self._rst:
            return True
        if self._buffered + len(payload) > MAX_STREAM_BUFFER:
            self._rst = True
            self._items.clear()
            self._buffered = 0
            self._rx_event.set()
            self._tx_event.set()
            return False
        self._items.append((DATA, payload))
        self._buffered += len(payload)
        self._rx_event.set()
        return True

    def push_eof(self):
        if self._rst:
            return
        self._items.append((EOF, b''))
        self._rx_event.set()

    def close_rst(self):
        self._rst = True
        self._items.clear()
        self._buffered = 0
        self._rx_event.set()
        self._tx_event.set()

    def add_window(self, increment):
        if increment <= 0 or self._rst:
            return
        self._send_window = min(self._send_window + increment, MAX_STREAM_BUFFER)
        if self._send_window > 0:
            self._tx_event.set()

    async def recv(self):
        while True:
            if self._rst:
                return RST, b''
            if self._items:
                kind, payload = self._items.popleft()
                if kind == DATA:
                    self._buffered -= len(payload)
                if not self._items and not self._rst:
                    self._rx_event.clear()
                return kind, payload
            self._rx_event.clear()
            await self._rx_event.wait()

    async def acquire_send(self, want):
        """Wait until >= 1 byte of send credit is available (or RST -> 0)."""
        while not self._rst:
            avail = self._send_window
            if avail > 0:
                granted = min(want, avail)
                self._send_window -= granted
                if self._send_window == 0:
                    self._tx_event.clear()
                return granted
            self._tx_event.clear()
            await self._tx_event.wait()
        return 0


async def send_stream_data(send_fn, stream_id, state, data):
    """Send `data` in window-bounded DATA frames; returns False if stream was RST."""
    view = memoryview(data)
    pos = 0
    total = len(view)
    while pos < total:
        granted = await state.acquire_send(total - pos)
        if granted <= 0:
            return False
        await send_fn(stream_id, DATA, bytes(view[pos:pos + granted]))
        pos += granted
    return True


async def splice_tasks(up_coro, down_coro, drain_timeout=300):
    """Run bidirectional up/down coroutines with intentional asymmetric half-close."""
    up = asyncio.create_task(up_coro)
    down = asyncio.create_task(down_coro)
    try:
        done, pending = await asyncio.wait([up, down], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if down in pending:
            await asyncio.wait_for(down, timeout=drain_timeout)
        elif up in pending:
            up.cancel()
            await asyncio.gather(up, return_exceptions=True)
    finally:
        for task in (up, down):
            if not task.done():
                task.cancel()
        await asyncio.gather(up, down, return_exceptions=True)


def normalize_ip(host):
    """Return canonical IPv4/IPv6 string (unmapping ::ffff:x.y.z.w, stripping %zone), or None."""
    if not host:
        return None
    raw = str(host).split('%', 1)[0]
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def is_disallowed_target_ip(host):
    """True when `host` is a loopback or unspecified IP (including IPv4-mapped IPv6)."""
    norm = normalize_ip(host)
    if norm is None:
        return True
    ip = ipaddress.ip_address(norm)
    return bool(ip.is_loopback or ip.is_unspecified)


def parse_socks_addr(buf, offset=0):
    """Parse RFC 1928 ATYP+ADDR+PORT at `offset`; return (atyp, host, port, end) or None."""
    size = len(buf)
    if size - offset < 4:
        return None
    atyp = buf[offset]
    pos = offset + 1
    if atyp == ATYP_IPV4:
        if size - pos < 6:
            return None
        host = socket.inet_ntop(socket.AF_INET, buf[pos:pos + 4])
        port = (buf[pos + 4] << 8) | buf[pos + 5]
        return atyp, host, port, pos + 6
    if atyp == ATYP_IPV6:
        if size - pos < 18:
            return None
        host = socket.inet_ntop(socket.AF_INET6, buf[pos:pos + 16])
        port = (buf[pos + 16] << 8) | buf[pos + 17]
        return atyp, host, port, pos + 18
    if atyp == ATYP_DOMAIN:
        if size - pos < 1:
            return None
        dlen = buf[pos]
        pos += 1
        if dlen == 0 or size - pos < dlen + 2:
            return None
        raw_host = buf[pos:pos + dlen]
        if b'\x00' in raw_host:
            return None
        try:
            host = raw_host.decode('utf-8')
        except UnicodeDecodeError:
            return None
        if not host or any(ch.isspace() for ch in host):
            return None
        port = (buf[pos + dlen] << 8) | buf[pos + dlen + 1]
        return atyp, host, port, pos + dlen + 2
    return None


def encode_socks_addr(host, port):
    """Encode a normalized IPv4 or IPv6 address + port as RFC 1928 ATYP+ADDR+PORT."""
    norm = normalize_ip(host)
    if norm is None:
        raise ValueError(f'not an IP address: {host!r}')
    ip = ipaddress.ip_address(norm)
    if isinstance(ip, ipaddress.IPv4Address):
        return bytes([ATYP_IPV4]) + ip.packed + struct.pack('!H', port)
    return bytes([ATYP_IPV6]) + ip.packed + struct.pack('!H', port)


def _errno_to_socks_rep(exc):
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
        return REP_TTL_EXPIRED
    code = getattr(exc, 'errno', None)
    if code == errno.ECONNREFUSED:
        return REP_CONN_REFUSED
    if code == errno.ENETUNREACH:
        return REP_NET_UNREACHABLE
    if code in (errno.EHOSTUNREACH, errno.EHOSTDOWN):
        return REP_HOST_UNREACHABLE
    if code == errno.ETIMEDOUT:
        return REP_TTL_EXPIRED
    if code in (errno.EACCES, errno.EPERM):
        return REP_NOT_ALLOWED
    return REP_GENERAL_FAILURE


def _interleave_v4_first(addrs):
    """Order deduplicated (af, ip) targets with IPv4 preferred for RFC 8305 Happy Eyeballs."""
    v4 = [pair for pair in addrs if pair[0] == socket.AF_INET]
    v6 = [pair for pair in addrs if pair[0] == socket.AF_INET6]
    ordered = []
    for idx in range(max(len(v4), len(v6))):
        if idx < len(v4):
            ordered.append(v4[idx])
        if idx < len(v6):
            ordered.append(v6[idx])
    return tuple(ordered)


def _detect_tunnel_iface(proc_dir=None):
    """Return active VPN tunnel interface name (if UP and routed/running), else ''."""
    root = PROC_DIR if proc_dir is None else proc_dir
    if not root:
        return ''
    ifaces = []
    try:
        with open(os.path.join(root, 'net', 'dev'), encoding='utf-8', errors='replace') as handle:
            for line in handle:
                if ':' not in line:
                    continue
                name = line.split(':', 1)[0].strip()
                if any(name.startswith(prefix) for prefix in _TUNNEL_PREFIXES):
                    ifaces.append(name)
    except OSError:
        return ''
    if not ifaces:
        return ''

    routed = set()
    try:
        with open(os.path.join(root, 'net', 'route'), encoding='utf-8', errors='replace') as handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if parts:
                    routed.add(parts[0])
    except OSError:
        pass

    for name in ifaces:
        flags = 0
        try:
            with open(f'/sys/class/net/{name}/flags', encoding='utf-8') as handle:
                flags = int(handle.read().strip(), 0)
        except (OSError, ValueError):
            flags = 0
        # Require IFF_UP (0x1) and either route present or IFF_RUNNING (0x40).
        if (flags & 0x1) and (name in routed or (flags & 0x40)):
            return name
    return ''


def _check_daemon_alive(profile, proc_dir=None):
    """Best-effort check whether expected VPN daemon processes exist in /proc."""
    wanted = _PROFILE_DAEMONS.get(profile)
    root = PROC_DIR if proc_dir is None else proc_dir
    if not wanted or not root or not os.path.isdir(root):
        return True
    visible_pids = 0
    try:
        for entry in os.listdir(root):
            if not entry.isdigit():
                continue
            visible_pids += 1
            try:
                with open(os.path.join(root, entry, 'comm'), encoding='utf-8', errors='replace') as handle:
                    comm = handle.read().strip()
            except OSError:
                continue
            if comm in wanted:
                return True
    except OSError:
        return True
    # Under hidepid=2 only our own PID is visible; degrade gracefully rather than false-positive.
    return visible_pids <= 2


def _has_local_dns_listener(proc_dir=None):
    """True when any local socket is bound to UDP/TCP port 53 (0x0035)."""
    root = PROC_DIR if proc_dir is None else proc_dir
    if not root:
        return False
    for name in ('udp', 'udp6', 'tcp', 'tcp6'):
        path = os.path.join(root, 'net', name)
        try:
            with open(path, encoding='utf-8', errors='replace') as handle:
                next(handle, None)
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].endswith(':0035'):
                        return True
        except OSError:
            continue
    return False


def _check_dns_ok():
    """Fast local sanity check of /etc/resolv.conf without sending external traffic."""
    servers = []
    try:
        with open('/etc/resolv.conf', encoding='utf-8', errors='replace') as handle:
            for line in handle:
                stripped = line.strip()
                if stripped.startswith('nameserver'):
                    parts = stripped.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
    except OSError:
        return True
    if not servers:
        return False
    if all(ns in ('127.0.0.1', '::1') for ns in servers):
        return _has_local_dns_listener()
    return True


def _read_iface_tx_bytes(iface):
    """Return kernel TX byte counter for `iface`, or None if unavailable."""
    if not iface:
        return None
    try:
        with open(f'/sys/class/net/{iface}/statistics/tx_bytes', encoding='utf-8') as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def _discover_keepalive_target(iface, resolv_path='/etc/resolv.conf', route_path='/proc/net/route'):
    """Pick a safe non-loopback (af, ip, port) target for passive idle tunnel keepalive, or None."""
    if not iface:
        return None
    # 1. Prefer non-loopback nameserver pushed by the VPN into /etc/resolv.conf.
    try:
        with open(resolv_path, encoding='utf-8', errors='replace') as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped.startswith('nameserver'):
                    continue
                parts = stripped.split()
                if len(parts) < 2:
                    continue
                norm = normalize_ip(parts[1])
                if norm and not is_disallowed_target_ip(norm):
                    ip_obj = ipaddress.ip_address(norm)
                    af = socket.AF_INET if isinstance(ip_obj, ipaddress.IPv4Address) else socket.AF_INET6
                    return af, norm, 53
    except OSError:
        pass

    # 2. Fall back to tunnel gateway or specific routed subnet peer from /proc/net/route.
    fallback_peer = None
    try:
        with open(route_path, encoding='utf-8', errors='replace') as handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if len(parts) < 8 or parts[0] != iface:
                    continue
                try:
                    dest = int(parts[1], 16)
                    gw = int(parts[2], 16)
                    mask = int(parts[7], 16)
                except ValueError:
                    continue
                if gw != 0:
                    gw_ip = socket.inet_ntop(socket.AF_INET, struct.pack('<I', gw))
                    if not is_disallowed_target_ip(gw_ip):
                        return socket.AF_INET, gw_ip, 53
                if fallback_peer is None and dest != 0 and mask != 0:
                    dest_net = socket.ntohl(dest) if sys.byteorder == 'little' else dest
                    mask_net = socket.ntohl(mask) if sys.byteorder == 'little' else mask
                    host_bits = (~mask_net) & 0xFFFFFFFF
                    cand_net = (dest_net | 1) if host_bits >= 2 else dest_net
                    cand_ip = socket.inet_ntop(socket.AF_INET, struct.pack('!I', cand_net))
                    if not is_disallowed_target_ip(cand_ip):
                        fallback_peer = (socket.AF_INET, cand_ip, 53)
    except OSError:
        pass
    return fallback_peer


async def _send_keepalive_probe(target, timeout=KEEPALIVE_PROBE_TIMEOUT):
    """Send one tiny non-blocking UDP DNS root probe and close the socket cleanly."""
    if not target:
        return False
    af, ip, port = target
    if is_disallowed_target_ip(ip):
        return False
    sock = socket.socket(af, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        sock.sendto(_DNS_KEEPALIVE_QUERY, (ip, port))
        with contextlib.suppress(asyncio.TimeoutError, OSError):
            await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=timeout)
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _state_volume_usage(path=STATE_MOUNT_PATH):
    """Return (used_pct, avail_mb) for mounted state volume, or (None, None)."""
    try:
        if not os.path.isdir(path):
            return None, None
        st = os.statvfs(path)
        if st.f_blocks <= 0:
            return None, None
        total = st.f_blocks * st.f_frsize
        avail = st.f_bavail * st.f_frsize
        used_pct = int(round((total - avail) * 100.0 / total)) if total > 0 else 0
        avail_mb = int(avail // (1024 * 1024))
        return max(0, min(100, used_pct)), avail_mb
    except OSError:
        return None, None


class _GuestUDPProtocol(asyncio.DatagramProtocol):
    """Receives remote UDP replies from previously contacted peers, drop-on-full."""

    def __init__(self, inbound_queue, is_allowed_peer, on_activity=None):
        self._inbound = inbound_queue
        self._is_allowed_peer = is_allowed_peer
        self._on_activity = on_activity

    def datagram_received(self, data, addr):
        if len(data) > MAX_UDP_PAYLOAD:
            return
        if not self._is_allowed_peer(addr[0], addr[1]):
            return
        try:
            encoded = encode_socks_addr(addr[0], addr[1]) + data
        except (ValueError, OSError):
            return
        if self._on_activity is not None:
            self._on_activity()
        with contextlib.suppress(asyncio.QueueFull):
            self._inbound.put_nowait(encoded)

    def error_received(self, exc):
        # Ignore transient ICMP errors so one unreachable destination never kills the relay.
        pass


class _GuestUDPAssoc:
    """One SOCKS5 UDP ASSOCIATE session running inside the container as `nobody`.

    Uses separate lazy AF_INET / AF_INET6 UDP sockets, a bounded TTL allowlist
    of contacted remote (ip, port) peers, non-blocking async DNS dispatch so one
    slow lookup never stalls other datagrams, post-resolve loopback/unspecified
    SSRF rejection, rate-limited EMSGSIZE diagnostics, and idle reaping (300s).
    """

    def __init__(self, mux, stream_id):
        self._mux = mux
        self._stream_id = stream_id
        self._outbound = asyncio.Queue(maxsize=UDP_QUEUE_SIZE)
        self._inbound = asyncio.Queue(maxsize=UDP_QUEUE_SIZE)
        self._allowed_peers = {}
        self._v4_transport = None
        self._v6_transport = None
        self._closed = False
        self._last_activity = time.monotonic()
        self._last_emsgsize_log = 0.0
        self._dns_tasks = set()
        self._tasks = (
            asyncio.create_task(self._outbound_loop()),
            asyncio.create_task(self._inbound_loop()),
        )

    @property
    def last_activity(self):
        return self._last_activity

    def _touch(self):
        self._last_activity = time.monotonic()
        self._mux.touch_tunnel_activity()

    def _record_peer(self, target_ip, port):
        now = time.monotonic()
        if len(self._allowed_peers) >= UDP_PEER_MAX:
            expired = [k for k, exp in self._allowed_peers.items() if exp <= now]
            for k in expired:
                self._allowed_peers.pop(k, None)
            if len(self._allowed_peers) >= UDP_PEER_MAX:
                self._allowed_peers.pop(next(iter(self._allowed_peers)))
        self._allowed_peers[(target_ip, port)] = now + UDP_PEER_TTL

    def _is_allowed_peer(self, host, port):
        norm = normalize_ip(host)
        if norm is None:
            return False
        exp = self._allowed_peers.get((norm, port))
        if exp is None:
            return False
        if exp <= time.monotonic():
            self._allowed_peers.pop((norm, port), None)
            return False
        return True

    def enqueue_outbound(self, payload):
        if not self._closed:
            self._touch()
            with contextlib.suppress(asyncio.QueueFull):
                self._outbound.put_nowait(payload)

    async def _ensure_transport(self, family):
        if self._closed:
            return None
        if family == socket.AF_INET:
            if self._v4_transport is not None and not self._v4_transport.is_closing():
                return self._v4_transport
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setblocking(False)
                sock.bind(('0.0.0.0', 0))
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: _GuestUDPProtocol(self._inbound, self._is_allowed_peer, self._touch),
                    sock=sock,
                )
            except BaseException:
                sock.close()
                raise
            if self._closed:
                transport.close()
                return None
            self._v4_transport = transport
            return transport

        if family == socket.AF_INET6:
            if self._v6_transport is not None and not self._v6_transport.is_closing():
                return self._v6_transport
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                sock.setblocking(False)
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind(('::', 0))
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: _GuestUDPProtocol(self._inbound, self._is_allowed_peer, self._touch),
                    sock=sock,
                )
            except BaseException:
                sock.close()
                raise
            if self._closed:
                transport.close()
                return None
            self._v6_transport = transport
            return transport

        return None

    async def _send_resolved(self, family, target_ip, port, data):
        if self._closed or self._mux.is_target_blocked(target_ip):
            return
        try:
            transport = await self._ensure_transport(family)
            if transport is not None and not transport.is_closing():
                self._record_peer(target_ip, port)
                transport.sendto(data, (target_ip, port))
                self._touch()
        except OSError as exc:
            if exc.errno == errno.EMSGSIZE:
                now = time.monotonic()
                if now - self._last_emsgsize_log >= EMSGSIZE_LOG_INTERVAL:
                    self._last_emsgsize_log = now
                    sys.stderr.write(
                        f'zt-mux: UDP datagram ({len(data)}B -> {target_ip}:{port}) '
                        'dropped with EMSGSIZE (path MTU exceeded)\n'
                    )
                    sys.stderr.flush()

    async def _resolve_and_send_domain(self, host, port, data):
        try:
            status, targets = await self._mux.resolve_and_filter(host, port, socket.SOCK_DGRAM)
            if status != 'ok' or not targets or self._closed:
                return
            family, target_ip = targets[0]
            await self._send_resolved(family, target_ip, port, data)
        except asyncio.CancelledError:
            raise
        except OSError:
            return

    async def _outbound_loop(self):
        try:
            while not self._closed:
                payload = await self._outbound.get()
                parsed = parse_socks_addr(payload)
                if parsed is None:
                    continue
                atyp, host, port, data_offset = parsed
                if port == 0:
                    continue
                data = payload[data_offset:]
                if len(data) > MAX_UDP_PAYLOAD:
                    continue
                if atyp == ATYP_IPV4:
                    if self._mux.is_target_blocked(host):
                        continue
                    await self._send_resolved(socket.AF_INET, host, port, data)
                elif atyp == ATYP_IPV6:
                    norm = normalize_ip(host)
                    if norm is None or self._mux.is_target_blocked(norm):
                        continue
                    ip_obj = ipaddress.ip_address(norm)
                    family = socket.AF_INET if isinstance(ip_obj, ipaddress.IPv4Address) else socket.AF_INET6
                    await self._send_resolved(family, norm, port, data)
                elif atyp == ATYP_DOMAIN:
                    cached = self._mux.lookup_dns_cache(host, socket.SOCK_DGRAM)
                    if cached is not None:
                        status, targets = cached
                        if status == 'ok' and targets:
                            await self._send_resolved(targets[0][0], targets[0][1], port, data)
                        continue
                    if len(self._dns_tasks) < UDP_MAX_PENDING_DNS:
                        task = asyncio.create_task(self._resolve_and_send_domain(host, port, data))
                        self._dns_tasks.add(task)
                        task.add_done_callback(self._dns_tasks.discard)
        except asyncio.CancelledError:
            raise

    async def _inbound_loop(self):
        try:
            while not self._closed:
                encoded = await self._inbound.get()
                await self._mux.send(self._stream_id, UDP_DATA, encoded)
        except (OSError, ConnectionError):
            pass
        except asyncio.CancelledError:
            raise

    def close(self):
        if self._closed:
            return
        self._closed = True
        self._allowed_peers.clear()
        for transport in (self._v4_transport, self._v6_transport):
            if transport is not None:
                transport.close()
        self._v4_transport = None
        self._v6_transport = None
        for task in (*self._tasks, *list(self._dns_tasks)):
            if not task.done():
                task.cancel()

    async def wait_closed(self):
        self.close()
        pending = [*self._tasks, *list(self._dns_tasks)]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._dns_tasks.clear()


class GuestMux:
    """Guest-side endpoint (BRIDGE_PROTO = 3): native TCP CONNECT, UDP ASSOCIATE,
    allowlisted loopback callbacks, PING/PONG health telemetry, and SSO event watcher.
    """

    def __init__(
        self,
        profile='',
        callback_ports=(),
        events_path=EVENTS_PATH,
        max_tcp_streams=MAX_TCP_STREAMS,
        max_udp_assocs=MAX_UDP_ASSOCS,
        udp_idle_ttl=UDP_IDLE_TTL,
        keepalive_idle=KEEPALIVE_IDLE_SECONDS,
        keepalive_probe_fn=None,
        proc_dir=None,
    ):
        self.profile = profile or ''
        # Defense-in-depth: intersect CLI-supplied ports with hardcoded static allowlist.
        self._callback_ports = frozenset(
            int(p) for p in callback_ports if int(p) in STATIC_CALLBACK_ALLOWLIST
        )
        self._events_path = events_path
        self._proc_dir = proc_dir
        self._max_tcp_streams = max_tcp_streams
        self._max_udp_assocs = max_udp_assocs
        self._udp_idle_ttl = udp_idle_ttl
        self._keepalive_idle = float(keepalive_idle)
        self._keepalive_probe_fn = keepalive_probe_fn
        self._streams = {}
        self._tasks = {}
        self._udp = {}
        self._dns_cache = {}
        self._dns_inflight = {}
        self._dns_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=DNS_WORKERS, thread_name_prefix='zt-dns',
        )
        self._write_lock = asyncio.Lock()
        self._out = None
        self._bg_tasks = set()
        self._pending_sso = None  # (url, ts)
        self._last_event_stat = None
        self._last_event_key = None
        self._last_tunnel_activity = time.monotonic()
        self._last_keepalive_probe = 0.0
        self._last_tunnel_tx = None  # (iface, tx_bytes)
        self._keepalive_probes_sent = 0

    def touch_tunnel_activity(self):
        """Record outbound/inbound VPN proxy traffic so idle keepalive stays silent while busy."""
        self._last_tunnel_activity = time.monotonic()

    def _track_bg(self, coro):
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    def is_target_blocked(self, host):
        """Return True when `host` is a disallowed proxy target (loopback / unspecified)."""
        return is_disallowed_target_ip(host)

    async def send(self, stream_id, kind, payload=b''):
        frame = encode_frame(stream_id, kind, payload)
        async with self._write_lock:
            if self._out is None or self._out.is_closing():
                raise ConnectionError('mux stdout closed')
            self._out.write(frame)
            await self._out.drain()

    def _schedule_send(self, stream_id, kind, payload=b''):
        async def _send():
            with contextlib.suppress(OSError, ConnectionError):
                await self.send(stream_id, kind, payload)

        self._track_bg(_send())

    def lookup_dns_cache(self, host, socktype):
        """Synchronous cache lookup returning (status, targets) or None."""
        literal = normalize_ip(host)
        if literal is not None:
            if self.is_target_blocked(literal):
                return 'blocked', ()
            ip_obj = ipaddress.ip_address(literal)
            fam = socket.AF_INET if isinstance(ip_obj, ipaddress.IPv4Address) else socket.AF_INET6
            return 'ok', ((fam, literal),)
        key = (host.lower(), socktype)
        cached = self._dns_cache.get(key)
        if cached is not None and cached[0] > time.monotonic():
            return cached[1], cached[2]
        return None

    async def resolve_and_filter(self, host, port, socktype=socket.SOCK_STREAM):
        """Resolve `host` asynchronously with in-flight deduplication and post-resolve SSRF filter.

        Returns:
            ('ok', ((af, ip), ...))   - allowed targets ordered IPv4-first for Happy Eyeballs
            ('blocked', ())           - target (or ALL resolved IPs) were loopback / unspecified
            ('unreach', ())           - DNS lookup failed / timed out / returned no usable IPs
        """
        cached = self.lookup_dns_cache(host, socktype)
        if cached is not None:
            return cached

        key = (host.lower(), socktype)
        inflight = self._dns_inflight.get(key)
        if inflight is not None:
            return await inflight

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._dns_inflight[key] = fut
        try:
            try:
                infos = await asyncio.wait_for(
                    loop.run_in_executor(
                        self._dns_executor, socket.getaddrinfo, host, port, 0, socktype,
                    ),
                    timeout=DNS_TIMEOUT,
                )
            except (OSError, asyncio.TimeoutError):
                infos = ()

            saw_any = False
            seen = set()
            allowed = []
            for af, _, _, _, sockaddr in infos:
                if af not in (socket.AF_INET, socket.AF_INET6):
                    continue
                norm = normalize_ip(sockaddr[0])
                if norm is None:
                    continue
                saw_any = True
                if self.is_target_blocked(norm):
                    continue
                ip_obj = ipaddress.ip_address(norm)
                fam = socket.AF_INET if isinstance(ip_obj, ipaddress.IPv4Address) else socket.AF_INET6
                pair = (fam, norm)
                if pair not in seen:
                    seen.add(pair)
                    allowed.append(pair)

            if allowed:
                status, targets = 'ok', _interleave_v4_first(allowed)
                ttl = DNS_CACHE_TTL
            elif saw_any:
                status, targets = 'blocked', ()
                ttl = DNS_NEG_TTL
            else:
                status, targets = 'unreach', ()
                ttl = DNS_NEG_TTL

            now = time.monotonic()
            if len(self._dns_cache) >= DNS_CACHE_MAX:
                expired = [k for k, v in self._dns_cache.items() if v[0] <= now]
                for k in expired:
                    self._dns_cache.pop(k, None)
                if len(self._dns_cache) >= DNS_CACHE_MAX:
                    self._dns_cache.clear()
            self._dns_cache[key] = (now + ttl, status, targets)
            result = (status, targets)
            if not fut.done():
                fut.set_result(result)
            return result
        except BaseException as exc:
            if not fut.done():
                fut.set_exception(exc)
            raise
        finally:
            self._dns_inflight.pop(key, None)

    async def resolve_udp_host(self, host, port):
        """Compatibility helper returning first allowed (family, ip) or None."""
        status, targets = await self.resolve_and_filter(host, port, socket.SOCK_DGRAM)
        return targets[0] if status == 'ok' and targets else None

    async def _happy_eyeballs_connect(self, targets, port, timeout=TCP_CONNECT_TIMEOUT):
        """Connect to first responsive target with RFC 8305 staggered fallback (IPv4 first)."""
        if len(targets) == 1:
            af, ip = targets[0]
            if self.is_target_blocked(ip):
                raise PermissionError('blocked loopback/unspecified target')
            return await asyncio.wait_for(
                asyncio.open_connection(ip, port, family=af),
                timeout=timeout,
            )

        deadline = time.monotonic() + timeout
        pending = set()
        next_idx = 0
        last_err = None
        winner = None

        async def _attempt(af, ip):
            if self.is_target_blocked(ip):
                raise PermissionError('blocked loopback/unspecified target')
            rem = max(0.1, deadline - time.monotonic())
            return await asyncio.wait_for(
                asyncio.open_connection(ip, port, family=af),
                timeout=rem,
            )

        try:
            pending.add(asyncio.create_task(_attempt(*targets[0])))
            next_idx = 1

            while pending or next_idx < len(targets):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                wait_for = min(HAPPY_EYEBALLS_DELAY, remaining) if next_idx < len(targets) else remaining
                done, pending = await asyncio.wait(
                    pending, timeout=wait_for, return_when=asyncio.FIRST_COMPLETED,
                )
                for task in done:
                    if task.cancelled():
                        continue
                    exc = task.exception()
                    if exc is None:
                        pair = task.result()
                        if winner is None:
                            winner = pair
                        else:
                            # Close extra simultaneous winner immediately so no socket leaks.
                            pair[1].close()
                            with contextlib.suppress(OSError, ConnectionError):
                                await pair[1].wait_closed()
                    else:
                        last_err = exc
                if winner is not None:
                    return winner
                if next_idx < len(targets) and (not done or not pending):
                    pending.add(asyncio.create_task(_attempt(*targets[next_idx])))
                    next_idx += 1

            if last_err is not None:
                raise last_err
            raise asyncio.TimeoutError('connection timed out')
        finally:
            for task in pending:
                task.cancel()
            if pending:
                results = await asyncio.gather(*pending, return_exceptions=True)
                for res in results:
                    if isinstance(res, tuple) and len(res) == 2:
                        res[1].close()
                        with contextlib.suppress(OSError, ConnectionError):
                            await res[1].wait_closed()

    async def _splice_stream(self, stream_id, state, reader, writer, track_tunnel=False):
        async def to_target():
            pending_win = 0
            while True:
                kind, payload = await state.recv()
                if kind == DATA:
                    if track_tunnel:
                        self.touch_tunnel_activity()
                    writer.write(payload)
                    await writer.drain()
                    pending_win += len(payload)
                    if pending_win >= WINDOW_REPLENISH:
                        inc = pending_win
                        pending_win = 0
                        await self.send(stream_id, WINDOW_UPDATE, WIN_STRUCT.pack(inc))
                elif kind == EOF:
                    if writer.can_write_eof():
                        with contextlib.suppress(ConnectionError, OSError):
                            writer.write_eof()
                    return
                elif kind == RST:
                    return

        async def from_target():
            while True:
                data = await reader.read(65536)
                if not data:
                    await self.send(stream_id, EOF)
                    return
                if track_tunnel:
                    self.touch_tunnel_activity()
                if not await send_stream_data(self.send, stream_id, state, data):
                    return

        await splice_tasks(to_target(), from_target(), drain_timeout=300)

    async def _run_tcp_connect(self, stream_id, state, host, port):
        writer = None
        opened = False
        try:
            self.touch_tunnel_activity()
            status, targets = await self.resolve_and_filter(host, port, socket.SOCK_STREAM)
            if status == 'blocked':
                state.close_rst()
                await self.send(stream_id, OPEN_ERR, bytes([REP_NOT_ALLOWED]))
                return
            if status != 'ok' or not targets:
                state.close_rst()
                await self.send(stream_id, OPEN_ERR, bytes([REP_HOST_UNREACHABLE]))
                return

            reader, writer = await self._happy_eyeballs_connect(targets, port)
            if state._rst:
                return

            sockname = writer.get_extra_info('sockname')
            try:
                bnd = encode_socks_addr(sockname[0], sockname[1]) if sockname else encode_socks_addr('0.0.0.0', 0)
            except ValueError:
                bnd = encode_socks_addr('0.0.0.0', 0)
            await self.send(stream_id, OPEN_OK, bnd)
            opened = True
            self.touch_tunnel_activity()
            await self._splice_stream(stream_id, state, reader, writer, track_tunnel=True)
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            state.close_rst()
            with contextlib.suppress(OSError, ConnectionError):
                if opened:
                    await self.send(stream_id, RST)
                else:
                    await self.send(stream_id, OPEN_ERR, bytes([_errno_to_socks_rep(exc)]))
        except asyncio.CancelledError:
            state.close_rst()
            raise
        finally:
            self._streams.pop(stream_id, None)
            self._tasks.pop(stream_id, None)
            if writer is not None:
                writer.close()
                with contextlib.suppress(OSError, ConnectionError):
                    await writer.wait_closed()

    async def _run_callback_connect(self, stream_id, state, port):
        writer = None
        opened = False
        try:
            if port not in self._callback_ports:
                state.close_rst()
                await self.send(stream_id, OPEN_ERR, bytes([REP_NOT_ALLOWED]))
                return
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', port),
                timeout=5.0,
            )
            if state._rst:
                return
            await self.send(stream_id, OPEN_OK, encode_socks_addr('127.0.0.1', port))
            opened = True
            await self._splice_stream(stream_id, state, reader, writer)
        except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
            state.close_rst()
            with contextlib.suppress(OSError, ConnectionError):
                if opened:
                    await self.send(stream_id, RST)
                else:
                    await self.send(stream_id, OPEN_ERR, bytes([_errno_to_socks_rep(exc)]))
        except asyncio.CancelledError:
            state.close_rst()
            raise
        finally:
            self._streams.pop(stream_id, None)
            self._tasks.pop(stream_id, None)
            if writer is not None:
                writer.close()
                with contextlib.suppress(OSError, ConnectionError):
                    await writer.wait_closed()

    def collect_health(self):
        """Return compact JSON-serializable container VPN/DNS/daemon/volume health dict."""
        now = int(time.time())
        iface = _detect_tunnel_iface() if self._proc_dir is None else _detect_tunnel_iface(self._proc_dir)
        daemon_ok = (
            _check_daemon_alive(self.profile)
            if self._proc_dir is None
            else _check_daemon_alive(self.profile, self._proc_dir)
        )
        dns_ok = _check_dns_ok()
        used_pct, avail_mb = _state_volume_usage()

        sso_url = ''
        sso_ts = 0
        if self._pending_sso is not None:
            url, ts = self._pending_sso
            if iface:
                # Clear stale SSO hint once VPN tunnel is connected.
                self._pending_sso = None
            elif now - ts <= SSO_URL_FRESH_SECONDS:
                sso_url, sso_ts = url, ts
            else:
                self._pending_sso = None

        if not daemon_ok:
            vpn = 'daemon-down'
        elif iface and not dns_ok:
            vpn = 'dns-err'
        elif iface:
            vpn = 'connected'
        elif sso_url:
            vpn = 'sso-pending'
        else:
            vpn = 'disconnected'

        payload = {
            'vpn': vpn,
            'iface': iface,
            'dns_ok': dns_ok,
            'daemon_ok': daemon_ok,
            'ts': now,
        }
        if used_pct is not None:
            payload['state_used_pct'] = used_pct
            payload['state_avail_mb'] = avail_mb
        if sso_url:
            payload['sso_url'] = sso_url
            payload['sso_ts'] = sso_ts
        return payload

    def _poll_events_once(self):
        """Inspect /run/zt-events/latest.json safely (O_NOFOLLOW, <=8KB) and emit control frames."""
        if not self._events_path:
            return
        try:
            st = os.lstat(self._events_path)
        except OSError:
            return
        sig = (st.st_mtime_ns, st.st_ino, st.st_size)
        if sig == self._last_event_stat:
            return
        self._last_event_stat = sig
        if st.st_size <= 0 or st.st_size > 8192:
            return
        try:
            flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(self._events_path, flags)
            try:
                raw = os.read(fd, 8192)
            finally:
                os.close(fd)
            data = json.loads(raw.decode('utf-8'))
        except (OSError, ValueError, UnicodeDecodeError):
            return
        if not isinstance(data, dict):
            return
        kind = data.get('kind')
        ts = int(data.get('ts') or int(time.time()))
        if kind == 'url':
            url = sanitize_sso_url(data.get('url'))
            if not url:
                return
            key = ('url', ts, url)
            if key == self._last_event_key:
                return
            self._last_event_key = key
            self._pending_sso = (url, ts)
            body = json.dumps({'url': url, 'ts': ts}, separators=(',', ':')).encode('utf-8')
            self._schedule_send(0, OPEN_URL, body)
        elif kind == 'callback':
            key = ('callback', ts, '')
            if key == self._last_event_key:
                return
            self._last_event_key = key
            body = json.dumps({'ts': ts}, separators=(',', ':')).encode('utf-8')
            self._schedule_send(0, CALLBACK_REQ, body)

    def _close_udp_assoc(self, assoc):
        if assoc is None:
            return
        assoc.close()
        self._track_bg(assoc.wait_closed())

    def _reap_idle_udp(self):
        now = time.monotonic()
        stale = [
            sid for sid, assoc in list(self._udp.items())
            if now - assoc.last_activity > self._udp_idle_ttl
        ]
        for sid in stale:
            assoc = self._udp.pop(sid, None)
            if assoc is not None:
                self._close_udp_assoc(assoc)
                self._schedule_send(sid, UDP_CLOSE)

    async def _run_idle_keepalive_probe(self, iface):
        try:
            if self._keepalive_probe_fn is not None:
                ok = await self._keepalive_probe_fn(iface)
            else:
                target = _discover_keepalive_target(iface)
                ok = await _send_keepalive_probe(target) if target else False
            if ok:
                self._keepalive_probes_sent += 1
        except asyncio.CancelledError:
            raise
        except OSError:
            pass

    def _maybe_idle_keepalive(self):
        """Trigger at most one lightweight probe per `keepalive_idle` window when tunnel is UP & idle."""
        if self._keepalive_idle <= 0:
            return False
        iface = _detect_tunnel_iface() if self._proc_dir is None else _detect_tunnel_iface(self._proc_dir)
        if not iface:
            self._last_tunnel_tx = None
            return False
        now = time.monotonic()
        tx_bytes = _read_iface_tx_bytes(iface)
        if tx_bytes is not None:
            if self._last_tunnel_tx is not None and self._last_tunnel_tx[0] == iface:
                if tx_bytes > self._last_tunnel_tx[1]:
                    self._last_tunnel_activity = now
            self._last_tunnel_tx = (iface, tx_bytes)
        if now - self._last_tunnel_activity < self._keepalive_idle:
            return False
        if now - self._last_keepalive_probe < self._keepalive_idle:
            return False
        self._last_keepalive_probe = now
        self._track_bg(self._run_idle_keepalive_probe(iface))
        return True

    async def _maintenance_loop(self):
        min_window = min(
            v for v in (self._udp_idle_ttl, self._keepalive_idle) if v > 0
        ) if (self._udp_idle_ttl > 0 or self._keepalive_idle > 0) else 30.0
        tick = min(1.0, max(0.05, min_window / 2.0))
        reap_every = min(30.0, max(0.05, self._udp_idle_ttl / 2.0)) if self._udp_idle_ttl > 0 else 30.0
        ka_every = min(30.0, max(0.05, self._keepalive_idle / 2.0)) if self._keepalive_idle > 0 else 30.0
        last_reap = time.monotonic()
        last_ka = time.monotonic()
        try:
            while True:
                self._poll_events_once()
                now = time.monotonic()
                if now - last_reap >= reap_every:
                    self._reap_idle_udp()
                    last_reap = now
                if now - last_ka >= ka_every:
                    self._maybe_idle_keepalive()
                    last_ka = now
                await asyncio.sleep(tick)
        except asyncio.CancelledError:
            raise

    async def serve(self, in_reader, out_writer):
        self._out = out_writer
        maint_task = asyncio.create_task(self._maintenance_loop())
        try:
            while True:
                frame = await read_frame(in_reader)
                if frame is None:
                    break
                stream_id, kind, payload = frame
                if kind == PING:
                    self._poll_events_once()
                    self._reap_idle_udp()
                    health = json.dumps(self.collect_health(), separators=(',', ':')).encode('utf-8')
                    self._schedule_send(0, PONG, health)
                elif kind == TCP_OPEN:
                    if stream_id == 0:
                        continue
                    if len(self._streams) >= self._max_tcp_streams:
                        self._schedule_send(stream_id, OPEN_ERR, bytes([REP_GENERAL_FAILURE]))
                        continue
                    parsed = parse_socks_addr(payload)
                    if parsed is None:
                        self._schedule_send(stream_id, OPEN_ERR, bytes([REP_ATYP_NOT_SUPPORTED]))
                        continue
                    _, host, port, _ = parsed
                    if port == 0:
                        self._schedule_send(stream_id, OPEN_ERR, bytes([REP_GENERAL_FAILURE]))
                        continue
                    state = StreamState()
                    self._streams[stream_id] = state
                    self._tasks[stream_id] = asyncio.create_task(
                        self._run_tcp_connect(stream_id, state, host, port)
                    )
                elif kind == CALLBACK_OPEN:
                    if stream_id == 0:
                        continue
                    if len(self._streams) >= self._max_tcp_streams:
                        self._schedule_send(stream_id, OPEN_ERR, bytes([REP_GENERAL_FAILURE]))
                        continue
                    if len(payload) != PORT_STRUCT.size:
                        self._schedule_send(stream_id, OPEN_ERR, bytes([REP_GENERAL_FAILURE]))
                        continue
                    cb_port = PORT_STRUCT.unpack(payload)[0]
                    if cb_port not in self._callback_ports:
                        self._schedule_send(stream_id, OPEN_ERR, bytes([REP_NOT_ALLOWED]))
                        continue
                    state = StreamState()
                    self._streams[stream_id] = state
                    self._tasks[stream_id] = asyncio.create_task(
                        self._run_callback_connect(stream_id, state, cb_port)
                    )
                elif kind == DATA:
                    state = self._streams.get(stream_id)
                    if state is not None and not state.push_data(payload):
                        self._streams.pop(stream_id, None)
                        task = self._tasks.pop(stream_id, None)
                        if task is not None:
                            task.cancel()
                        self._schedule_send(stream_id, RST)
                elif kind == EOF:
                    state = self._streams.get(stream_id)
                    if state is not None:
                        state.push_eof()
                elif kind == WINDOW_UPDATE:
                    state = self._streams.get(stream_id)
                    if state is not None and len(payload) == WIN_STRUCT.size:
                        state.add_window(WIN_STRUCT.unpack(payload)[0])
                elif kind == UDP_OPEN:
                    if stream_id == 0:
                        continue
                    if stream_id not in self._udp and len(self._udp) >= self._max_udp_assocs:
                        self._schedule_send(stream_id, UDP_CLOSE)
                        continue
                    old = self._udp.pop(stream_id, None)
                    if old is not None:
                        self._close_udp_assoc(old)
                    self._udp[stream_id] = _GuestUDPAssoc(self, stream_id)
                elif kind == UDP_DATA:
                    assoc = self._udp.get(stream_id)
                    if assoc is not None:
                        assoc.enqueue_outbound(payload)
                elif kind == UDP_CLOSE:
                    assoc = self._udp.pop(stream_id, None)
                    if assoc is not None:
                        self._close_udp_assoc(assoc)
                elif kind == RST:
                    state = self._streams.pop(stream_id, None)
                    if state is not None:
                        state.close_rst()
                    task = self._tasks.pop(stream_id, None)
                    if task is not None:
                        task.cancel()
                    assoc = self._udp.pop(stream_id, None)
                    if assoc is not None:
                        self._close_udp_assoc(assoc)
        finally:
            maint_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await maint_task
            for state in list(self._streams.values()):
                state.close_rst()
            self._streams.clear()
            tasks = list(self._tasks.values())
            self._tasks.clear()
            for task in tasks:
                task.cancel()
            bg = list(self._bg_tasks)
            self._bg_tasks.clear()
            for task in bg:
                task.cancel()
            assocs = list(self._udp.values())
            self._udp.clear()
            for assoc in assocs:
                assoc.close()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if bg:
                await asyncio.gather(*bg, return_exceptions=True)
            if assocs:
                await asyncio.gather(*(a.wait_closed() for a in assocs), return_exceptions=True)
            self._dns_executor.shutdown(wait=False, cancel_futures=True)


async def _stdio_streams():
    loop = asyncio.get_running_loop()
    raw_in = os.fdopen(os.dup(0), 'rb', buffering=0)
    raw_out = os.fdopen(os.dup(1), 'wb', buffering=0)
    os.dup2(2, 1)

    reader = asyncio.StreamReader()
    in_proto = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: in_proto, raw_in)

    out_transport, out_proto = await loop.connect_write_pipe(
        asyncio.streams.FlowControlMixin, raw_out,
    )
    writer = asyncio.StreamWriter(out_transport, out_proto, None, loop)
    return reader, writer


def _parse_callback_ports(raw):
    ports = []
    for tok in (raw or '').split(','):
        tok = tok.strip()
        if not tok:
            continue
        try:
            port = int(tok)
        except ValueError:
            continue
        if port in STATIC_CALLBACK_ALLOWLIST:
            ports.append(port)
    return tuple(sorted(set(ports)))


async def _run(profile='', callback_ports=()):
    reader, writer = await _stdio_streams()
    mux = GuestMux(profile=profile, callback_ports=callback_ports)
    try:
        await mux.serve(reader, writer)
    finally:
        writer.close()


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--profile', default='')
    parser.add_argument('--callback-ports', default='')
    args, _unknown = parser.parse_known_args(argv)
    asyncio.run(_run(
        profile=args.profile,
        callback_ports=_parse_callback_ports(args.callback_ports),
    ))


if __name__ == '__main__':
    main()
