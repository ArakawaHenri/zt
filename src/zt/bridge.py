"""Multiplexed persistent SOCKS5 bridge (proto v3: native TCP + UDP + SSO callbacks + VNC guard)."""
import asyncio
import collections
import contextlib
import csv
import hmac
import io
import ipaddress
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from zt import spec as zt_spec
from zt.config import (
    accept_mode,
    auth_fingerprint,
    auth_password,
    bind_address,
    die,
    ensure_state_dir,
    health_file,
    is_lan_ip,
    say,
    state_dir,
    warn,
    write_private_file,
)
from zt.guest.mux import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    CALLBACK_OPEN,
    CALLBACK_REQ,
    DATA,
    EOF,
    MAX_TCP_STREAMS,
    MAX_UDP_ASSOCS,
    MAX_UDP_PAYLOAD,
    OPEN_ERR,
    OPEN_OK,
    OPEN_URL,
    PING,
    PONG,
    PORT_STRUCT,
    REP_ATYP_NOT_SUPPORTED,
    REP_CMD_NOT_SUPPORTED,
    REP_GENERAL_FAILURE,
    RST,
    STATIC_CALLBACK_ALLOWLIST,
    TCP_OPEN,
    UDP_CLOSE,
    UDP_DATA,
    UDP_OPEN,
    UDP_QUEUE_SIZE,
    WIN_STRUCT,
    WINDOW_REPLENISH,
    WINDOW_UPDATE,
    StreamState,
    encode_frame,
    encode_socks_addr,
    normalize_ip,
    parse_socks_addr,
    read_frame,
    sanitize_sso_url,
    send_stream_data,
    splice_tasks,
)
from zt.resources import guest_script, zipapp_archive
from zt.spec import (
    AUTH_USER,
    ENGINE_NAMES,
    container_name,
    desktop_backend_port,
    desktop_port,
    socks_port,
)

# Bump whenever bridge/mux wire protocol gains capabilities:
#   v1 = TCP via microsocks
#   v2 = TCP via microsocks + UDP ASSOCIATE
#   v3 = Native GuestMux TCP CONNECT (no microsocks) + PING/HEALTH + SSO callbacks + accept-all VNC guard
BRIDGE_PROTO = 3

SOCKS_HANDSHAKE_TIMEOUT = 30.0
TCP_OPEN_TIMEOUT = 20.0
PIPE_WRITE_TIMEOUT = 10.0
HEARTBEAT_INTERVAL = 15.0
HEARTBEAT_TIMEOUT = 5.0
BOOT_REFRESH_DELAYS = (3.0, 6.0)
SLEEP_JUMP_THRESHOLD = 10.0
CALLBACK_TTL_SECONDS = 300.0
MAX_TRACKED_RATE_IPS = 4096

_DEFAULT_CALLBACK_PORTS = {
    'trustagent': (39301,),
    'atrust': (54631,),
    'easyconnect': (54530,),
}


def callback_ports_for(profile):
    """Return allowed container loopback callback ports for `profile`."""
    if not profile:
        return ()
    mapping = getattr(zt_spec, 'CALLBACK_PORTS', _DEFAULT_CALLBACK_PORTS)
    ports = mapping.get(profile, ())
    return tuple(sorted({int(p) for p in ports if int(p) in STATIC_CALLBACK_ALLOWLIST}))


def bridge_pidfile(profile):
    return state_dir() / f'socks-{profile}.pid'


def bridge_logfile(profile):
    return state_dir() / f'socks-{profile}.log'


def _is_loopback_ip(host):
    norm = normalize_ip(host)
    if norm is None:
        return False
    return ipaddress.ip_address(norm).is_loopback


class _ConnRateLimiter:
    """Bounded per-source-IP sliding-window connection rate limiter (exempting loopback)."""

    def __init__(self, max_hits=20, window=10.0, max_ips=MAX_TRACKED_RATE_IPS):
        self._max_hits = max_hits
        self._window = window
        self._max_ips = max_ips
        self._hits = collections.OrderedDict()

    def allow(self, peer_ip, now=None):
        norm = normalize_ip(peer_ip)
        if not norm or _is_loopback_ip(norm):
            return True
        now = time.monotonic() if now is None else now
        cutoff = now - self._window
        dq = self._hits.get(norm)
        if dq is None:
            if len(self._hits) >= self._max_ips:
                self._hits.popitem(last=False)
            dq = collections.deque()
            self._hits[norm] = dq
        else:
            self._hits.move_to_end(norm)
            while dq and dq[0] <= cutoff:
                dq.popleft()
        if len(dq) >= self._max_hits:
            return False
        dq.append(now)
        return True


class _AuthFailureLimiter:
    """Bounded per-source-IP RFC 1929 auth failure blocker (exempting loopback)."""

    def __init__(self, max_failures=5, window=60.0, block_seconds=60.0, max_ips=MAX_TRACKED_RATE_IPS):
        self._max_failures = max_failures
        self._window = window
        self._block_seconds = block_seconds
        self._max_ips = max_ips
        self._failures = collections.OrderedDict()
        self._blocked_until = {}

    def is_blocked(self, peer_ip, now=None):
        norm = normalize_ip(peer_ip)
        if not norm or _is_loopback_ip(norm):
            return False
        now = time.monotonic() if now is None else now
        until = self._blocked_until.get(norm)
        if until is None:
            return False
        if now >= until:
            self._blocked_until.pop(norm, None)
            return False
        return True

    def record_failure(self, peer_ip, now=None):
        norm = normalize_ip(peer_ip)
        if not norm or _is_loopback_ip(norm):
            return
        now = time.monotonic() if now is None else now
        cutoff = now - self._window
        dq = self._failures.get(norm)
        if dq is None:
            if len(self._failures) >= self._max_ips:
                evicted, _ = self._failures.popitem(last=False)
                self._blocked_until.pop(evicted, None)
            dq = collections.deque()
            self._failures[norm] = dq
        else:
            self._failures.move_to_end(norm)
            while dq and dq[0] <= cutoff:
                dq.popleft()
        dq.append(now)
        if len(dq) >= self._max_failures:
            self._blocked_until[norm] = now + self._block_seconds

    def record_success(self, peer_ip):
        norm = normalize_ip(peer_ip)
        if not norm:
            return
        self._failures.pop(norm, None)
        self._blocked_until.pop(norm, None)


def _check_sleep_jump(last_mono, last_wall, now_mono, now_wall, threshold=SLEEP_JUMP_THRESHOLD):
    """True when host clock jumped (suspend/resume) across a heartbeat tick."""
    mono_dt = now_mono - last_mono
    wall_dt = now_wall - last_wall
    return mono_dt > threshold or abs(wall_dt - mono_dt) > threshold


def _recv_exact(conn, count):
    buf = bytearray()
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return b''
        buf.extend(chunk)
    return bytes(buf)


def socks_ready(port, auth=None, timeout=2.0):
    """True when 127.0.0.1:port completes the expected SOCKS5 handshake end-to-end.

    When `auth` is None, checks unauthenticated greeting.
    When `auth=(user, password)`, verifies no-auth is rejected (0x05 0xff)
    AND RFC 1929 username/password succeeds (0x01 0x00, which requires live GuestMux).
    """
    try:
        if auth is None:
            with socket.create_connection(('127.0.0.1', port), timeout=timeout) as conn:
                conn.sendall(b'\x05\x01\x00')
                return _recv_exact(conn, 2) == b'\x05\x00'

        user, password = auth
        # 1. Confirm unauthenticated method is rejected.
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as conn:
            conn.sendall(b'\x05\x01\x00')
            if _recv_exact(conn, 2) != b'\x05\xff':
                return False
        # 2. Confirm RFC 1929 username/password succeeds end-to-end (requiring live GuestMux).
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as conn:
            conn.sendall(b'\x05\x01\x02')
            if _recv_exact(conn, 2) != b'\x05\x02':
                return False
            u_bytes = user.encode('utf-8')
            p_bytes = password.encode('utf-8')
            conn.sendall(bytes([0x01, len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes)
            return _recv_exact(conn, 2) == b'\x01\x00'
    except OSError:
        return False


def socks_any_listener(port, timeout=1.0):
    """True if anything on 127.0.0.1:port speaks SOCKS5 (auth or no-auth)."""
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=timeout) as conn:
            conn.sendall(b'\x05\x01\x00')
            reply = _recv_exact(conn, 2)
            return len(reply) == 2 and reply[0] == 0x05
    except OSError:
        return False


def _port_listening(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.3):
            return True
    except OSError:
        return False


def _parse_pidfile(path):
    """Return (pid, engine_cli, accept_val, auth_hash, proto) from JSON or legacy pidfile."""
    try:
        raw = path.read_text(encoding='utf-8').strip()
    except OSError:
        return None, None, None, None, None
    if not raw:
        return None, None, None, None, None
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and isinstance(data.get('pid'), int):
            proto = data.get('proto', 1)
            return (
                data['pid'],
                data.get('engine'),
                data.get('accept', 'local'),
                data.get('auth_hash', ''),
                proto if isinstance(proto, int) else 1,
            )
        if isinstance(data, int):
            return data, None, None, None, 1
    except ValueError:
        pass
    try:
        return int(raw), None, None, None, 1
    except ValueError:
        return None, None, None, None, None


def _write_pidfile(profile, pid, engine_cli, mode='local', auth_hash='', proto=BRIDGE_PROTO):
    ensure_state_dir()
    payload = json.dumps({
        'pid': pid,
        'engine': engine_cli,
        'profile': profile,
        'accept': mode,
        'auth_hash': auth_hash,
        'proto': proto,
    }) + '\n'
    write_private_file(bridge_pidfile(profile), payload)


def _open_private_append(path):
    """Open `path` for binary append with 0600 permissions on POSIX (refusing symlinks)."""
    if os.name == 'nt':
        return path.open('ab')
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, 'ab')


def _enable_tcp_keepalive(sock, idle=60, interval=15, count=4):
    """Best-effort cross-platform TCP keepalive so dead peers do not leak sockets/tasks."""
    if sock is None:
        return
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if os.name == 'nt' and hasattr(socket, 'SIO_KEEPALIVE_VALS'):
        with contextlib.suppress(OSError, ValueError):
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, idle * 1000, interval * 1000))
        return
    keepidle = getattr(socket, 'TCP_KEEPIDLE', None)
    if keepidle is None:
        keepidle = getattr(socket, 'TCP_KEEPALIVE', None)
    if keepidle is not None:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, keepidle, idle)
    keepintvl = getattr(socket, 'TCP_KEEPINTVL', None)
    if keepintvl is not None:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, keepintvl, interval)
    keepcnt = getattr(socket, 'TCP_KEEPCNT', None)
    if keepcnt is not None:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, keepcnt, count)


def _pid_is_bridge_windows(pid, profile):
    """Verify on Windows that `pid` is still a live `zt bridge <profile>` process."""
    ps_bin = shutil.which('powershell') or shutil.which('pwsh')
    if ps_bin:
        try:
            proc = subprocess.run(
                [
                    ps_bin, '-NoProfile', '-NonInteractive', '-Command',
                    f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}').CommandLine",
                ],
                capture_output=True, text=True, check=False, timeout=5,
            )
            if proc.returncode == 0:
                tokens = proc.stdout.strip().split()
                if not tokens:
                    return False
                return tokens[-2:] == ['bridge', profile]
        except (OSError, subprocess.TimeoutExpired):
            pass

    tasklist = shutil.which('tasklist')
    if tasklist:
        try:
            proc = subprocess.run(
                [tasklist, '/FI', f'PID eq {int(pid)}', '/FO', 'CSV', '/NH'],
                capture_output=True, text=True, check=False, timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                rows = list(csv.reader(io.StringIO(proc.stdout.strip())))
                return bool(
                    rows
                    and len(rows[0]) >= 2
                    and rows[0][1].strip() == str(pid)
                    and 'python' in rows[0][0].lower()
                )
        except (OSError, subprocess.TimeoutExpired):
            pass
    return False


def _pid_is_bridge(pid, profile):
    if os.name == 'nt':
        return _pid_is_bridge_windows(pid, profile)
    ps = shutil.which('ps') or ('/bin/ps' if os.path.exists('/bin/ps') else None)
    if not ps:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    try:
        proc = subprocess.run(
            [ps, '-ww', '-p', str(pid), '-o', 'command='],
            capture_output=True, text=True, check=False, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and proc.stdout.split()[-2:] == ['bridge', profile]


def bridge_record(profile):
    """Return (pid, engine_cli, accept_val, auth_hash, proto) if live, else five Nones."""
    pid, recorded_engine, recorded_accept, recorded_auth, recorded_proto = _parse_pidfile(
        bridge_pidfile(profile)
    )
    if not pid:
        return None, None, None, None, None
    if _pid_is_bridge(pid, profile):
        return pid, recorded_engine, recorded_accept, recorded_auth, recorded_proto
    return None, None, None, None, None


def bridge_pid(profile, engine_cli=None):
    pid, recorded_engine, _, _, _ = bridge_record(profile)
    if not pid:
        return None
    if engine_cli is not None and recorded_engine != engine_cli:
        return None
    return pid


def bridge_matches(live_accept, live_hash, live_proto, mode, wanted_hash):
    """True when a running bridge matches the desired accept mode, password hash, and protocol."""
    return (
        live_accept == mode
        and live_hash == wanted_hash
        and live_proto == BRIDGE_PROTO
    )


def _bridge_command(profile):
    archive = zipapp_archive()
    if archive:
        return [sys.executable, archive, 'bridge', profile], None
    src_dir = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ)
    existing = env.get('PYTHONPATH', '')
    env['PYTHONPATH'] = f'{src_dir}{os.pathsep}{existing}' if existing else src_dir
    return [sys.executable, '-m', 'zt', 'bridge', profile], env


def _detached_popen_kwargs():
    if os.name == 'nt':
        # CREATE_NO_WINDOW and DETACHED_PROCESS are mutually exclusive in Win32 CreateProcess.
        flags = (
            getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
            | getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        return {'creationflags': flags}
    return {'start_new_session': True}


def _needs_vnc_front_proxy(mode):
    return mode in ('lan', 'all')


def bridge_start(engine, profile, mode=None, wait_seconds=45.0):
    """Start (or auto-heal/restart) the background multiplexed bridge."""
    mode = mode or accept_mode()
    password = auth_password(mode)
    wanted_hash = auth_fingerprint(mode, password)
    auth = (AUTH_USER, password) if password else None
    bind_host = bind_address(mode)
    port = socks_port(profile)
    vnc_fronted = _needs_vnc_front_proxy(mode)

    live_pid, live_engine, live_accept, live_hash, live_proto = bridge_record(profile)
    if live_pid:
        if live_engine != engine.cli:
            other = ENGINE_NAMES.get(live_engine, live_engine or 'another engine')
            return (
                f'{bind_host}:{port} is served by a zt bridge for {other} (pid {live_pid}), '
                f'not {engine.display_name}'
            )
        if bridge_matches(live_accept, live_hash, live_proto, mode, wanted_hash):
            desktop_ok = True if not vnc_fronted else _port_listening(desktop_port(profile))
            if desktop_ok and socks_ready(port, auth=auth):
                return None
            # Auto-heal hung or half-dead bridge instead of refusing recovery.
            warn(f'{profile}: restarting unresponsive bridge (pid {live_pid})')
            bridge_stop(profile, engine_cli=engine.cli)
        else:
            # Accept mode, password, or bridge protocol changed — restart cleanly (container stays up).
            bridge_stop(profile, engine_cli=engine.cli)

    if socks_any_listener(port):
        return (
            f'something else answers on 127.0.0.1:{port} '
            f'({engine.port_holders(port) or "a listener this user cannot see"}); '
            'it is not a bridge started by zt'
        )

    if vnc_fronted and _port_listening(desktop_port(profile)):
        dport = desktop_port(profile)
        return (
            f'something else answers on {bind_host}:{dport} '
            f'({engine.port_holders(dport) or "a listener this user cannot see"}); '
            f'cannot start the {mode} desktop proxy'
        )

    ensure_state_dir()
    cmd, base_env = _bridge_command(profile)
    child_env = dict(base_env if base_env is not None else os.environ)
    child_env['ZT_ENGINE'] = engine.cli
    child_env['ZT_ACCEPT'] = mode
    if password:
        child_env['ZT_VNC_PW'] = password
    else:
        child_env.pop('ZT_VNC_PW', None)

    with _open_private_append(bridge_logfile(profile)) as log:
        bridge = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            env=child_env,
            **_detached_popen_kwargs(),
        )
    _write_pidfile(profile, bridge.pid, engine.cli, mode, wanted_hash)

    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if bridge.poll() is not None:
            break
        desktop_ok = True if not vnc_fronted else _port_listening(desktop_port(profile))
        if desktop_ok and socks_ready(port, auth=auth):
            return None
        time.sleep(0.25)

    listening = _port_listening(port)
    still_alive = bridge.poll() is None
    if still_alive:
        # Clean up newly spawned unresponsive bridge so no orphan leaks.
        bridge_stop(profile, engine_cli=engine.cli)
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            bridge.wait(timeout=2.0)

    who = engine.port_holders(port) or 'a listener this user cannot see'
    if not still_alive and socks_any_listener(port):
        return (
            f'the bridge did not take {bind_host}:{port}, {who} answers there instead, '
            f'see {bridge_logfile(profile)}'
        )
    if still_alive and listening:
        return (
            f'the bridge listened on {bind_host}:{port}, but the guest mux inside '
            f'{container_name(profile)} did not complete a handshake in {int(wait_seconds)}s; '
            f'see {bridge_logfile(profile)}'
        )
    return f'the bridge did not answer on {bind_host}:{port}, see {bridge_logfile(profile)}'


def bridge_stop(profile, engine_cli=None):
    pid = bridge_pid(profile, engine_cli=engine_cli)
    if pid:
        if os.name == 'nt':
            try:
                subprocess.run(
                    ['taskkill', '/PID', str(pid), '/T', '/F'],
                    capture_output=True, check=False, timeout=10,
                )
                time.sleep(0.2)
            except (OSError, subprocess.TimeoutExpired):
                with contextlib.suppress(OSError):
                    os.kill(pid, signal.SIGTERM)
        else:
            try:
                os.kill(pid, signal.SIGTERM)
                deadline = time.monotonic() + 5.0
                while time.monotonic() < deadline and bridge_pid(profile, engine_cli=engine_cli):
                    time.sleep(0.1)
                if bridge_pid(profile, engine_cli=engine_cli):
                    os.kill(pid, signal.SIGKILL)
                    time.sleep(0.3)
            except OSError:
                pass
    if engine_cli is None or bridge_record(profile)[1] in (None, engine_cli):
        bridge_pidfile(profile).unlink(missing_ok=True)
        health_file(profile).unlink(missing_ok=True)


async def _read_socks5_noauth(reader, writer, timeout=SOCKS_HANDSHAKE_TIMEOUT):
    """Perform RFC 1928 method selection for unauthenticated (0x00) mode."""
    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        ver, nmethods = header[0], header[1]
        if ver != 0x05 or nmethods == 0:
            return False
        methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=timeout)
        if 0x00 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return False
        return True
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        return False


async def _read_socks5_credentials(reader, writer, timeout=SOCKS_HANDSHAKE_TIMEOUT):
    """Perform RFC 1928 method selection + read RFC 1929 (user, password) bytes."""
    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        ver, nmethods = header[0], header[1]
        if ver != 0x05 or nmethods == 0:
            return None
        methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=timeout)
        if 0x02 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return None
        writer.write(b'\x05\x02')
        await writer.drain()

        sub = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if sub[0] != 0x01:
            writer.write(b'\x01\x01')
            await writer.drain()
            return None
        uname = await asyncio.wait_for(reader.readexactly(sub[1]), timeout=timeout)
        plen = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
        passwd = await asyncio.wait_for(reader.readexactly(plen), timeout=timeout)
        return uname, passwd
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        return None


async def _read_socks5_addr_port_raw(reader, initial=b'', timeout=SOCKS_HANDSHAKE_TIMEOUT):
    """Read RFC 1928 ATYP+ADDR+PORT returning (atyp, host, port, raw_bytes) or None."""
    buf = bytearray(initial)
    consumed = bytearray()

    async def take(count):
        if len(buf) < count:
            need = count - len(buf)
            buf.extend(await asyncio.wait_for(reader.readexactly(need), timeout=timeout))
        out = bytes(buf[:count])
        del buf[:count]
        consumed.extend(out)
        return out

    try:
        atyp = (await take(1))[0]
        if atyp == ATYP_IPV4:
            raw = await take(6)
            return atyp, socket.inet_ntop(socket.AF_INET, raw[:4]), (raw[4] << 8) | raw[5], bytes(consumed)
        if atyp == ATYP_IPV6:
            raw = await take(18)
            return atyp, socket.inet_ntop(socket.AF_INET6, raw[:16]), (raw[16] << 8) | raw[17], bytes(consumed)
        if atyp == ATYP_DOMAIN:
            dlen = (await take(1))[0]
            if dlen == 0:
                return None
            raw = await take(dlen + 2)
            if b'\x00' in raw[:dlen]:
                return None
            try:
                host = raw[:dlen].decode('utf-8')
            except UnicodeDecodeError:
                return None
            if not host or any(ch.isspace() for ch in host):
                return None
            return atyp, host, (raw[dlen] << 8) | raw[dlen + 1], bytes(consumed)
        return 'unsupported', None, 0, bytes(consumed)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        return None


async def _read_socks5_addr_port(reader, initial=b'', timeout=SOCKS_HANDSHAKE_TIMEOUT):
    """Read RFC 1928 ATYP+ADDR+PORT returning (atyp, host, port) or None."""
    parsed = await _read_socks5_addr_port_raw(reader, initial=initial, timeout=timeout)
    if parsed is None:
        return None
    return parsed[0], parsed[1], parsed[2]


def _socks5_reply(rep, host='0.0.0.0', port=0):
    return b'\x05' + bytes([rep, 0x00]) + encode_socks_addr(host, port)


def _bind_udp_socket(local_ip, scope_id=0):
    """Bind a non-blocking host UDP relay socket on `local_ip:0` (Windows & IPv6 link-local safe)."""
    ip = ipaddress.ip_address(local_ip)
    family = socket.AF_INET6 if isinstance(ip, ipaddress.IPv6Address) else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        if family == socket.AF_INET6:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        if os.name == 'nt' and hasattr(socket, 'SIO_UDP_CONNRESET'):
            with contextlib.suppress(OSError, ValueError):
                sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        if family == socket.AF_INET6 and ip.is_link_local and scope_id:
            sock.bind((local_ip, 0, 0, scope_id))
        else:
            sock.bind((local_ip, 0))
    except BaseException:
        sock.close()
        raise
    return sock


async def _start_dual_stack_servers(handler, bind_host, port):
    """Start primary IPv4 TCP server plus best-effort companion IPv6 (IPV6_V6ONLY) listener.

    On IPv4-only hosts (or when IPv6 address is unavailable), falls back silently to IPv4
    without leaking sockets or raising warnings.
    """
    primary = await asyncio.start_server(handler, bind_host, port)
    servers = [primary]
    v6_host = '::1' if bind_host == '127.0.0.1' else ('::' if bind_host == '0.0.0.0' else None)
    if v6_host is None or not getattr(socket, 'has_ipv6', False):
        return servers
    v6_sock = None
    try:
        v6_sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        v6_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        v6_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        v6_sock.bind((v6_host, port))
        v6_sock.setblocking(False)
        v6_srv = await asyncio.start_server(handler, sock=v6_sock)
        v6_sock = None  # Ownership transferred to asyncio Server.
        servers.append(v6_srv)
    except OSError:
        if v6_sock is not None:
            v6_sock.close()
    except BaseException:
        if v6_sock is not None:
            v6_sock.close()
        primary.close()
        await primary.wait_closed()
        raise
    return servers


class _HostUDPProtocol(asyncio.DatagramProtocol):
    """Host-side SOCKS5 UDP relay enforcing peer-IP verification and RFC 1928 §7."""

    def __init__(self, expected_ip, expected_port, tx_queue, on_client_addr):
        self._expected_ip = expected_ip
        self._expected_port = expected_port
        self._tx_queue = tx_queue
        self._on_client_addr = on_client_addr

    def datagram_received(self, data, addr):
        src_ip = normalize_ip(addr[0])
        if src_ip != self._expected_ip:
            return
        if self._expected_port is not None and addr[1] != self._expected_port:
            return
        if len(data) < 4 or data[0] != 0 or data[1] != 0 or data[2] != 0:
            # RFC 1928 §7: drop malformed RSV or fragmented (FRAG != 0) datagrams.
            return
        body = data[3:]
        parsed = parse_socks_addr(body)
        if parsed is None:
            return
        _, _, dst_port, data_offset = parsed
        if dst_port == 0 or len(body) - data_offset > MAX_UDP_PAYLOAD:
            return
        self._on_client_addr(addr)
        with contextlib.suppress(asyncio.QueueFull):
            self._tx_queue.put_nowait(body)

    def error_received(self, exc):
        # Ignore transient ICMP Port Unreachable / Winsock WSAECONNRESET.
        pass


class HostMuxTunnel:
    """Single persistent `CLI exec ... python3 -c <mux>` tunnel multiplexing TCP + UDP + callbacks."""

    def __init__(
        self,
        engine,
        name,
        auth=None,
        mux_source=None,
        profile=None,
        callback_ports=None,
        heartbeat_interval=HEARTBEAT_INTERVAL,
        heartbeat_timeout=HEARTBEAT_TIMEOUT,
        boot_refresh_delays=BOOT_REFRESH_DELAYS,
        callback_ttl=CALLBACK_TTL_SECONDS,
        max_tcp_streams=MAX_TCP_STREAMS,
        auth_limiter=None,
        health_path=None,
    ):
        self.engine = engine
        self.name = name
        self.profile = profile
        self.auth = auth  # None or (username, password)
        self._mux_source = mux_source if mux_source is not None else guest_script('mux')
        raw_cb = callback_ports_for(profile) if callback_ports is None else callback_ports
        self.callback_ports = tuple(sorted({
            int(p) for p in raw_cb if int(p) in STATIC_CALLBACK_ALLOWLIST
        }))
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._boot_refresh_delays = tuple(sorted(d for d in (boot_refresh_delays or ()) if d > 0))
        self._callback_ttl = callback_ttl
        self._max_tcp_streams = max_tcp_streams
        self._auth_limiter = auth_limiter if auth_limiter is not None else _AuthFailureLimiter()
        self._health_path = health_path

        self._process = None
        self._epoch = 0
        self._connected_at = 0.0
        self._active_procs = set()
        self._bg_tasks = set()
        self._reader_task = None
        self._stderr_task = None
        self._heartbeat_task = None
        self._connect_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._ping_lock = asyncio.Lock()
        self._pong_waiter = None
        self._streams = {}
        self._pending_opens = {}
        self._udp_handlers = {}
        self._next_id = 1
        self._closing = False

        self._backoff = 0.0
        self._next_connect_after = 0.0
        self._last_health = None
        self._sso_url = ''
        self._sso_ts = 0
        self._callback_servers = {}
        self._callback_until = 0.0
        self._callback_timer = None
        self._callback_conns = set()

    def _alloc_id(self):
        for _ in range(10000):
            sid = self._next_id
            self._next_id = (self._next_id % 0x7FFFFFFF) + 1
            if (
                sid not in self._streams
                and sid not in self._pending_opens
                and sid not in self._udp_handlers
            ):
                return sid
        raise RuntimeError('exhausted stream ids')

    async def _spawn_process(self):
        cmd = [
            self.engine.cli, 'exec', '--interactive', '--user', 'nobody', self.name,
            '/usr/bin/python3', '-c', self._mux_source,
        ]
        if self.profile:
            cmd += ['--profile', self.profile]
        if self.callback_ports:
            cmd += ['--callback-ports', ','.join(str(p) for p in self.callback_ports)]
        return await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def _reap_process(self, proc, force=False):
        """Close stdin, terminate/kill if still running, and await wait() so no zombie leaks."""
        if proc is None:
            return
        try:
            if proc.stdin is not None and not proc.stdin.is_closing():
                with contextlib.suppress(OSError):
                    proc.stdin.close()
            if proc.returncode is None:
                if force:
                    with contextlib.suppress(ProcessLookupError, OSError):
                        proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError, OSError):
                        proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        with contextlib.suppress(ProcessLookupError, OSError):
                            proc.kill()
                        with contextlib.suppress(ProcessLookupError, OSError):
                            await proc.wait()
            else:
                with contextlib.suppress(ProcessLookupError, OSError):
                    await proc.wait()
        finally:
            if proc.returncode is not None:
                self._active_procs.discard(proc)

    def _track_bg(self, coro):
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    def _schedule_send_if_open(self, stream_id, kind, payload=b'', proc=None):
        """Schedule a non-blocking teardown frame while tracking the task to prevent leaks."""
        self._track_bg(self.send_if_open(stream_id, kind, payload, proc=proc))

    def _fail_waiters(self, reason='mux tunnel closed'):
        for fut in list(self._pending_opens.values()):
            if not fut.done():
                fut.set_result((RST, b''))
        self._pending_opens.clear()
        waiter = self._pong_waiter
        self._pong_waiter = None
        if waiter is not None and not waiter.done():
            waiter.set_exception(ConnectionError(reason))

    async def _reset_tunnel(self, proc):
        if proc is None:
            return
        if self._process is proc:
            self._process = None
        for state in list(self._streams.values()):
            state.close_rst()
        for _, on_close in list(self._udp_handlers.values()):
            on_close()
        self._fail_waiters('mux tunnel reset')
        await self._reap_process(proc, force=True)

    async def ensure_connected(self):
        proc = self._process
        if proc is not None and proc.returncode is None:
            return proc
        async with self._connect_lock:
            proc = self._process
            if proc is not None and proc.returncode is None:
                return proc
            if self._closing:
                raise ConnectionError('bridge is shutting down')
            now = time.monotonic()
            if now < self._next_connect_after:
                raise ConnectionError('mux reconnect backing off')
            proc = await self._spawn_process()
            self._process = proc
            self._active_procs.add(proc)
            stderr_task = asyncio.create_task(self._drain_stderr(proc))
            self._stderr_task = stderr_task
            self._reader_task = asyncio.create_task(self._read_loop(proc, stderr_task))
            try:
                await self.ping(proc=proc, timeout=self._heartbeat_timeout)
            except (ConnectionError, OSError, asyncio.TimeoutError):
                await self._reset_tunnel(proc)
                self._backoff = min(2.0, self._backoff * 2.0 if self._backoff else 0.25)
                self._next_connect_after = time.monotonic() + self._backoff
                raise ConnectionError('guest mux did not answer PING')
            self._epoch += 1
            self._connected_at = time.monotonic()
            self._backoff = 0.0
            self._next_connect_after = 0.0
            return proc

    async def ping(self, proc=None, timeout=None):
        """Send a PING frame on `proc` and await its PONG health response."""
        target = proc if proc is not None else self._process
        if target is None or target.returncode is not None:
            raise ConnectionError('mux tunnel closed')
        timeout = self._heartbeat_timeout if timeout is None else timeout
        async with self._ping_lock:
            if self._process is not target or target.returncode is not None:
                raise ConnectionError('mux tunnel closed')
            loop = asyncio.get_running_loop()
            waiter = loop.create_future()
            self._pong_waiter = waiter
            try:
                await self.send_on(target, 0, PING)
                return await asyncio.wait_for(waiter, timeout=timeout)
            finally:
                if self._pong_waiter is waiter:
                    self._pong_waiter = None

    def _resolved_health_path(self):
        if self._health_path is not None:
            return Path(self._health_path)
        if self.profile:
            return health_file(self.profile)
        return None

    def _persist_health(self, guest_data=None):
        path = self._resolved_health_path()
        now = int(time.time())
        record = dict(self._last_health or {})
        if isinstance(guest_data, dict):
            record.update(guest_data)
        if self._sso_url and (now - self._sso_ts) <= 300:
            if record.get('vpn') != 'connected':
                record['sso_url'] = self._sso_url
                record['sso_ts'] = self._sso_ts
                if record.get('vpn') in (None, '', 'disconnected'):
                    record['vpn'] = 'sso-pending'
            else:
                self._sso_url = ''
                self._sso_ts = 0
                record.pop('sso_url', None)
                record.pop('sso_ts', None)
        elif self._sso_url:
            self._sso_url = ''
            self._sso_ts = 0
            record.pop('sso_url', None)
            record.pop('sso_ts', None)

        record['updated_at'] = now
        record['bridge_pid'] = os.getpid()
        if self._callback_until > time.monotonic() and self._callback_servers:
            record['callback_ports'] = sorted(self._callback_servers)
            record['callback_until'] = int(time.time() + max(0.0, self._callback_until - time.monotonic()))
        else:
            record.pop('callback_ports', None)
            record.pop('callback_until', None)

        self._last_health = record
        if path is not None:
            with contextlib.suppress(OSError):
                write_private_file(path, json.dumps(record, sort_keys=True) + '\n')

    def _on_pong(self, payload):
        parsed = {}
        if payload:
            try:
                data = json.loads(payload.decode('utf-8'))
                if isinstance(data, dict):
                    parsed = data
            except (UnicodeDecodeError, ValueError):
                parsed = {}
        self._persist_health(parsed)
        waiter = self._pong_waiter
        if waiter is not None and not waiter.done():
            waiter.set_result(self._last_health)

    def _on_open_url(self, payload):
        try:
            data = json.loads(payload.decode('utf-8'))
        except (UnicodeDecodeError, ValueError):
            return
        if not isinstance(data, dict):
            return
        url = sanitize_sso_url(data.get('url'))
        if not url:
            return
        self._sso_url = url
        self._sso_ts = int(data.get('ts') or int(time.time()))
        # NEVER auto-launch a host browser; record URL for `zt status` and arm loopback callbacks.
        self._persist_health()
        if self.callback_ports and not self._closing:
            self._track_bg(self.arm_callbacks())

    def _on_callback_req(self):
        if self.callback_ports and not self._closing:
            self._track_bg(self.arm_callbacks())

    async def arm_callbacks(self, ttl=None):
        """Bind host 127.0.0.1:<cb_port> on demand for `ttl` seconds (never 0.0.0.0)."""
        if self._closing or not self.callback_ports:
            return ()
        ttl = self._callback_ttl if ttl is None else float(ttl)
        self._callback_until = max(self._callback_until, time.monotonic() + ttl)
        bound = []
        for cb_port in self.callback_ports:
            if cb_port in self._callback_servers:
                bound.append(cb_port)
                continue
            try:
                srv = await asyncio.start_server(
                    lambda r, w, p=cb_port: self._accept_callback(p, r, w),
                    '127.0.0.1',
                    cb_port,
                )
            except OSError as exc:
                warn(
                    f'bridge({self.name}): cannot bind SSO callback 127.0.0.1:{cb_port} '
                    f'({exc.strerror or exc}); SOCKS5 remains active'
                )
                continue
            self._callback_servers[cb_port] = srv
            bound.append(cb_port)
            say(f'SSO callback 127.0.0.1:{cb_port} -> {self.name} (loopback only, {int(ttl)}s TTL)')

        if self._callback_timer is not None and not self._callback_timer.done():
            self._callback_timer.cancel()
        if self._callback_servers:
            self._callback_timer = self._track_bg(self._callback_expiry_loop())
        self._persist_health()
        return tuple(bound)

    async def _callback_expiry_loop(self):
        try:
            while True:
                remaining = self._callback_until - time.monotonic()
                if remaining <= 0:
                    break
                await asyncio.sleep(min(remaining, 10.0))
        except asyncio.CancelledError:
            return
        await self._close_callback_servers()
        self._persist_health()

    async def _close_callback_servers(self):
        servers = list(self._callback_servers.values())
        self._callback_servers.clear()
        self._callback_until = 0.0
        for srv in servers:
            srv.close()
        for srv in servers:
            with contextlib.suppress(OSError):
                await srv.wait_closed()

    async def _accept_callback(self, cb_port, reader, writer):
        task = asyncio.current_task()
        self._callback_conns.add(task)
        try:
            await self._handle_callback_client(cb_port, reader, writer)
        finally:
            self._callback_conns.discard(task)

    async def _handle_callback_client(self, cb_port, reader, writer):
        stream_id = None
        bound_proc = None
        opened = False
        _enable_tcp_keepalive(writer.get_extra_info('socket'))
        try:
            if cb_port not in self.callback_ports or len(self._streams) >= self._max_tcp_streams:
                return
            bound_proc = await self.ensure_connected()
            stream_id = self._alloc_id()
            state = StreamState()
            open_fut = asyncio.get_running_loop().create_future()
            self._streams[stream_id] = state
            self._pending_opens[stream_id] = open_fut
            await self.send_on(bound_proc, stream_id, CALLBACK_OPEN, PORT_STRUCT.pack(cb_port))
            kind, _payload = await asyncio.wait_for(open_fut, timeout=10.0)
            if kind != OPEN_OK:
                return
            opened = True
            await self._splice_host_stream(bound_proc, stream_id, state, reader, writer)
        except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.CancelledError):
            if opened and stream_id is not None:
                await self.send_if_open(stream_id, RST, proc=bound_proc)
        finally:
            if stream_id is not None:
                self._pending_opens.pop(stream_id, None)
                self._streams.pop(stream_id, None)
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    def start_heartbeat(self):
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        return self._heartbeat_task

    async def _heartbeat_loop(self):
        last_mono = time.monotonic()
        last_wall = time.time()
        last_ping = last_mono
        seen_epoch = self._epoch
        pending_boot_delays = list(self._boot_refresh_delays) if self._process is not None else []
        min_period = min(
            (self._heartbeat_interval, *(self._boot_refresh_delays or (self._heartbeat_interval,))),
        )
        tick = min(1.0, max(0.05, min_period / 2.0))
        try:
            while not self._closing:
                await asyncio.sleep(tick)
                now_mono = time.monotonic()
                now_wall = time.time()
                woke = _check_sleep_jump(last_mono, last_wall, now_mono, now_wall)
                last_mono = now_mono
                last_wall = now_wall

                if self._epoch != seen_epoch:
                    seen_epoch = self._epoch
                    pending_boot_delays = list(self._boot_refresh_delays) if self._process is not None else []
                    last_ping = self._connected_at or now_mono

                # Fast post-start health refresh (e.g. ~3s and ~6s) while container services settle.
                boot_due = False
                if pending_boot_delays and self._process is not None:
                    cur_vpn = (self._last_health or {}).get('vpn')
                    if cur_vpn in ('connected', 'sso-pending'):
                        pending_boot_delays.clear()
                    elif (now_mono - self._connected_at) >= pending_boot_delays[0]:
                        pending_boot_delays.pop(0)
                        boot_due = True

                due = (now_mono - last_ping) >= self._heartbeat_interval
                if not woke and not due and not boot_due:
                    continue
                proc = self._process
                if proc is None:
                    if woke:
                        self._backoff = 0.0
                        self._next_connect_after = 0.0
                        with contextlib.suppress(ConnectionError, OSError):
                            await self.ensure_connected()
                        last_ping = time.monotonic()
                    continue
                last_ping = now_mono
                try:
                    await self.ping(proc=proc, timeout=self._heartbeat_timeout)
                except (ConnectionError, OSError, asyncio.TimeoutError):
                    reason = 'host sleep-wake' if woke else 'heartbeat timeout'
                    warn(f'bridge({self.name}): {reason}; resetting mux tunnel')
                    await self._reset_tunnel(proc)
                    self._backoff = 0.0
                    self._next_connect_after = 0.0
                    if not self._closing:
                        with contextlib.suppress(ConnectionError, OSError):
                            await self.ensure_connected()
        except asyncio.CancelledError:
            return

    async def _drain_stderr(self, proc):
        try:
            while proc.stderr is not None:
                line = await proc.stderr.readline()
                if not line:
                    break
                text = line.decode(errors='replace').rstrip()
                if text:
                    warn(f'bridge({self.name}): {text}')
        except (OSError, asyncio.CancelledError):
            pass

    async def _read_loop(self, proc, stderr_task=None):
        protocol_error = False
        try:
            while True:
                frame = await read_frame(proc.stdout)
                if frame is None:
                    break
                stream_id, kind, payload = frame
                if kind == PONG:
                    self._on_pong(payload)
                    continue
                if kind == OPEN_URL:
                    self._on_open_url(payload)
                    continue
                if kind == CALLBACK_REQ:
                    self._on_callback_req()
                    continue
                if kind in (OPEN_OK, OPEN_ERR):
                    fut = self._pending_opens.pop(stream_id, None)
                    if fut is not None and not fut.done():
                        fut.set_result((kind, payload))
                    continue
                if kind == UDP_DATA:
                    handler = self._udp_handlers.get(stream_id)
                    if handler is not None:
                        handler[0](payload)
                    continue
                if kind == UDP_CLOSE:
                    handler = self._udp_handlers.get(stream_id)
                    if handler is not None:
                        handler[1]()
                    continue
                if kind == RST and stream_id in self._udp_handlers:
                    self._udp_handlers[stream_id][1]()
                    continue
                state = self._streams.get(stream_id)
                if state is None:
                    continue
                if kind == DATA:
                    if not state.push_data(payload):
                        # Peer violated stream window cap: RST only this stream, never stall demux.
                        self._streams.pop(stream_id, None)
                        self._schedule_send_if_open(stream_id, RST, proc=proc)
                elif kind == EOF:
                    state.push_eof()
                elif kind == WINDOW_UPDATE:
                    if len(payload) == WIN_STRUCT.size:
                        state.add_window(WIN_STRUCT.unpack(payload)[0])
                elif kind == RST:
                    state.close_rst()
        except ValueError as exc:
            protocol_error = True
            warn(f'bridge({self.name}): mux protocol desync ({exc}); resetting tunnel')
        except OSError:
            protocol_error = True
        except asyncio.CancelledError:
            pass
        finally:
            if self._process is proc:
                self._process = None
            for state in list(self._streams.values()):
                state.close_rst()
            for _, on_close in list(self._udp_handlers.values()):
                on_close()
            self._fail_waiters('mux tunnel closed')
            if not self._closing:
                await self._reap_process(proc, force=protocol_error)
                if stderr_task is not None and not stderr_task.done():
                    try:
                        await asyncio.wait_for(asyncio.shield(stderr_task), timeout=1.0)
                    except (asyncio.TimeoutError, asyncio.CancelledError, OSError):
                        stderr_task.cancel()
                        with contextlib.suppress(asyncio.CancelledError, OSError):
                            await stderr_task

    async def send_on(self, proc, stream_id, kind, payload=b''):
        """Send a frame strictly on `proc` (never respawning a new tunnel mid-stream)."""
        if (
            proc is None
            or self._process is not proc
            or proc.returncode is not None
            or proc.stdin is None
            or proc.stdin.is_closing()
        ):
            raise ConnectionError('mux tunnel closed')
        frame = encode_frame(stream_id, kind, payload)
        async with self._write_lock:
            if (
                self._process is not proc
                or proc.returncode is not None
                or proc.stdin is None
                or proc.stdin.is_closing()
            ):
                raise ConnectionError('mux tunnel closed')
            proc.stdin.write(frame)
            try:
                await asyncio.wait_for(proc.stdin.drain(), timeout=PIPE_WRITE_TIMEOUT)
            except asyncio.TimeoutError:
                self._track_bg(self._reset_tunnel(proc))
                raise ConnectionError('mux tunnel write timed out')

    async def send(self, stream_id, kind, payload=b''):
        proc = await self.ensure_connected()
        await self.send_on(proc, stream_id, kind, payload)

    async def send_if_open(self, stream_id, kind, payload=b'', proc=None):
        """Send a teardown frame only when the bound mux process is still live (never respawn)."""
        target = self._process if proc is None else proc
        if (
            target is None
            or self._process is not target
            or target.returncode is not None
            or target.stdin is None
            or target.stdin.is_closing()
        ):
            return
        frame = encode_frame(stream_id, kind, payload)
        try:
            async with self._write_lock:
                if (
                    self._process is not target
                    or target.returncode is not None
                    or target.stdin is None
                    or target.stdin.is_closing()
                ):
                    return
                target.stdin.write(frame)
                await asyncio.wait_for(target.stdin.drain(), timeout=PIPE_WRITE_TIMEOUT)
        except (BrokenPipeError, ConnectionError, OSError, asyncio.TimeoutError):
            return

    async def _splice_host_stream(self, bound_proc, stream_id, state, reader, writer):
        async def send_bound(sid, kind, data=b''):
            await self.send_on(bound_proc, sid, kind, data)

        async def host_to_guest():
            while True:
                data = await reader.read(65536)
                if not data:
                    await self.send_on(bound_proc, stream_id, EOF)
                    return
                if not await send_stream_data(send_bound, stream_id, state, data):
                    return

        async def guest_to_host():
            pending_win = 0
            while True:
                kind, payload = await state.recv()
                if kind == DATA:
                    writer.write(payload)
                    await writer.drain()
                    pending_win += len(payload)
                    if pending_win >= WINDOW_REPLENISH:
                        inc = pending_win
                        pending_win = 0
                        await self.send_on(bound_proc, stream_id, WINDOW_UPDATE, WIN_STRUCT.pack(inc))
                elif kind == EOF:
                    if writer.can_write_eof():
                        with contextlib.suppress(ConnectionError, OSError):
                            writer.write_eof()
                    return
                elif kind == RST:
                    return

        await splice_tasks(host_to_guest(), guest_to_host(), drain_timeout=300)

    async def _handle_udp_associate(self, bound_proc, reader, writer, atyp, req_host, req_port):
        if atyp == 'unsupported':
            writer.write(_socks5_reply(REP_ATYP_NOT_SUPPORTED))
            await writer.drain()
            return

        if len(self._udp_handlers) >= MAX_UDP_ASSOCS:
            writer.write(_socks5_reply(REP_GENERAL_FAILURE))
            await writer.drain()
            return

        sockname = writer.get_extra_info('sockname')
        peername = writer.get_extra_info('peername')
        local_ip = normalize_ip(sockname[0]) if sockname else None
        peer_ip = normalize_ip(peername[0]) if peername else None
        if not local_ip or not peer_ip:
            writer.write(_socks5_reply(REP_GENERAL_FAILURE))
            await writer.drain()
            return

        # Pin client UDP source port only when explicitly requested and not NAT-rewritten.
        expected_port = None
        if req_port != 0:
            req_norm = normalize_ip(req_host) if atyp in (ATYP_IPV4, ATYP_IPV6) else None
            if req_norm in ('0.0.0.0', '::', peer_ip):
                expected_port = req_port

        udp_transport = None
        udp_sid = None
        tasks = ()
        opened_udp = False
        try:
            loop = asyncio.get_running_loop()
            tx_queue = asyncio.Queue(maxsize=UDP_QUEUE_SIZE)
            closed_event = asyncio.Event()
            client_addr = [None]

            def set_client_addr(addr):
                client_addr[0] = addr

            scope_id = sockname[3] if (sockname and len(sockname) >= 4) else 0
            sock = _bind_udp_socket(local_ip, scope_id=scope_id)
            bound_port = sock.getsockname()[1]
            try:
                udp_transport, _ = await loop.create_datagram_endpoint(
                    lambda: _HostUDPProtocol(peer_ip, expected_port, tx_queue, set_client_addr),
                    sock=sock,
                )
            except BaseException:
                sock.close()
                raise

            def on_guest_datagram(payload):
                target = client_addr[0]
                if target is None or udp_transport is None or udp_transport.is_closing():
                    return
                with contextlib.suppress(OSError):
                    udp_transport.sendto(b'\x00\x00\x00' + payload, target)

            def on_tunnel_close():
                closed_event.set()

            udp_sid = self._alloc_id()
            self._udp_handlers[udp_sid] = (on_guest_datagram, on_tunnel_close)
            await self.send_on(bound_proc, udp_sid, UDP_OPEN)
            opened_udp = True

            writer.write(_socks5_reply(0x00, local_ip, bound_port))
            await writer.drain()

            _enable_tcp_keepalive(writer.get_extra_info('socket'))

            async def tx_pump():
                while True:
                    body = await tx_queue.get()
                    await self.send_on(bound_proc, udp_sid, UDP_DATA, body)

            async def watch_tcp_control():
                while await reader.read(1024):
                    pass

            tx_task = asyncio.create_task(tx_pump())
            ctrl_task = asyncio.create_task(watch_tcp_control())
            close_wait = asyncio.create_task(closed_event.wait())
            tasks = (tx_task, ctrl_task, close_wait)
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            for task in done:
                if not task.cancelled():
                    with contextlib.suppress(ConnectionError, OSError):
                        task.result()
        except OSError:
            if not opened_udp:
                with contextlib.suppress(ConnectionError, OSError):
                    writer.write(_socks5_reply(REP_GENERAL_FAILURE))
                    await writer.drain()
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if udp_transport is not None:
                udp_transport.close()
            if udp_sid is not None:
                self._udp_handlers.pop(udp_sid, None)
            if opened_udp and udp_sid is not None:
                with contextlib.suppress(ConnectionError, OSError):
                    await self.send_if_open(udp_sid, UDP_CLOSE, proc=bound_proc)

    async def handle_client(self, reader, writer):
        stream_id = None
        bound_proc = None
        opened = False
        _enable_tcp_keepalive(writer.get_extra_info('socket'))
        peername = writer.get_extra_info('peername')
        peer_ip = peername[0] if peername else None
        try:
            if self.auth is not None:
                if self._auth_limiter.is_blocked(peer_ip):
                    return
                creds = await _read_socks5_credentials(reader, writer)
                if creds is None:
                    return
                uname, passwd = creds
                want_u, want_p = self.auth
                valid = (
                    hmac.compare_digest(uname, want_u.encode('utf-8'))
                    and hmac.compare_digest(passwd, want_p.encode('utf-8'))
                )
                if not valid:
                    self._auth_limiter.record_failure(peer_ip)
                    writer.write(b'\x01\x01')
                    await writer.drain()
                    return
                self._auth_limiter.record_success(peer_ip)
            else:
                if not await _read_socks5_noauth(reader, writer):
                    return

            # Ensure live GuestMux before completing greeting so `socks_ready()` checks guest liveness.
            bound_proc = await self.ensure_connected()
            writer.write(b'\x01\x00' if self.auth is not None else b'\x05\x00')
            await writer.drain()

            # Read RFC 1928 request header (VER, CMD, RSV) with bounded handshake timeout.
            try:
                req_hdr = await asyncio.wait_for(reader.readexactly(3), timeout=SOCKS_HANDSHAKE_TIMEOUT)
            except asyncio.IncompleteReadError as exc:
                if not exc.partial:
                    return  # Clean probe EOF (e.g. `socks_ready`)
                return
            ver, cmd, rsv = req_hdr[0], req_hdr[1], req_hdr[2]
            if ver != 0x05 or rsv != 0x00:
                return

            parsed = await _read_socks5_addr_port_raw(reader, timeout=SOCKS_HANDSHAKE_TIMEOUT)
            if parsed is None:
                return
            atyp, req_host, req_port, raw_addr = parsed

            if cmd == 0x03:
                await self._handle_udp_associate(bound_proc, reader, writer, atyp, req_host, req_port)
                return

            if cmd != 0x01:
                writer.write(_socks5_reply(REP_CMD_NOT_SUPPORTED))
                await writer.drain()
                return

            if atyp == 'unsupported':
                writer.write(_socks5_reply(REP_ATYP_NOT_SUPPORTED))
                await writer.drain()
                return

            if req_port == 0 or len(self._streams) >= self._max_tcp_streams:
                writer.write(_socks5_reply(REP_GENERAL_FAILURE))
                await writer.drain()
                return

            stream_id = self._alloc_id()
            state = StreamState()
            open_fut = asyncio.get_running_loop().create_future()
            self._streams[stream_id] = state
            self._pending_opens[stream_id] = open_fut
            await self.send_on(bound_proc, stream_id, TCP_OPEN, raw_addr)
            opened = True

            kind, payload = await asyncio.wait_for(open_fut, timeout=TCP_OPEN_TIMEOUT)
            if kind == OPEN_ERR:
                opened = False
                rep = payload[0] if payload else REP_GENERAL_FAILURE
                writer.write(_socks5_reply(rep))
                await writer.drain()
                return
            if kind != OPEN_OK:
                opened = False
                writer.write(_socks5_reply(REP_GENERAL_FAILURE))
                await writer.drain()
                return

            writer.write(b'\x05\x00\x00' + payload)
            await writer.drain()
            await self._splice_host_stream(bound_proc, stream_id, state, reader, writer)
        except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.CancelledError):
            if opened and stream_id is not None:
                with contextlib.suppress(ConnectionError, OSError):
                    await self.send_if_open(stream_id, RST, proc=bound_proc)
        finally:
            if stream_id is not None:
                self._pending_opens.pop(stream_id, None)
                self._streams.pop(stream_id, None)
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def close(self):
        self._closing = True
        if self._heartbeat_task is not None and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
        if self._callback_timer is not None and not self._callback_timer.done():
            self._callback_timer.cancel()
        for task in list(self._callback_conns):
            if not task.done():
                task.cancel()
        if self._callback_conns:
            await asyncio.gather(*list(self._callback_conns), return_exceptions=True)
        await self._close_callback_servers()
        self._fail_waiters('bridge is shutting down')

        proc = self._process
        self._process = None
        procs = list(self._active_procs)
        if proc is not None and proc not in procs:
            procs.append(proc)
        for p in procs:
            await self._reap_process(p)

        tasks = [
            t for t in (
                self._heartbeat_task,
                self._reader_task,
                self._stderr_task,
                *list(self._bg_tasks),
            )
            if t is not None
        ]
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._bg_tasks.clear()


async def _splice_tcp(reader, writer, target_host, target_port):
    """Raw bidirectional TCP forwarder (used for `accept lan` and `accept all` VNC front proxy)."""
    backend_writer = None
    _enable_tcp_keepalive(writer.get_extra_info('socket'))
    try:
        backend_reader, backend_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port), timeout=5.0,
        )
        _enable_tcp_keepalive(backend_writer.get_extra_info('socket'))

        async def pump(src, dst):
            while data := await src.read(65536):
                dst.write(data)
                await dst.drain()
            if dst.can_write_eof():
                with contextlib.suppress(ConnectionError, OSError):
                    dst.write_eof()

        await splice_tasks(pump(reader, backend_writer), pump(backend_reader, writer), drain_timeout=30)
    except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.CancelledError):
        pass
    finally:
        for sock in (backend_writer, writer):
            if sock is not None:
                sock.close()
                with contextlib.suppress(ConnectionError, OSError):
                    await sock.wait_closed()


def _peer_allowed(writer, lan_only):
    if not lan_only:
        return True
    peer = writer.get_extra_info('peername')
    return bool(peer and is_lan_ip(peer[0]))


def _install_stop_handlers(loop, stopped):
    """Register cross-platform signal handlers (POSIX event-loop or Windows signal.signal)."""
    if os.name == 'nt':
        def _on_signal(_signum, _frame):
            loop.call_soon_threadsafe(stopped.set)

        for name in ('SIGINT', 'SIGTERM', 'SIGBREAK'):
            sig = getattr(signal, name, None)
            if sig is not None:
                with contextlib.suppress(OSError, ValueError):
                    signal.signal(sig, _on_signal)
    else:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stopped.set)


async def serve(engine, name, port, bind_host='127.0.0.1', auth=None,
                lan_only=False, vnc_front_port=None, vnc_back_port=None,
                profile=None, vnc_rate_limit=False):
    tunnel = HostMuxTunnel(engine, name, auth=auth, profile=profile)
    vnc_limiter = _ConnRateLimiter() if vnc_rate_limit else None
    connections = set()
    loop = asyncio.get_running_loop()
    stopped = asyncio.Event()
    _install_stop_handlers(loop, stopped)

    async def accept_socks(reader, writer):
        if not _peer_allowed(writer, lan_only):
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()
            return
        task = asyncio.current_task()
        connections.add(task)
        try:
            await tunnel.handle_client(reader, writer)
        finally:
            connections.discard(task)

    async def accept_vnc(reader, writer):
        if not _peer_allowed(writer, lan_only):
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()
            return
        if vnc_limiter is not None:
            peer = writer.get_extra_info('peername')
            if peer and not vnc_limiter.allow(peer[0]):
                writer.close()
                with contextlib.suppress(ConnectionError, OSError):
                    await writer.wait_closed()
                return
        task = asyncio.current_task()
        connections.add(task)
        try:
            await _splice_tcp(reader, writer, '127.0.0.1', vnc_back_port)
        finally:
            connections.discard(task)

    servers = await _start_dual_stack_servers(accept_socks, bind_host, port)
    if vnc_front_port and vnc_back_port:
        try:
            servers.extend(await _start_dual_stack_servers(accept_vnc, bind_host, vnc_front_port))
        except OSError:
            for srv in servers:
                srv.close()
            for srv in servers:
                await srv.wait_closed()
            raise

    scope_label = 'LAN only' if lan_only else ('local' if bind_host == '127.0.0.1' else 'all')
    auth_label = 'password required' if auth else 'no password'
    mode_label = f'{scope_label}, {auth_label}'
    say(f'SOCKS5 {bind_host}:{port} into {name} ({engine.cli}, mux v{BRIDGE_PROTO}, {mode_label})')
    if vnc_front_port and vnc_back_port:
        guard_label = 'LAN only' if lan_only else 'rate-limited'
        say(f'VNC proxy {bind_host}:{vnc_front_port} -> 127.0.0.1:{vnc_back_port} ({guard_label})')
    with contextlib.suppress(OSError, ConnectionError):
        await tunnel.ensure_connected()
    tunnel.start_heartbeat()
    try:
        await stopped.wait()
    finally:
        for srv in servers:
            srv.close()
        for task in list(connections):
            task.cancel()
        if connections:
            await asyncio.gather(*connections, return_exceptions=True)
        await tunnel.close()
        for srv in servers:
            await srv.wait_closed()


def run_bridge(engine, profile):
    """Run the multiplexed SOCKS5 bridge (and VNC front proxy in `accept lan`/`all` modes)."""
    if engine.container_state(profile) != 'running':
        die(f'{profile} is not running')
    mode = accept_mode()
    password = auth_password(mode)
    wanted_hash = auth_fingerprint(mode, password)
    bind_host = bind_address(mode)
    auth = (AUTH_USER, password) if password else None
    lan_only = mode == 'lan'
    vnc_fronted = _needs_vnc_front_proxy(mode)
    vnc_front = desktop_port(profile) if vnc_fronted else None
    vnc_back = desktop_backend_port(profile) if vnc_fronted else None

    live_pid, live_engine, _, _, _ = bridge_record(profile)
    if live_pid and live_pid != os.getpid():
        other = ENGINE_NAMES.get(live_engine, live_engine or 'another engine')
        die(f'a bridge for {profile} is already running on {other} (pid {live_pid})')

    _write_pidfile(profile, os.getpid(), engine.cli, mode, wanted_hash)
    try:
        asyncio.run(serve(
            engine,
            container_name(profile),
            socks_port(profile),
            bind_host=bind_host,
            auth=auth,
            lan_only=lan_only,
            vnc_front_port=vnc_front,
            vnc_back_port=vnc_back,
            profile=profile,
            vnc_rate_limit=(mode == 'all'),
        ))
    except OSError as error:
        ports = f'{socks_port(profile)}/{vnc_front}' if vnc_front else str(socks_port(profile))
        die(
            f'cannot listen on {bind_host}:{ports} ({error.strerror}); '
            'something else has the port'
        )
    finally:
        with contextlib.suppress(OSError):
            recorded_pid, _, _, _, _ = _parse_pidfile(bridge_pidfile(profile))
            if recorded_pid == os.getpid():
                bridge_pidfile(profile).unlink(missing_ok=True)
                health_file(profile).unlink(missing_ok=True)
