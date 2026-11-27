"""Multiplexed persistent SOCKS5 bridge (TCP + UDP ASSOCIATE) with accept-mode guard & RFC 1929 auth."""
import asyncio
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

from zt.config import (
    accept_mode,
    auth_fingerprint,
    auth_password,
    bind_address,
    die,
    is_lan_ip,
    say,
    state_dir,
    warn,
)
from zt.guest.mux import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    ATYP_IPV6,
    DATA,
    EOF,
    MAX_UDP_PAYLOAD,
    OPEN,
    RST,
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

MAX_UDP_ASSOCS = 128
BRIDGE_PROTO = 2  # Bump whenever bridge/mux wire protocol gains capabilities (v1=TCP, v2=TCP+UDP)


def bridge_pidfile(profile):
    return state_dir() / f'socks-{profile}.pid'


def bridge_logfile(profile):
    return state_dir() / f'socks-{profile}.log'


def _recv_exact(conn, count):
    buf = bytearray()
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return b''
        buf.extend(chunk)
    return bytes(buf)


def socks_ready(port, auth=None, timeout=2.0):
    """True when 127.0.0.1:port completes the expected SOCKS5 handshake.

    When `auth` is None (`accept local` / `lan`), checks unauthenticated greeting.
    When `auth=(user, password)` (`accept all`), verifies no-auth is rejected
    (0x05 0xff) AND RFC 1929 username/password succeeds (0x01 0x00).
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
        # 2. Confirm RFC 1929 username/password succeeds end-to-end (including microsocks).
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
    state_dir().mkdir(parents=True, exist_ok=True)
    payload = json.dumps({
        'pid': pid,
        'engine': engine_cli,
        'profile': profile,
        'accept': mode,
        'auth_hash': auth_hash,
        'proto': proto,
    }) + '\n'
    bridge_pidfile(profile).write_text(payload, encoding='utf-8')


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
    proc = subprocess.run(
        [ps, '-ww', '-p', str(pid), '-o', 'command='],
        capture_output=True, text=True, check=False,
    )
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
        and (mode != 'all' or live_hash == wanted_hash)
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


def bridge_start(engine, profile, mode=None, wait_seconds=45.0):
    """Start (or restart on accept/password change) the background multiplexed bridge."""
    mode = mode or accept_mode()
    password = auth_password(mode)
    wanted_hash = auth_fingerprint(mode, password)
    auth = (AUTH_USER, password) if mode == 'all' else None
    bind_host = bind_address(mode)
    port = socks_port(profile)

    live_pid, live_engine, live_accept, live_hash, live_proto = bridge_record(profile)
    if live_pid:
        if live_engine != engine.cli:
            other = ENGINE_NAMES.get(live_engine, live_engine or 'another engine')
            return (
                f'{bind_host}:{port} is served by a zt bridge for {other} (pid {live_pid}), '
                f'not {engine.display_name}'
            )
        if bridge_matches(live_accept, live_hash, live_proto, mode, wanted_hash):
            desktop_ok = True if mode != 'lan' else _port_listening(desktop_port(profile))
            return (
                None
                if desktop_ok and socks_ready(port, auth=auth)
                else f'the bridge started for it is up, but nothing answers on {bind_host}:{port}'
            )
        # Accept mode, password, or bridge protocol changed — restart cleanly (container stays up).
        bridge_stop(profile, engine_cli=engine.cli)

    if socks_any_listener(port):
        return (
            f'something else answers on 127.0.0.1:{port} '
            f'({engine.port_holders(port) or "a listener this user cannot see"}); '
            'it is not a bridge started by zt'
        )

    if mode == 'lan' and _port_listening(desktop_port(profile)):
        dport = desktop_port(profile)
        return (
            f'something else answers on {bind_host}:{dport} '
            f'({engine.port_holders(dport) or "a listener this user cannot see"}); '
            'cannot start the LAN desktop guard'
        )

    state_dir().mkdir(parents=True, exist_ok=True)
    cmd, base_env = _bridge_command(profile)
    child_env = dict(base_env if base_env is not None else os.environ)
    child_env['ZT_ENGINE'] = engine.cli
    child_env['ZT_ACCEPT'] = mode
    if mode == 'all':
        child_env['ZT_VNC_PW'] = password
    else:
        child_env.pop('ZT_VNC_PW', None)

    with bridge_logfile(profile).open('ab') as log:
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
        desktop_ok = True if mode != 'lan' else _port_listening(desktop_port(profile))
        if desktop_ok and socks_ready(port, auth=auth):
            return None
        time.sleep(0.25)

    who = engine.port_holders(port) or 'a listener this user cannot see'
    if bridge.poll() is not None and socks_any_listener(port):
        return (
            f'the bridge did not take {bind_host}:{port}, {who} answers there instead, '
            f'see {bridge_logfile(profile)}'
        )
    if bridge.poll() is None and _port_listening(port):
        return (
            f'the bridge is listening on {bind_host}:{port}, but microsocks inside '
            f'{container_name(profile)} did not complete a SOCKS5 handshake in {int(wait_seconds)}s; '
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


async def _read_socks5_noauth(reader, writer):
    """Perform RFC 1928 method selection for unauthenticated (0x00) mode."""
    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
        ver, nmethods = header[0], header[1]
        if ver != 0x05 or nmethods == 0:
            return False
        methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=10.0)
        if 0x00 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return False
        return True
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        return False


async def _read_socks5_credentials(reader, writer):
    """Perform RFC 1928 method selection + read RFC 1929 (user, password) bytes.

    Returns (uname_bytes, passwd_bytes) or None if client fails method negotiation.
    """
    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
        ver, nmethods = header[0], header[1]
        if ver != 0x05 or nmethods == 0:
            return None
        methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=10.0)
        if 0x02 not in methods:
            writer.write(b'\x05\xff')
            await writer.drain()
            return None
        writer.write(b'\x05\x02')
        await writer.drain()

        sub = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
        if sub[0] != 0x01:
            writer.write(b'\x01\x01')
            await writer.drain()
            return None
        uname = await asyncio.wait_for(reader.readexactly(sub[1]), timeout=10.0)
        plen = (await asyncio.wait_for(reader.readexactly(1), timeout=10.0))[0]
        passwd = await asyncio.wait_for(reader.readexactly(plen), timeout=10.0)
        return uname, passwd
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        return None


async def _read_socks5_addr_port(reader, initial=b''):
    """Read RFC 1928 ATYP+ADDR+PORT from `initial` buffer then `reader`."""
    buf = bytearray(initial)

    async def take(count):
        if len(buf) < count:
            need = count - len(buf)
            buf.extend(await asyncio.wait_for(reader.readexactly(need), timeout=10.0))
        out = bytes(buf[:count])
        del buf[:count]
        return out

    try:
        atyp = (await take(1))[0]
        if atyp == ATYP_IPV4:
            raw = await take(6)
            return atyp, socket.inet_ntop(socket.AF_INET, raw[:4]), (raw[4] << 8) | raw[5]
        if atyp == ATYP_IPV6:
            raw = await take(18)
            return atyp, socket.inet_ntop(socket.AF_INET6, raw[:16]), (raw[16] << 8) | raw[17]
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
            return atyp, host, (raw[dlen] << 8) | raw[dlen + 1]
        return 'unsupported', None, 0
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        return None


def _socks5_reply(rep, host='0.0.0.0', port=0):
    return b'\x05' + bytes([rep, 0x00]) + encode_socks_addr(host, port)


def _bind_udp_socket(local_ip):
    """Bind a non-blocking host UDP relay socket on `local_ip:0` (Windows-safe)."""
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
        sock.bind((local_ip, 0))
    except BaseException:
        sock.close()
        raise
    return sock


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
    """Single persistent `CLI exec ... python3 -c <mux>` tunnel multiplexing TCP + UDP."""

    def __init__(self, engine, name, auth=None, mux_source=None):
        self.engine = engine
        self.name = name
        self.auth = auth  # None (local/lan) or (username, password) (all)
        self._mux_source = mux_source if mux_source is not None else guest_script('mux')
        self._process = None
        self._reader_task = None
        self._stderr_task = None
        self._connect_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._streams = {}
        self._udp_handlers = {}
        self._next_id = 1
        self._closing = False

    def _alloc_id(self):
        for _ in range(10000):
            sid = self._next_id
            self._next_id = (self._next_id % 0x7FFFFFFF) + 1
            if sid not in self._streams and sid not in self._udp_handlers:
                return sid
        raise RuntimeError('exhausted stream ids')

    async def _spawn_process(self):
        return await asyncio.create_subprocess_exec(
            self.engine.cli, 'exec', '--interactive', '--user', 'nobody', self.name,
            '/usr/bin/python3', '-c', self._mux_source, '127.0.0.1', '1080',
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

    async def ensure_connected(self):
        if self._process is not None and self._process.returncode is None:
            return self._process
        async with self._connect_lock:
            if self._process is not None and self._process.returncode is None:
                return self._process
            if self._closing:
                raise ConnectionError('bridge is shutting down')
            proc = await self._spawn_process()
            self._process = proc
            self._reader_task = asyncio.create_task(self._read_loop(proc))
            self._stderr_task = asyncio.create_task(self._drain_stderr(proc))
            return proc

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

    async def _read_loop(self, proc):
        try:
            while True:
                frame = await read_frame(proc.stdout)
                if frame is None:
                    break
                stream_id, kind, payload = frame
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
                        asyncio.create_task(self.send_if_open(stream_id, RST))
                elif kind == EOF:
                    state.push_eof()
                elif kind == WINDOW_UPDATE:
                    if len(payload) == WIN_STRUCT.size:
                        state.add_window(WIN_STRUCT.unpack(payload)[0])
                elif kind == RST:
                    state.close_rst()
        except (OSError, ValueError, asyncio.CancelledError):
            pass
        finally:
            if self._process is proc:
                self._process = None
            for state in list(self._streams.values()):
                state.close_rst()
            for _, on_close in list(self._udp_handlers.values()):
                on_close()

    async def send(self, stream_id, kind, payload=b''):
        proc = await self.ensure_connected()
        frame = encode_frame(stream_id, kind, payload)
        async with self._write_lock:
            if proc.returncode is not None or proc.stdin.is_closing():
                raise ConnectionError('mux tunnel closed')
            proc.stdin.write(frame)
            await proc.stdin.drain()

    async def send_if_open(self, stream_id, kind, payload=b''):
        """Send a teardown frame only when the mux process is already live (never respawn)."""
        proc = self._process
        if proc is None or proc.returncode is not None or proc.stdin is None or proc.stdin.is_closing():
            return
        frame = encode_frame(stream_id, kind, payload)
        async with self._write_lock:
            if proc.returncode is not None or proc.stdin.is_closing():
                return
            proc.stdin.write(frame)
            await proc.stdin.drain()

    async def _complete_guest_noauth(self, stream_id, state):
        """Send no-auth greeting to guest microsocks and absorb its 2-byte reply."""
        if not await send_stream_data(self.send, stream_id, state, b'\x05\x01\x00'):
            return None
        buf = bytearray()
        while len(buf) < 2:
            kind, payload = await asyncio.wait_for(state.recv(), timeout=5.0)
            if kind != DATA:
                return None
            buf.extend(payload)
        if bytes(buf[:2]) != b'\x05\x00':
            return None
        return bytes(buf[2:])

    async def _handle_udp_associate(self, reader, writer, initial=b''):
        req = await _read_socks5_addr_port(reader, initial=initial)
        if req is None:
            return
        atyp, req_host, req_port = req
        if atyp == 'unsupported':
            writer.write(_socks5_reply(0x08))
            await writer.drain()
            return

        if len(self._udp_handlers) >= MAX_UDP_ASSOCS:
            writer.write(_socks5_reply(0x01))
            await writer.drain()
            return

        sockname = writer.get_extra_info('sockname')
        peername = writer.get_extra_info('peername')
        local_ip = normalize_ip(sockname[0]) if sockname else None
        peer_ip = normalize_ip(peername[0]) if peername else None
        if not local_ip or not peer_ip:
            writer.write(_socks5_reply(0x01))
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

            sock = _bind_udp_socket(local_ip)
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
            await self.send(udp_sid, UDP_OPEN)
            opened_udp = True

            writer.write(_socks5_reply(0x00, local_ip, bound_port))
            await writer.drain()

            ctrl_sock = writer.get_extra_info('socket')
            if ctrl_sock is not None:
                with contextlib.suppress(OSError):
                    ctrl_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

            async def tx_pump():
                while True:
                    body = await tx_queue.get()
                    await self.send(udp_sid, UDP_DATA, body)

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
                    writer.write(_socks5_reply(0x01))
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
                    await self.send_if_open(udp_sid, UDP_CLOSE)

    async def handle_client(self, reader, writer):
        stream_id = None
        opened = False
        try:
            if self.auth is not None:
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
                    writer.write(b'\x01\x01')
                    await writer.drain()
                    return
            else:
                if not await _read_socks5_noauth(reader, writer):
                    return

            stream_id = self._alloc_id()
            state = StreamState()
            self._streams[stream_id] = state
            await self.send(stream_id, OPEN)
            opened = True

            trailing = await self._complete_guest_noauth(stream_id, state)
            if trailing is None:
                if self.auth is not None:
                    writer.write(b'\x01\x01')
                    await writer.drain()
                return
            writer.write(b'\x01\x00' if self.auth is not None else b'\x05\x00')
            if trailing:
                writer.write(trailing)
            await writer.drain()

            first_chunk = await reader.read(65536)
            if not first_chunk:
                await self.send_if_open(stream_id, EOF)
                return
            if first_chunk[0] == 0x05 and len(first_chunk) < 3:
                try:
                    first_chunk += await asyncio.wait_for(
                        reader.readexactly(3 - len(first_chunk)), timeout=10.0,
                    )
                except asyncio.IncompleteReadError as exc:
                    first_chunk += exc.partial
                    await send_stream_data(self.send, stream_id, state, first_chunk)
                    await self.send_if_open(stream_id, EOF)
                    return

            if len(first_chunk) >= 3 and first_chunk[:3] == b'\x05\x03\x00':
                # Switch to SOCKS5 UDP ASSOCIATE without touching microsocks.
                with contextlib.suppress(ConnectionError, OSError):
                    await self.send_if_open(stream_id, RST)
                state.close_rst()
                self._streams.pop(stream_id, None)
                opened = False
                stream_id = None
                await self._handle_udp_associate(reader, writer, initial=first_chunk[3:])
                return

            if not await send_stream_data(self.send, stream_id, state, first_chunk):
                return

            async def host_to_guest():
                while True:
                    data = await reader.read(65536)
                    if not data:
                        await self.send(stream_id, EOF)
                        return
                    if not await send_stream_data(self.send, stream_id, state, data):
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
                            await self.send(stream_id, WINDOW_UPDATE, WIN_STRUCT.pack(inc))
                    elif kind == EOF:
                        if writer.can_write_eof():
                            with contextlib.suppress(ConnectionError, OSError):
                                writer.write_eof()
                        return
                    elif kind == RST:
                        return

            await splice_tasks(host_to_guest(), guest_to_host(), drain_timeout=300)
        except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.CancelledError):
            if opened and stream_id is not None:
                with contextlib.suppress(ConnectionError, OSError):
                    await self.send_if_open(stream_id, RST)
        finally:
            if stream_id is not None:
                self._streams.pop(stream_id, None)
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()

    async def close(self):
        self._closing = True
        proc = self._process
        self._process = None
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(OSError):
                proc.stdin.close()
            try:
                await asyncio.wait_for(proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        proc.kill()
                    await proc.wait()
        for task in (self._reader_task, self._stderr_task):
            if task and not task.done():
                task.cancel()
        tasks = [t for t in (self._reader_task, self._stderr_task) if t]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


async def _splice_tcp(reader, writer, target_host, target_port):
    """Raw bidirectional TCP forwarder (used for the `accept lan` VNC guard)."""
    backend_writer = None
    try:
        backend_reader, backend_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port), timeout=5.0,
        )

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
                lan_only=False, vnc_front_port=None, vnc_back_port=None):
    tunnel = HostMuxTunnel(engine, name, auth=auth)
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
        task = asyncio.current_task()
        connections.add(task)
        try:
            await _splice_tcp(reader, writer, '127.0.0.1', vnc_back_port)
        finally:
            connections.discard(task)

    servers = [await asyncio.start_server(accept_socks, bind_host, port)]
    if vnc_front_port and vnc_back_port:
        try:
            servers.append(await asyncio.start_server(accept_vnc, bind_host, vnc_front_port))
        except OSError:
            for srv in servers:
                srv.close()
                await srv.wait_closed()
            raise

    mode_label = 'auth required' if auth else ('LAN only, no password' if lan_only else 'local, no password')
    say(f'SOCKS5 {bind_host}:{port} into {name} ({engine.cli}, multiplexed, {mode_label})')
    if vnc_front_port and vnc_back_port:
        say(f'VNC guard {bind_host}:{vnc_front_port} -> 127.0.0.1:{vnc_back_port} (LAN only)')
    with contextlib.suppress(OSError, ConnectionError):
        await tunnel.ensure_connected()
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
    """Run the multiplexed SOCKS5 bridge (and LAN VNC guard in `accept lan` mode)."""
    if engine.container_state(profile) != 'running':
        die(f'{profile} is not running')
    mode = accept_mode()
    password = auth_password(mode)
    wanted_hash = auth_fingerprint(mode, password)
    bind_host = bind_address(mode)
    auth = (AUTH_USER, password) if mode == 'all' else None
    lan_only = mode == 'lan'
    vnc_front = desktop_port(profile) if lan_only else None
    vnc_back = desktop_backend_port(profile) if lan_only else None

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
