#!/usr/bin/env python3
"""Minimal stdlib asyncio TCP + UDP multiplexer for the zt SOCKS5 bridge.

Runs inside the container as `nobody` via `python3 -c <source> 127.0.0.1 1080`
over a single persistent `exec -i` pipe, leaving stdin/stdout dedicated to
binary frames and multiplexing concurrent TCP streams (to microsocks) alongside
SOCKS5 UDP ASSOCIATE sessions (native asyncio UDP sockets with container DNS).

Frame layout (big-endian, 9-byte header):
    uint32 stream_id | uint8 frame_type | uint32 length | <length bytes>

Flow control (TCP streams):
    Each stream starts with a 4 MiB credit window (`STREAM_WINDOW`) and
    replenishes via `WINDOW_UPDATE` frames (`uint32` increment) as bytes drain.
    The demux loop NEVER awaits per-stream delivery (`push_data` is synchronous
    and non-blocking); any peer violating `MAX_STREAM_BUFFER` receives a
    per-stream `RST` without stalling other TCP streams or UDP associations.

UDP_DATA payload layout (RFC 1928 §7 body without the 3-byte RSV+FRAG prefix):
    uint8 atyp | addr (4B IPv4 / 1B+N domain / 16B IPv6) | uint16 port | data
"""
import asyncio
import collections
import contextlib
import ipaddress
import os
import socket
import struct
import sys
import time

HEADER = struct.Struct('>IBI')
WIN_STRUCT = struct.Struct('>I')

OPEN = 1
DATA = 2
EOF = 3
RST = 4
UDP_OPEN = 5
UDP_DATA = 6
UDP_CLOSE = 7
WINDOW_UPDATE = 8

ATYP_IPV4 = 1
ATYP_DOMAIN = 3
ATYP_IPV6 = 4

MAX_FRAME = 1 << 20                 # 1 MiB safety bound
STREAM_WINDOW = 4 * 1024 * 1024     # 4 MiB initial per-stream send window
WINDOW_REPLENISH = 1 * 1024 * 1024  # Send WINDOW_UPDATE once >= 1 MiB drained
MAX_STREAM_BUFFER = STREAM_WINDOW + (1 * 1024 * 1024)  # 5 MiB hard receive cap

MAX_UDP_PAYLOAD = 65507             # Max IPv4 UDP datagram payload
UDP_QUEUE_SIZE = 256                # Bounded per-direction UDP queue (drop-on-full)
UDP_PEER_TTL = 300.0                # Seconds an outbound UDP peer may send replies
UDP_PEER_MAX = 512                  # Max tracked remote UDP peers per association
DNS_CACHE_TTL = 30.0                # Seconds to cache successful ATYP=0x03 resolutions
DNS_NEG_TTL = 5.0                   # Seconds to cache failed resolutions (prevents storms)
DNS_CACHE_MAX = 256


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
    """Run bidirectional up/down coroutines with intentional asymmetric half-close.

    When `up` completes first (client EOF), `down` gets up to `drain_timeout`
    seconds to flush remaining server responses. When `down` completes first
    (server EOF/close), `up` is cancelled immediately so closed tunnel/SOCKS/VNC
    streams tear down cleanly instead of waiting on an idle writer.
    """
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


class _GuestUDPProtocol(asyncio.DatagramProtocol):
    """Receives remote UDP replies from previously contacted peers, drop-on-full."""

    def __init__(self, inbound_queue, is_allowed_peer):
        self._inbound = inbound_queue
        self._is_allowed_peer = is_allowed_peer

    def datagram_received(self, data, addr):
        if len(data) > MAX_UDP_PAYLOAD:
            return
        if not self._is_allowed_peer(addr[0], addr[1]):
            return
        try:
            encoded = encode_socks_addr(addr[0], addr[1]) + data
        except (ValueError, OSError):
            return
        with contextlib.suppress(asyncio.QueueFull):
            self._inbound.put_nowait(encoded)

    def error_received(self, exc):
        # Ignore transient ICMP errors so one unreachable destination never kills the relay.
        pass


class _GuestUDPAssoc:
    """One SOCKS5 UDP ASSOCIATE session running inside the container as `nobody`.

    Uses separate lazy AF_INET / AF_INET6 UDP sockets, a bounded TTL allowlist
    of contacted remote (ip, port) peers (defense-in-depth alongside ZT-INPUT),
    and bounded drop-on-full queues so UDP bursts never stall TCP streams.
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
        self._tasks = (
            asyncio.create_task(self._outbound_loop()),
            asyncio.create_task(self._inbound_loop()),
        )

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
                    lambda: _GuestUDPProtocol(self._inbound, self._is_allowed_peer),
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
                    lambda: _GuestUDPProtocol(self._inbound, self._is_allowed_peer),
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
                    family, target_ip = socket.AF_INET, host
                elif atyp == ATYP_IPV6:
                    norm = normalize_ip(host)
                    if norm is None:
                        continue
                    ip_obj = ipaddress.ip_address(norm)
                    family = socket.AF_INET if isinstance(ip_obj, ipaddress.IPv4Address) else socket.AF_INET6
                    target_ip = norm
                elif atyp == ATYP_DOMAIN:
                    resolved = await self._mux.resolve_udp_host(host, port)
                    if resolved is None:
                        continue
                    family, target_ip = resolved
                else:
                    continue
                try:
                    transport = await self._ensure_transport(family)
                    if transport is not None and not transport.is_closing():
                        self._record_peer(target_ip, port)
                        transport.sendto(data, (target_ip, port))
                except OSError:
                    continue
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
        for task in self._tasks:
            if not task.done():
                task.cancel()

    async def wait_closed(self):
        self.close()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)


class GuestMux:
    """Guest-side endpoint: reads frames from stdin, dials TCP microsocks or UDP targets.

    Each OPEN / UDP_OPEN synchronously registers its StreamState / association
    before returning to the frame reader loop, and the reader loop never awaits
    per-stream delivery so one stalled stream can never block another.
    """

    def __init__(self, target_host='127.0.0.1', target_port=1080):
        self.target_host = target_host
        self.target_port = target_port
        self._streams = {}
        self._tasks = {}
        self._udp = {}
        self._dns_cache = {}
        self._write_lock = asyncio.Lock()
        self._out = None

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

        asyncio.create_task(_send())

    async def resolve_udp_host(self, host, port):
        """Resolve ATYP=0x03 domain asynchronously via container DNS (IPv4 preferred, TTL cached)."""
        literal = normalize_ip(host)
        if literal is not None:
            ip_obj = ipaddress.ip_address(literal)
            fam = socket.AF_INET if isinstance(ip_obj, ipaddress.IPv4Address) else socket.AF_INET6
            return fam, literal

        key = host.lower()
        now = time.monotonic()
        cached = self._dns_cache.get(key)
        if cached is not None and cached[0] > now:
            return cached[1]

        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM),
                timeout=5.0,
            )
        except (OSError, asyncio.TimeoutError):
            infos = ()

        chosen = None
        for af, _, _, _, sockaddr in infos:
            if af == socket.AF_INET:
                norm = normalize_ip(sockaddr[0])
                if norm is not None:
                    chosen = (socket.AF_INET, norm)
                    break
        if chosen is None:
            for af, _, _, _, sockaddr in infos:
                if af == socket.AF_INET6:
                    norm = normalize_ip(sockaddr[0])
                    if norm is not None:
                        ip_obj = ipaddress.ip_address(norm)
                        fam = socket.AF_INET if isinstance(ip_obj, ipaddress.IPv4Address) else socket.AF_INET6
                        chosen = (fam, norm)
                        break

        if len(self._dns_cache) >= DNS_CACHE_MAX:
            expired = [k for k, v in self._dns_cache.items() if v[0] <= now]
            for k in expired:
                self._dns_cache.pop(k, None)
            if len(self._dns_cache) >= DNS_CACHE_MAX:
                self._dns_cache.clear()
        ttl = DNS_CACHE_TTL if chosen is not None else DNS_NEG_TTL
        self._dns_cache[key] = (now + ttl, chosen)
        return chosen

    async def _run_stream(self, stream_id, state):
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=5.0,
            )

            async def to_target():
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

            async def from_target():
                while True:
                    data = await reader.read(65536)
                    if not data:
                        await self.send(stream_id, EOF)
                        return
                    if not await send_stream_data(self.send, stream_id, state, data):
                        return

            await splice_tasks(to_target(), from_target(), drain_timeout=300)
        except (OSError, ConnectionError, asyncio.TimeoutError):
            state.close_rst()
            with contextlib.suppress(OSError, ConnectionError):
                await self.send(stream_id, RST)
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

    async def serve(self, in_reader, out_writer):
        self._out = out_writer
        try:
            while True:
                frame = await read_frame(in_reader)
                if frame is None:
                    break
                stream_id, kind, payload = frame
                if kind == OPEN:
                    if stream_id == 0:
                        continue
                    state = StreamState()
                    self._streams[stream_id] = state
                    self._tasks[stream_id] = asyncio.create_task(self._run_stream(stream_id, state))
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
                    old = self._udp.pop(stream_id, None)
                    if old is not None:
                        old.close()
                    self._udp[stream_id] = _GuestUDPAssoc(self, stream_id)
                elif kind == UDP_DATA:
                    assoc = self._udp.get(stream_id)
                    if assoc is not None:
                        assoc.enqueue_outbound(payload)
                elif kind == UDP_CLOSE:
                    assoc = self._udp.pop(stream_id, None)
                    if assoc is not None:
                        assoc.close()
                elif kind == RST:
                    state = self._streams.pop(stream_id, None)
                    if state is not None:
                        state.close_rst()
                    task = self._tasks.pop(stream_id, None)
                    if task is not None:
                        task.cancel()
                    assoc = self._udp.pop(stream_id, None)
                    if assoc is not None:
                        assoc.close()
        finally:
            for state in list(self._streams.values()):
                state.close_rst()
            self._streams.clear()
            tasks = list(self._tasks.values())
            self._tasks.clear()
            for task in tasks:
                task.cancel()
            assocs = list(self._udp.values())
            self._udp.clear()
            for assoc in assocs:
                assoc.close()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            if assocs:
                await asyncio.gather(*(a.wait_closed() for a in assocs), return_exceptions=True)


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


async def _run(host, port):
    reader, writer = await _stdio_streams()
    mux = GuestMux(host, port)
    try:
        await mux.serve(reader, writer)
    finally:
        writer.close()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1080
    asyncio.run(_run(host, port))


if __name__ == '__main__':
    main()
