#!/usr/bin/env python3
"""Minimal stdlib asyncio stream multiplexer for the zt SOCKS5 bridge.

Runs inside the container as `nobody` via `python3 -c <source> 127.0.0.1 1080`
over a single persistent `exec -i` pipe, leaving stdin/stdout dedicated to
binary frames and multiplexing arbitrary concurrent TCP streams to microsocks.

Frame layout (big-endian, 9-byte header):
    uint32 stream_id | uint8 frame_type | uint32 length | <length bytes>
"""
import asyncio
import contextlib
import os
import struct
import sys

HEADER = struct.Struct('>IBI')
OPEN = 1
DATA = 2
EOF = 3
RST = 4
PING = 5
PONG = 6

MAX_FRAME = 1 << 20  # 1 MiB safety bound


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


class GuestMux:
    """Guest-side endpoint: reads frames from stdin, dials target_host:target_port.

    Each OPEN synchronously creates a per-stream asyncio.Queue before returning
    to the frame reader loop, so DATA frames arriving immediately after OPEN
    (before TCP connect completes) are buffered in strict order and never dropped.
    """

    def __init__(self, target_host='127.0.0.1', target_port=1080):
        self.target_host = target_host
        self.target_port = target_port
        self._queues = {}
        self._tasks = {}
        self._write_lock = asyncio.Lock()
        self._out = None

    async def send(self, stream_id, kind, payload=b''):
        frame = encode_frame(stream_id, kind, payload)
        async with self._write_lock:
            self._out.write(frame)
            await self._out.drain()

    async def _run_stream(self, stream_id, queue):
        writer = None
        up = down = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port),
                timeout=5.0,
            )

            async def to_target():
                while True:
                    kind, payload = await queue.get()
                    if kind == DATA:
                        writer.write(payload)
                        await writer.drain()
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
                    await self.send(stream_id, DATA, data)

            up = asyncio.create_task(to_target())
            down = asyncio.create_task(from_target())
            done, pending = await asyncio.wait([up, down], return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            if down in pending:
                await asyncio.wait_for(down, timeout=300)
            elif up in pending:
                up.cancel()
                await asyncio.gather(up, return_exceptions=True)
        except (OSError, ConnectionError, asyncio.TimeoutError):
            with contextlib.suppress(OSError, ConnectionError):
                await self.send(stream_id, RST)
        except asyncio.CancelledError:
            raise
        finally:
            for task in (up, down):
                if task and not task.done():
                    task.cancel()
            tasks = [t for t in (up, down) if t]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._queues.pop(stream_id, None)
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
                if kind == PING:
                    await self.send(0, PONG, payload)
                elif kind == OPEN:
                    queue = asyncio.Queue(maxsize=64)
                    self._queues[stream_id] = queue
                    self._tasks[stream_id] = asyncio.create_task(self._run_stream(stream_id, queue))
                elif kind in (DATA, EOF):
                    queue = self._queues.get(stream_id)
                    if queue is not None:
                        await queue.put((kind, payload))
                elif kind == RST:
                    self._queues.pop(stream_id, None)
                    task = self._tasks.pop(stream_id, None)
                    if task is not None:
                        task.cancel()
        finally:
            self._queues.clear()
            tasks = list(self._tasks.values())
            self._tasks.clear()
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)


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
