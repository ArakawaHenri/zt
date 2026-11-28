"""Host-side two-boot image verification orchestrator (guest/check.py + probe.py + GuestMux e2e)."""
import argparse
import asyncio
import base64
import contextlib
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from zt.bridge import HostMuxTunnel
from zt.build import build, current_ref
from zt.config import accept_mode, container_env, die, say, target_arch
from zt.engine import make_engine
from zt.guest.mux import (
    CALLBACK_OPEN,
    OPEN_ERR,
    PORT_STRUCT,
    REP_NOT_ALLOWED,
    encode_socks_addr,
)
from zt.resources import guest_script
from zt.spec import (
    ACCEPT_MODES,
    AUTH_USER,
    CHECKS,
    CLIENTS,
    STAND_IN,
    SUPPORTED_ARCHES,
    platform_for,
    resolve_targets,
    system_setuid,
)


def http_status(url, timeout=4, auth=None):
    """GET status code on loopback only (including 4xx like 401); 0 when unreachable."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    headers = {}
    if auth is not None:
        token = base64.b64encode(f'{auth[0]}:{auth[1]}'.encode('utf-8')).decode('ascii')
        headers['Authorization'] = f'Basic {token}'
    request = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code
    except OSError:
        return 0


def free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def wait_for_desktop(port, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = http_status(f'https://127.0.0.1:{port}/')
        if status:
            return True, status
        time.sleep(1)
    return False, 0


def parse_report(output, errors=''):
    """Validate strict JSON report emitted by guest/check.py.

    Returns [(check, 'ok' | 'fail', detail)]. Any truncation, malformed JSON,
    incomplete marker, or missing check produces an ('inside', 'fail', ...) entry.
    """
    text = (output or '').strip()
    findings = []
    trouble = []
    payload = None
    if not text:
        trouble.append('empty report')
    else:
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) != 1:
            trouble.append(f'expected 1 JSON line, got {len(lines)}')
        try:
            payload = json.loads(lines[-1])
        except (ValueError, IndexError) as exc:
            trouble.append(f'invalid JSON: {exc}')

    if isinstance(payload, dict):
        if payload.get('version') != 1:
            trouble.append(f'unexpected report version {payload.get("version")!r}')
        if payload.get('complete') is not True:
            trouble.append('cut off before the end')
        raw_checks = payload.get('checks')
        if not isinstance(raw_checks, dict):
            trouble.append('missing checks map')
        else:
            missing = [c for c in CHECKS if c not in raw_checks]
            extra = [c for c in raw_checks if c not in CHECKS]
            if missing:
                trouble.append('missing checks: ' + ', '.join(missing))
            if extra:
                trouble.append('unexpected checks: ' + ', '.join(extra))
            for check in CHECKS:
                if check not in raw_checks:
                    continue
                entry = raw_checks[check]
                if not isinstance(entry, dict) or not isinstance(entry.get('ok'), bool):
                    trouble.append(f'malformed finding for {check}')
                    continue
                findings.append((
                    check,
                    'ok' if entry['ok'] else 'fail',
                    str(entry.get('detail', '')),
                ))
    elif payload is not None:
        trouble.append('report root is not a JSON object')

    if trouble:
        tail = ': ' + ' '.join(errors.split()[-12:]) if errors and errors.strip() else ''
        findings.append((
            'inside',
            'fail',
            'the checks inside the container did not complete (' + '; '.join(trouble) + ')' + tail,
        ))
    return findings


def guest_report(engine, name, profile, zone, net_mode=None, arch=None):
    """Run guest/check.py inside `name` and parse its JSON findings."""
    arch = arch or target_arch()
    spec = CLIENTS[profile]
    check_spec = {
        'vendor': spec['vendor'],
        'units': list(spec['units']),
        'nnp_units': list(spec['nnp_units']),
        'ui': spec['ui'],
        'launch': spec['launch'],
        'tz': zone or '',
        'net_mode': net_mode or engine.net_mode,
        'engine_cli': engine.cli,
        'is_rootless_podman': bool(getattr(engine, 'is_rootless_podman', False)),
        'is_rootless': bool(getattr(engine, 'is_rootless', False)),
        'libs': list(spec['libs']),
        'quiet': list(spec['quiet']),
        'extra_logs': [
            [path, list(needles)] for path, needles in spec.get('extra_logs', ())
        ],
        'mid_url': spec.get('mid_url', ''),
        'root_runs': list(spec['root_runs']),
        'setuid': list(system_setuid(arch) + spec['setuid']),
        'desktop_writes': list(spec['desktop_writes']),
        'stand_in_port': STAND_IN,
    }
    script = guest_script('check').encode('utf-8')
    try:
        proc = engine.exec_capture(
            name, 'root',
            ['/usr/bin/python3', '-', json.dumps(check_spec, sort_keys=True)],
            stdin=script, timeout=300,
        )
    except subprocess.TimeoutExpired:
        return [('inside', 'fail', 'the checks inside the container did not finish')]
    stdout = proc.stdout.decode(errors='replace') if isinstance(proc.stdout, bytes) else (proc.stdout or '')
    stderr = proc.stderr.decode(errors='replace') if isinstance(proc.stderr, bytes) else (proc.stderr or '')
    return parse_report(stdout, stderr)


def _derive_peer_ipv6(ipv6_cidr):
    """Choose a distinct peer IPv6 address inside the target container's prefix."""
    net = ipaddress.ip_network(ipv6_cidr, strict=False)
    target = ipaddress.ip_interface(ipv6_cidr).ip
    candidate = ipaddress.IPv6Address(int(net.network_address) + 0xbeef)
    if candidate == target or candidate not in net:
        candidate = ipaddress.IPv6Address(int(net.network_address) + 0xbeee)
    return f'{candidate}/{net.prefixlen}'


def host_only_holds(engine, name, net_mode=None, arch=None):
    """Measure peer-container isolation with positive and negative controls."""
    arch = arch or target_arch()
    net_mode = net_mode or engine.net_mode
    info = engine.inspect(name) or {}
    try:
        network = info['status']['networks'][0]
        ipv4 = str(network['ipv4Address']).split('/')[0]
    except (KeyError, IndexError, TypeError):
        return 'the container has no address to probe', ''

    ipv6_raw = str(network.get('ipv6Address', ''))
    ipv6, peer_v6_cidr = '', ''
    if ipv6_raw:
        try:
            ipv6 = ipv6_raw.split('/')[0]
            cidr = ipv6_raw if '/' in ipv6_raw else f'{ipv6}/64'
            peer_v6_cidr = _derive_peer_ipv6(cidr)
        except ValueError:
            ipv6, peer_v6_cidr = '', ''

    questions = ['desktop over IPv4', 'stand-in over IPv4', 'stand-in UDP over IPv4'] + (
        ['stand-in over IPv6', 'stand-in UDP over IPv6'] if ipv6 else []
    )
    other = f'{name}-from'
    probe_src = guest_script('probe').encode('utf-8')

    def told(rounds):
        return [
            'with the rule ' + word + ': ' + ', '.join(
                f'{q} {answers.get(q, "gave no answer")}' for q in questions
            )
            for word, answers in zip(('in', 'out'), rounds)
        ]

    engine.run_cli('rm', '-f', other, quiet=True, check=False)
    rounds = []
    rule_removed = False
    try:
        engine.run_cli(
            'run', '--rm', '-d', '--name', other, '--platform', platform_for(arch),
            '--user', 'root', '--cap-add', 'NET_ADMIN',
            '--entrypoint', '/bin/sleep', current_ref('base', arch), '600',
            quiet=True, timeout=600,
        )
        if peer_v6_cidr:
            engine.exec_capture(
                other, 'root', ['/usr/bin/python3', '-', 'setup-ipv6', peer_v6_cidr],
                stdin=probe_src,
            )

        def asked():
            proc = engine.exec_capture(
                other, 'root',
                ['/usr/bin/python3', '-', 'probe', ipv4, ipv6, str(STAND_IN)],
                stdin=probe_src,
            )
            raw = proc.stdout.decode(errors='replace') if isinstance(proc.stdout, bytes) else (proc.stdout or '')
            try:
                data = json.loads(raw.strip())
                return data if isinstance(data, dict) else {}
            except ValueError:
                return {}

        def toggle(direction):
            proc = engine.exec_capture(
                name, 'root',
                ['/usr/bin/python3', '-', 'toggle', direction, net_mode],
                stdin=probe_src,
            )
            return proc.returncode == 0

        rounds = [asked()]
        if not toggle('out'):
            return '; '.join(told(rounds)) + '; the rule could not be taken out for the control', ''
        rule_removed = True
        rounds.append(asked())
        if not toggle('in'):
            return '; '.join(told(rounds)) + '; the rule could not be put back', ''
        rule_removed = False
    finally:
        if rule_removed:
            engine.exec_capture(
                name, 'root',
                ['/usr/bin/python3', '-', 'toggle', 'in', net_mode],
                stdin=probe_src,
            )
        engine.run_cli('rm', '-f', other, quiet=True, check=False)

    by_question = [[answers.get(q) for q in questions] for answers in rounds]
    if (
        len(rounds) == 2
        and by_question[0] == ['stopped'] * len(questions)
        and by_question[1] == ['through'] * len(questions)
    ):
        return None, (
            f'from another container {", ".join(questions)} stopped, '
            'each through with the rule out'
        )
    return '; '.join(told(rounds)), ''


async def _socks5_connect_probe(proxy_port, raw_addr, payload=None, timeout=6.0):
    """Run one no-auth SOCKS5 CONNECT via local HostMuxTunnel; return (rep, reply_bytes)."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection('127.0.0.1', proxy_port), timeout=timeout,
    )
    try:
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        greet = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if greet != b'\x05\x00':
            raise ConnectionError(f'unexpected SOCKS5 greeting reply {greet!r}')
        writer.write(b'\x05\x01\x00' + raw_addr)
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if hdr[0] != 0x05 or hdr[2] != 0x00:
            raise ConnectionError(f'malformed SOCKS5 reply header {hdr!r}')
        rep, atyp = hdr[1], hdr[3]
        if atyp == 0x01:
            await asyncio.wait_for(reader.readexactly(6), timeout=timeout)
        elif atyp == 0x04:
            await asyncio.wait_for(reader.readexactly(18), timeout=timeout)
        elif atyp == 0x03:
            dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=timeout))[0]
            await asyncio.wait_for(reader.readexactly(dlen + 2), timeout=timeout)
        else:
            raise ConnectionError(f'unexpected SOCKS5 reply ATYP {atyp}')

        reply = b''
        if rep == 0x00 and payload is not None:
            writer.write(payload)
            if writer.can_write_eof():
                writer.write_eof()
            await writer.drain()
            reply = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        return rep, reply
    finally:
        writer.close()
        with contextlib.suppress(ConnectionError, OSError):
            await writer.wait_closed()


def mux_e2e_holds(engine, name, profile, tunnel_cls=HostMuxTunnel):
    """Verify live BRIDGE_PROTO=3 GuestMux end-to-end: PING/HEALTH, TCP CONNECT, SSRF, callback guard."""
    info = engine.inspect(name) or {}
    try:
        network = info['status']['networks'][0]
        ipv4 = str(network['ipv4Address']).split('/')[0]
    except (KeyError, IndexError, TypeError):
        return 'the container has no IPv4 address for GuestMux e2e', ''

    async def scenario():
        with tempfile.TemporaryDirectory() as tmp:
            health_path = Path(tmp) / 'health.json'
            tunnel = tunnel_cls(engine, name, auth=None, profile=profile, health_path=health_path)
            srv = await asyncio.start_server(tunnel.handle_client, '127.0.0.1', 0)
            proxy_port = srv.sockets[0].getsockname()[1]
            try:
                proc = await tunnel.ensure_connected()
                health = tunnel._last_health
                if not isinstance(health, dict) or 'vpn' not in health or not health_path.is_file():
                    return 'GuestMux PING/PONG did not produce a valid health snapshot', ''

                # 1. Allowed TCP CONNECT to container's non-loopback eth0 IP + STAND_IN echo port.
                rep_ok, echo = await _socks5_connect_probe(
                    proxy_port, encode_socks_addr(ipv4, STAND_IN), payload=b'zt-mux-e2e',
                )
                if rep_ok != 0x00 or echo != b'echo:zt-mux-e2e':
                    return f'TCP CONNECT to {ipv4}:{STAND_IN} failed (rep=0x{rep_ok:02x}, echo={echo!r})', ''

                # 2. Loopback IPv4 SSRF must be rejected with RFC 1928 REP=0x02.
                rep_lo, _ = await _socks5_connect_probe(
                    proxy_port, encode_socks_addr('127.0.0.1', 6901),
                )
                if rep_lo != REP_NOT_ALLOWED:
                    return f'loopback target 127.0.0.1:6901 returned REP=0x{rep_lo:02x} (want 0x02)', ''

                # 3. Domain resolving to loopback (`localhost`) must be rejected post-resolve (REP=0x02).
                dom_addr = b'\x03\x09localhost' + struct.pack('!H', 6901)
                rep_dom, _ = await _socks5_connect_probe(proxy_port, dom_addr)
                if rep_dom != REP_NOT_ALLOWED:
                    return f'domain localhost:6901 returned REP=0x{rep_dom:02x} (want 0x02)', ''

                # 4. Disallowed CALLBACK_OPEN port (6901) must be rejected with OPEN_ERR(REP=0x02).
                cb_sid = tunnel._alloc_id()
                cb_fut = asyncio.get_running_loop().create_future()
                tunnel._pending_opens[cb_sid] = cb_fut
                try:
                    await tunnel.send_on(proc, cb_sid, CALLBACK_OPEN, PORT_STRUCT.pack(6901))
                    cb_kind, cb_payload = await asyncio.wait_for(cb_fut, timeout=5.0)
                finally:
                    tunnel._pending_opens.pop(cb_sid, None)
                if cb_kind != OPEN_ERR or cb_payload != bytes([REP_NOT_ALLOWED]):
                    return (
                        f'disallowed CALLBACK_OPEN port 6901 returned kind={cb_kind} payload={cb_payload!r} '
                        '(want OPEN_ERR REP=0x02)'
                    ), ''

                return None, (
                    f'tcp {ipv4}:{STAND_IN} ok; 127.0.0.1/localhost/callback:6901 blocked (REP=0x02); '
                    f'vpn={health.get("vpn")}'
                )
            finally:
                srv.close()
                await srv.wait_closed()
                await tunnel.close()

    try:
        return asyncio.run(scenario())
    except Exception as exc:
        return f'GuestMux e2e error: {exc}', ''


def logs_tail(engine, name, lines=12):
    proc = engine.exec_capture(
        name, 'root',
        ['journalctl', '--boot', '--no-pager', '--quiet', '--lines', str(lines), '--output', 'cat'],
        timeout=30,
    )
    text = (
        proc.stdout
        if proc.returncode == 0 and proc.stdout and proc.stdout.strip()
        else engine.run_cli('logs', name, quiet=True, check=False).stdout
    )
    return (text or '').strip().splitlines()[-lines:]


_IDENTITY_SNAPSHOT_CODE = (
    'import hashlib, json, os\n'
    'def read_txt(p):\n'
    '    try:\n'
    '        with open(p, encoding="utf-8", errors="replace") as f:\n'
    '            return f.read().strip()\n'
    '    except OSError:\n'
    '        return ""\n'
    'def read_sha(*paths):\n'
    '    h = hashlib.sha256()\n'
    '    seen = 0\n'
    '    for p in paths:\n'
    '        try:\n'
    '            with open(p, "rb") as f:\n'
    '                data = f.read()\n'
    '            if not data:\n'
    '                return ""\n'
    '            h.update(data)\n'
    '            seen += 1\n'
    '        except OSError:\n'
    '            return ""\n'
    '    return h.hexdigest() if seen == len(paths) else ""\n'
    'wan = ""\n'
    'for line in read_txt("/run/zt/wan.env").splitlines():\n'
    '    if line.startswith("WAN="):\n'
    '        wan = line.split("=", 1)[1].strip()\n'
    '        break\n'
    'wan = wan or "eth0"\n'
    'out = {\n'
    '    "machine_id": read_txt("/etc/machine-id"),\n'
    '    "dbus_machine_id": read_txt("/var/lib/dbus/machine-id"),\n'
    '    "smbios_sha256": read_sha(\n'
    '        "/sys/firmware/dmi/tables/smbios_entry_point",\n'
    '        "/sys/firmware/dmi/tables/DMI",\n'
    '    ),\n'
    '    "has_dmi_id": os.path.isdir("/sys/devices/virtual/dmi/id"),\n'
    '    "product_uuid": read_txt("/sys/devices/virtual/dmi/id/product_uuid"),\n'
    '    "product_serial": read_txt("/sys/devices/virtual/dmi/id/product_serial"),\n'
    '    "eth0_mac": read_txt(f"/sys/class/net/{wan}/address").lower(),\n'
    '    "tls_cert_sha256": read_sha("/etc/ssl/certs/ssl-cert-snakeoil.pem"),\n'
    '}\n'
    'print(json.dumps(out, sort_keys=True))\n'
)

_PERSISTED_IDENTITY_FIELDS = (
    'machine_id',
    'dbus_machine_id',
    'smbios_sha256',
    'eth0_mac',
    'tls_cert_sha256',
)


def _random_verify_mac():
    raw = os.urandom(3)
    return f'02:7a:74:{raw[0]:02x}:{raw[1]:02x}:{raw[2]:02x}'


def capture_identity_snapshot(engine, name):
    """Capture persisted machine-id, D-Bus ID, SMBIOS/DMI, MAC, and KasmVNC TLS cert digest."""
    proc = engine.exec_capture(
        name, 'root', ['/usr/bin/python3', '-c', _IDENTITY_SNAPSHOT_CODE], timeout=30,
    )
    if proc.returncode != 0:
        return None
    raw = proc.stdout.decode(errors='replace') if isinstance(proc.stdout, bytes) else (proc.stdout or '')
    try:
        data = json.loads(raw.strip())
        return data if isinstance(data, dict) else None
    except ValueError:
        return None


def compare_identity_snapshots(boot1, boot2, expected_mac=None):
    """Compare Boot 1 and Boot 2 identity snapshots; return (problem_or_None, detail)."""
    if not isinstance(boot1, dict) or not isinstance(boot2, dict):
        return 'failed to capture identity snapshot across two boots', ''
    issues = []
    fields = list(_PERSISTED_IDENTITY_FIELDS)
    if boot1.get('has_dmi_id') or boot2.get('has_dmi_id'):
        fields.extend(('product_uuid', 'product_serial'))
    for field in fields:
        v1 = str(boot1.get(field) or '').strip()
        v2 = str(boot2.get(field) or '').strip()
        if not v1:
            issues.append(f'boot1 missing {field}')
        elif v1 != v2:
            issues.append(f'{field} drifted ({v1[:16]} -> {v2[:16]})')
    if boot1.get('machine_id') and boot1.get('dbus_machine_id') != boot1.get('machine_id'):
        issues.append('dbus_machine_id != machine_id')
    if expected_mac:
        got_mac = str(boot2.get('eth0_mac') or '').lower()
        if got_mac != expected_mac.lower():
            issues.append(f'eth0_mac={got_mac!r} (want {expected_mac!r})')
    if issues:
        return '; '.join(issues), ''
    return None, (
        f'2-boot volume persisted mid={boot2["machine_id"][:8]}.. '
        f'smbios={boot2["smbios_sha256"][:12]}.. mac={boot2["eth0_mac"]} '
        f'tls={boot2["tls_cert_sha256"][:12]}..'
    )


def _check_desktop_auth(port, status, env, mode):
    url = f'https://127.0.0.1:{port}/'
    if env.get('ZT_AUTH') == '1':
        unauth = status
        authed = http_status(url, auth=(AUTH_USER, env['VNC_PW']))
        ok = unauth == 401 and authed == 200
        detail = (
            '401 without password, 200 with password'
            if ok
            else f'unauthenticated HTTP {unauth} (want 401), authenticated HTTP {authed} (want 200)'
        )
        return ok, detail
    ok = status == 200
    detail = (
        f'{mode} (no password, HTTP 200)'
        if ok
        else f'{mode} mode returned HTTP {status} (want 200)'
    )
    return ok, detail


def verify(engine, profile, mode=None, arch=None, keep=False, ref=None):
    """Boot the client's image across two stateful boots on a temp volume and run every check."""
    arch = arch or target_arch()
    mode = mode or accept_mode()
    net_mode = engine.net_mode_for(mode)
    name = f'zt-verify-{profile}'
    vol = f'zt-verify-state-{profile}-{secrets.token_hex(4)}'
    mac = _random_verify_mac()
    ref = ref or current_ref(profile, arch)
    if not engine.image_exists(ref):
        die(f'{ref} is not built; run "zt up {profile}"')
    env = container_env(profile, net_mode=net_mode, mode=mode)
    port = free_port()
    say(f'{profile}: booting {ref} ({platform_for(arch)}) to check it')
    engine.run_cli('rm', '-f', name, quiet=True, check=False)
    engine.ensure_volume(vol, profile)
    # `zt.*` labels mark runtime/ephemeral container state; `org.zt.*` marks image/volume ownership.
    failures = []
    try:
        engine.run_container(
            name, ref, env, port, {'zt.verify': profile},
            bind_host='127.0.0.1', arch=arch, volume=vol, mac_address=mac, quiet=True,
        )
        up, status = wait_for_desktop(port, 120)
        if not up:
            msg = f'desktop: did not answer on its port (HTTP {status})'
            say(f'  fail {msg}')
            failures.append(msg)
            for line in logs_tail(engine, name):
                say('      ' + line)
                failures.append('      ' + line)
        else:
            auth_ok, auth_detail = _check_desktop_auth(port, status, env, mode)
            findings = [('auth', 'ok' if auth_ok else 'fail', auth_detail)]
            findings += guest_report(engine, name, profile, env.get('TZ'), net_mode=net_mode, arch=arch)
            mux_problem, mux_detail = mux_e2e_holds(engine, name, profile)
            findings.append(('mux_e2e', 'fail' if mux_problem else 'ok', mux_problem or mux_detail))
            problem, measured = host_only_holds(engine, name, net_mode=net_mode, arch=arch)
            findings.append(('reachability', 'fail' if problem else 'ok', problem or measured))

            # Boot 2: recreate container against the SAME temp volume + MAC and assert persistence.
            boot1 = capture_identity_snapshot(engine, name)
            engine.run_cli('stop', '-t', '8', name, quiet=True, check=False)
            engine.run_cli('rm', '-f', name, quiet=True, check=False)
            engine.run_container(
                name, ref, env, port, {'zt.verify': profile},
                bind_host='127.0.0.1', arch=arch, volume=vol, mac_address=mac, quiet=True,
            )
            up2, status2 = wait_for_desktop(port, 120)
            if not up2:
                findings.append(('persistence', 'fail', f'boot 2 desktop did not answer (HTTP {status2})'))
            else:
                auth2_ok, auth2_detail = _check_desktop_auth(port, status2, env, mode)
                if not auth2_ok:
                    findings.append(('persistence', 'fail', f'boot 2 auth failed: {auth2_detail}'))
                else:
                    boot2 = capture_identity_snapshot(engine, name)
                    expect_mac = None if getattr(engine, 'is_rootless_podman', False) else mac
                    if engine.cli == 'container' and not getattr(engine, '_supports_network_mac', False):
                        expect_mac = None
                    p_err, p_detail = compare_identity_snapshots(boot1, boot2, expected_mac=expect_mac)
                    findings.append(('persistence', 'fail' if p_err else 'ok', p_err or p_detail))

            for check, state, detail in findings:
                say(f'  {state:<4} {check}' + (f': {detail}' if detail else ''))
                if state != 'ok':
                    failures.append(f'{check}: {detail}' if detail else check)
    finally:
        if failures and keep:
            say(f'left running to look at; remove with: {engine.cli} rm -f {name} && {engine.cli} volume rm {vol}')
        else:
            engine.run_cli('stop', '-t', '8', name, quiet=True, check=False)
            engine.run_cli('rm', '-f', name, quiet=True, check=False)
            engine.remove_volume(vol)
    return failures


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog='python3 -m zt.verify',
        description='Run live two-boot container image verification (CI / maintainer entry).',
    )
    parser.add_argument(
        '--profile', default='trustagent', choices=['all', *CLIENTS],
        help='client profile to verify (default: trustagent)',
    )
    parser.add_argument(
        '--accept', dest='mode', default=None, choices=list(ACCEPT_MODES),
        help='accept mode override (local, lan, or all)',
    )
    parser.add_argument(
        '--arch', default=None, choices=list(SUPPORTED_ARCHES),
        help='target architecture override (arm64 or amd64)',
    )
    parser.add_argument(
        '--build', action='store_true',
        help='build base and client image first if not already present',
    )
    parser.add_argument(
        '--keep', action='store_true',
        help='keep failing verify container and temp volume for inspection',
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    arch = args.arch or target_arch()
    engine = make_engine()
    engine.require()
    total_failures = []
    for profile in resolve_targets(args.profile):
        if args.build:
            build(engine, profile, arch=arch)
        total_failures.extend(
            verify(engine, profile, mode=args.mode, arch=arch, keep=args.keep)
        )
    sys.exit(1 if total_failures else 0)


if __name__ == '__main__':
    main()
