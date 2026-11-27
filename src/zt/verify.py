"""Host-side image verification orchestrator (guest/check.py + guest/probe.py)."""
import base64
import ipaddress
import json
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from zt.build import current_ref
from zt.config import accept_mode, container_env, die, say, target_arch
from zt.resources import guest_script
from zt.spec import AUTH_USER, CHECKS, CLIENTS, STAND_IN, platform_for, system_setuid


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
        'libs': list(spec['libs']),
        'quiet': list(spec['quiet']),
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


def verify(engine, profile, mode=None, arch=None, keep=False, ref=None):
    """Boot the client's image once on loopback and run every guest + peer check."""
    arch = arch or target_arch()
    mode = mode or accept_mode()
    net_mode = engine.net_mode_for(mode)
    name = f'zt-verify-{profile}'
    ref = ref or current_ref(profile, arch)
    if not engine.image_exists(ref):
        die(f'{ref} is not built; run "zt up {profile}"')
    env = container_env(profile, net_mode=net_mode, mode=mode)
    port = free_port()
    say(f'{profile}: booting {ref} ({platform_for(arch)}) to check it')
    engine.run_cli('rm', '-f', name, quiet=True, check=False)
    # `zt.*` labels mark runtime/ephemeral container state; `org.zt.*` marks image/volume ownership.
    engine.run_container(
        name, ref, env, port, {'zt.verify': profile},
        bind_host='127.0.0.1', arch=arch, quiet=True,
    )
    failures = []
    try:
        up, status = wait_for_desktop(port, 120)
        if not up:
            msg = f'desktop: did not answer on its port (HTTP {status})'
            say(f'  fail {msg}')
            failures.append(msg)
            for line in logs_tail(engine, name):
                say('      ' + line)
                failures.append('      ' + line)
        else:
            url = f'https://127.0.0.1:{port}/'
            if env.get('ZT_AUTH') == '1':
                unauth = status
                authed = http_status(url, auth=(AUTH_USER, env['VNC_PW']))
                auth_ok = unauth == 401 and authed == 200
                auth_detail = (
                    '401 without password, 200 with password'
                    if auth_ok
                    else f'unauthenticated HTTP {unauth} (want 401), authenticated HTTP {authed} (want 200)'
                )
            else:
                auth_ok = status == 200
                auth_detail = (
                    f'{mode} (no password, HTTP 200)'
                    if auth_ok
                    else f'{mode} mode returned HTTP {status} (want 200)'
                )
            findings = [('auth', 'ok' if auth_ok else 'fail', auth_detail)]
            findings += guest_report(engine, name, profile, env.get('TZ'), net_mode=net_mode, arch=arch)
            problem, measured = host_only_holds(engine, name, net_mode=net_mode, arch=arch)
            findings.append(('reachability', 'fail' if problem else 'ok', problem or measured))
            for check, state, detail in findings:
                say(f'  {state:<4} {check}' + (f': {detail}' if detail else ''))
                if state != 'ok':
                    failures.append(f'{check}: {detail}' if detail else check)
    finally:
        if failures and keep:
            say(f'left running to look at; remove it with: {engine.cli} rm -f {name}')
        else:
            engine.run_cli('stop', name, quiet=True, check=False)
            engine.run_cli('rm', '-f', name, quiet=True, check=False)
    return failures
