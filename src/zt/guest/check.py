#!/usr/bin/env python3
"""In-container verification harness for zt images.

Executed as root via `python3 - <json-spec>` inside a booted verify container.
All diagnostic output goes to stderr; a single JSON report is written to the
original stdout descriptor (duped to fd 3) so noisy subprocesses cannot corrupt
or forge findings.
"""
import concurrent.futures
import json
import os
import pwd
import re
import socket
import stat
import struct
import subprocess
import sys
import time

CHECKS = (
    'units',
    'ui',
    'libraries',
    'policy',
    'tunnel',
    'timezone',
    'log',
    'privilege',
    'setuid',
    'ownership',
    'programs',
)

DEFAULT_OWNERSHIP_EXCLUDES = (
    '/proc',
    '/sys',
    '/dev',
    '/run',
    '/tmp',
    '/var/tmp',
    '/home/kasm-user',
)

_EXEC_PATH_RE = re.compile(r'\bpath=([^ ;}]+)')


def _run(cmd, timeout=30, env=None):
    return subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        errors='replace',
        timeout=timeout,
        env=env,
    )


def _flat(text, limit=300):
    cleaned = ' | '.join(line.strip() for line in text.splitlines() if line.strip())
    return cleaned[:limit]


def elf_machine(path):
    """Return Elf_Ehdr.e_machine (uint16) for an ELF file, or None if not ELF."""
    try:
        with open(path, 'rb') as handle:
            header = handle.read(20)
    except OSError:
        return None
    if len(header) < 20 or header[:4] != b'\x7fELF':
        return None
    endian = '<' if header[5] == 1 else '>' if header[5] == 2 else None
    if endian is None:
        return None
    return struct.unpack(endian + 'H', header[18:20])[0]


def check_ownership(root='/', uid=1000, desktop_writes=(), extra_excludes=DEFAULT_OWNERSHIP_EXCLUDES):
    """Ensure uid owns nothing on the root filesystem outside allowed paths."""
    root = os.path.normpath(root)
    try:
        root_dev = os.lstat(root).st_dev
    except OSError as exc:
        return False, f'cannot stat {root}: {exc}'

    excludes = tuple(os.path.normpath(p) for p in (*extra_excludes, *desktop_writes) if p)

    def excluded(path):
        for prefix in excludes:
            if path == prefix or path.startswith(prefix + '/'):
                return True
        return False

    found = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        kept_dirs = []
        for name in sorted(dirnames):
            full = os.path.join(dirpath, name)
            if excluded(full):
                continue
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if st.st_dev != root_dev:
                continue
            if st.st_uid == uid:
                found.append(full)
                if len(found) >= 10:
                    return False, '; '.join(found)
            if not stat.S_ISLNK(st.st_mode):
                kept_dirs.append(name)
        dirnames[:] = kept_dirs

        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if excluded(full):
                continue
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if st.st_dev != root_dev:
                continue
            if st.st_uid == uid:
                found.append(full)
                if len(found) >= 10:
                    return False, '; '.join(found)

    if found:
        return False, '; '.join(found)
    return True, ''


def check_path_chain(path, root='/', must_exist=True, _seen=None):
    """Verify every directory and file along `path`, including resolved symlink
    targets and their ancestor chains, is owned by root and not group/world
    writable.

    When `must_exist` is False (e.g. an inactive stock systemd unit referencing
    an optional binary like /etc/rc.local), walk up to the deepest existing
    ancestor and audit its chain so nobody can plant the missing binary.
    Masked systemd unit targets (/dev/null) are ignored.
    """
    if _seen is None:
        _seen = set()
    problems = []
    norm = os.path.normpath(path)
    if norm == '/dev/null':
        return problems
    if norm in _seen:
        return problems
    _seen.add(norm)

    if not os.path.lexists(norm):
        if must_exist:
            return [f'{norm} (missing)']
        parent = os.path.dirname(norm)
        while parent and parent != norm and not os.path.lexists(parent):
            parent = os.path.dirname(parent)
        if parent and os.path.lexists(parent):
            return check_path_chain(parent, root=root, must_exist=True, _seen=_seen)
        return problems

    root_norm = os.path.normpath(root)
    rel = os.path.relpath(norm, root_norm)
    parts = [] if rel == '.' else rel.split(os.sep)
    cur = root_norm

    for index, part in enumerate(parts):
        cur = os.path.join(cur, part)
        try:
            st = os.lstat(cur)
        except OSError as exc:
            problems.append(f'{cur} ({exc.strerror or exc})')
            break

        mode_str = stat.filemode(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            if st.st_uid != 0:
                problems.append(f'{cur}(uid={st.st_uid} {mode_str})')
            try:
                link_val = os.readlink(cur)
            except OSError as exc:
                problems.append(f'{cur} (unreadable symlink: {exc})')
                break
            target = (
                link_val
                if os.path.isabs(link_val)
                else os.path.normpath(os.path.join(os.path.dirname(cur), link_val))
            )
            remainder = parts[index + 1:]
            next_target = os.path.join(target, *remainder) if remainder else target
            if os.path.normpath(next_target) == '/dev/null':
                break
            problems.extend(
                check_path_chain(next_target, root=root_norm, must_exist=must_exist, _seen=_seen)
            )
            break

        if st.st_uid != 0 or (st.st_mode & 0o022):
            problems.append(f'{cur}(uid={st.st_uid} {mode_str})')

    return problems


def parse_systemd_exec_paths(show_output):
    """Extract (unit_files, active_root_execs, optional_root_execs) from `systemctl show`."""
    unit_files = []
    active_execs = []
    optional_execs = []
    blocks = show_output.strip().split('\n\n')
    for block in blocks:
        if not block.strip():
            continue
        props = {}
        for line in block.splitlines():
            if '=' not in line:
                continue
            key, val = line.split('=', 1)
            props.setdefault(key, []).append(val.strip())

        for frag in props.get('FragmentPath', ()):
            if frag:
                unit_files.append(frag)
        for dropins in props.get('DropInPaths', ()):
            for item in dropins.split():
                if item:
                    unit_files.append(item)

        users = props.get('User', [''])
        user = users[0] if users else ''
        active = (props.get('ActiveState', [''])[0] == 'active')
        if user in ('', 'root', '0'):
            target_list = active_execs if active else optional_execs
            for key in ('ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStopPost'):
                for raw in props.get(key, ()):
                    for match in _EXEC_PATH_RE.findall(raw):
                        if match.startswith('/'):
                            target_list.append(match)
    return sorted(set(unit_files)), sorted(set(active_execs)), sorted(set(optional_execs))


def check_setuid(expected, root='/'):
    """Exact allowlist check for setuid/setgid regular files on root filesystem."""
    root = os.path.normpath(root)
    try:
        root_dev = os.lstat(root).st_dev
    except OSError as exc:
        return False, f'cannot stat {root}: {exc}'

    found = set()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        kept = []
        for name in dirnames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if st.st_dev == root_dev and not stat.S_ISLNK(st.st_mode):
                kept.append(name)
        dirnames[:] = kept

        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            if st.st_dev != root_dev or not stat.S_ISREG(st.st_mode):
                continue
            if st.st_mode & 0o6000:
                try:
                    owner = pwd.getpwuid(st.st_uid).pw_name
                except KeyError:
                    owner = str(st.st_uid)
                found.add(f'{st.st_mode & 0o7777:04o} {owner} {full}')

    wanted = {line.strip() for line in expected if line.strip()}
    if found == wanted:
        return True, ''
    missing = sorted(wanted - found)
    extra = sorted(found - wanted)
    parts = [f'missing: {m}' for m in missing[:4]] + [f'extra: {e}' for e in extra[:4]]
    return False, '; '.join(parts)


def start_stand_in(port):
    """Spawn detached dual-stack TCP + UDP echo listeners for live positive/negative probes."""
    code = (
        'import socket, sys, threading\n'
        'port = int(sys.argv[1])\n'
        'u = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)\n'
        'u.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n'
        'u.bind(("::", port))\n'
        'def serve_udp():\n'
        '    while True:\n'
        '        data, addr = u.recvfrom(2048)\n'
        '        u.sendto(b"pong:" + data, addr)\n'
        'threading.Thread(target=serve_udp, daemon=True).start()\n'
        's = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)\n'
        's.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n'
        's.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n'
        's.bind(("::", port))\n'
        's.listen(32)\n'
        'while True:\n'
        '    c, _ = s.accept()\n'
        '    c.close()\n'
    )
    subprocess.Popen(
        [sys.executable, '-c', code, str(port)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                    probe.settimeout(0.5)
                    probe.sendto(b'hi', ('127.0.0.1', port))
                    if probe.recvfrom(64)[0] == b'pong:hi':
                        return True
        except OSError:
            time.sleep(0.1)
    return False


def _kasm_windows():
    proc = _run([
        'setpriv', '--reuid', 'kasm-user', '--regid', 'kasm-user',
        '--init-groups', '--no-new-privs',
        'env', 'DISPLAY=:1', 'HOME=/home/kasm-user', 'wmctrl', '-l',
    ])
    titles = []
    for line in proc.stdout.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4:
            titles.append(parts[3].strip())
        elif parts:
            titles.append('')
    return titles


def _pgrep_exact(name):
    proc = _run(['pgrep', '-x', name])
    if proc.returncode != 0:
        return []
    return [int(tok) for tok in proc.stdout.split() if tok.isdigit()]


def check_units(units):
    down = []
    for _ in range(60):
        down = []
        for unit in units:
            if _run(['systemctl', 'is-active', '--quiet', unit]).returncode != 0:
                down.append(unit)
        if not down:
            return True, ''
        activating = any(
            _run(['systemctl', 'is-active', unit]).stdout.strip() == 'activating'
            for unit in down
        )
        if not activating:
            break
        time.sleep(1)

    reasons = []
    for unit in down:
        state = _run([
            'systemctl', 'show', unit,
            '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result', '-p', 'ExecMainStatus',
            '--value',
        ]).stdout.split()
        journal = _run(['journalctl', '--no-pager', '-q', '-n', '6', '-o', 'cat', '-u', unit]).stdout
        reasons.append(f'{unit}:{" ".join(state)} {_flat(journal, 120)}')
    return False, f'not active: {" ".join(down)} -- {"; ".join(reasons)}'[:300]


def check_ui(ui_name, launch):
    log_path = '/var/log/zt-sangfor.log'
    if launch:
        os.makedirs('/tmp/zt-verify', exist_ok=True)
        pw = pwd.getpwnam('kasm-user')
        os.chown('/tmp/zt-verify', pw.pw_uid, pw.pw_gid)
        log_path = '/tmp/zt-verify/ui.log'
        with open(log_path, 'wb') as log_out:
            os.fchown(log_out.fileno(), pw.pw_uid, pw.pw_gid)
            subprocess.Popen(
                [
                    'setpriv', '--reuid', 'kasm-user', '--regid', 'kasm-user',
                    '--init-groups', '--no-new-privs',
                    'env', 'HOME=/home/kasm-user', 'DISPLAY=:1', 'LANG=en_US.UTF-8',
                    launch,
                ],
                stdin=subprocess.DEVNULL,
                stdout=log_out,
                stderr=log_out,
                start_new_session=True,
                close_fds=True,
            )

    for _ in range(30):
        if _pgrep_exact(ui_name):
            break
        time.sleep(2)
    time.sleep(8)

    if not _pgrep_exact(ui_name):
        tail = ''
        try:
            with open(log_path, errors='replace') as handle:
                tail = _flat('\n'.join(handle.read().splitlines()[-6:]))
        except OSError:
            pass
        return False, f'{ui_name} is not staying up -- {tail}', log_path

    titles = _kasm_windows()
    joined = ';'.join(titles)
    if any('xmessage' in t for t in titles):
        return False, f'{ui_name} is up, but a warning dialog is in the way: {joined}', log_path
    real_windows = [t for t in titles if t and t != 'stalonetray']
    if not real_windows:
        return False, f'{ui_name} is up, but shows no window: {joined}', log_path
    return True, f'windows: {joined}', log_path


def check_libraries(vendor, libs):
    native = elf_machine('/bin/bash')
    if native is None:
        return False, 'cannot read native ELF machine from /bin/bash'

    paths = set()
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            exe = os.readlink(f'/proc/{entry}/exe')
        except OSError:
            continue
        if exe.startswith(vendor + '/') and not exe.endswith(' (deleted)'):
            paths.add(exe)

    for rel in libs:
        paths.add(os.path.join(vendor, rel))

    issues = []
    for path in sorted(paths):
        if not os.path.exists(path):
            issues.append(f'{path} is missing')
            continue
        machine = elf_machine(path)
        if machine is not None and machine != native:
            issues.append(f'{path} is built for another CPU (e_machine={machine}, expected {native})')
            continue
        if machine is not None:
            proc = _run(['ldd', path])
            missing_libs = [
                line.split()[0]
                for line in proc.stdout.splitlines()
                if '=> not found' in line
            ]
            for missing in missing_libs:
                issues.append(f'{path} needs {missing}')
            if (
                proc.returncode != 0
                and 'not a dynamic executable' not in (proc.stdout + proc.stderr)
                and 'statically linked' not in (proc.stdout + proc.stderr)
            ):
                issues.append(f'ldd {path} failed: {_flat(proc.stderr or proc.stdout, 120)}')
    if issues:
        return False, '; '.join(issues[:6])
    return True, ''


def _zt_rules():
    """Return canonical list of ZT-INPUT, filter INPUT-jump, and NAT zt rules."""
    rules = {}
    for tool in ('iptables-save', 'ip6tables-save'):
        proc = _run([tool])
        if proc.returncode != 0:
            return None, f'{tool} failed: {_flat(proc.stderr, 120)}'
        zt_lines = []
        filter_input = []
        table = ''
        for line in proc.stdout.splitlines():
            if line.startswith('*'):
                table = line[1:].strip()
                continue
            if table == 'filter' and line.startswith('-A INPUT '):
                filter_input.append(line)
            if (
                (table == 'filter' and (line.startswith('-A ZT-INPUT ') or line == '-A INPUT -j ZT-INPUT'))
                or (line.startswith('-A ') and 'zt:' in line)
            ):
                zt_lines.append(f'{table}:{line}')
        first_input = filter_input[0] if filter_input else ''
        rules[tool] = (zt_lines, first_input)
    return rules, ''


def check_policy(net_mode):
    before, err = _zt_rules()
    if err:
        return False, err
    env = dict(os.environ, ZT_NET_MODE=net_mode)
    rerun = _run(['/usr/local/bin/zt-net-setup.sh'], env=env)
    after, err = _zt_rules()
    if err:
        return False, err
    if rerun.returncode != 0:
        return False, f'zt-net-setup.sh exited {rerun.returncode}: {_flat(rerun.stderr, 150)}'
    for tool in ('iptables-save', 'ip6tables-save'):
        zt_lines, first_input = before[tool]
        if not zt_lines:
            return False, f'{tool}: no zt rules installed'
        if first_input != '-A INPUT -j ZT-INPUT':
            return False, f'{tool}: first INPUT rule is {first_input!r}, expected -A INPUT -j ZT-INPUT'
        if before[tool] != after[tool]:
            added = [line for line in after[tool][0] if line not in before[tool][0]]
            return False, f'{tool}: policy drifted until re-applied: {_flat(chr(10).join(added), 180)}'
    return True, ''


def _probe_from_netns(ns, host, port, proto='tcp'):
    if proto == 'udp':
        code = (
            'import socket, sys\n'
            'af = socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET\n'
            'try:\n'
            '    s = socket.socket(af, socket.SOCK_DGRAM)\n'
            '    s.settimeout(2.0)\n'
            '    s.sendto(b"zt", (sys.argv[1], int(sys.argv[2])))\n'
            '    print("through" if s.recvfrom(64)[0] == b"pong:zt" else "stopped")\n'
            'except OSError:\n'
            '    print("stopped")\n'
        )
    else:
        code = (
            'import socket, sys\n'
            'try:\n'
            '    socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=3).close()\n'
            '    print("through")\n'
            'except OSError:\n'
            '    print("stopped")\n'
        )
    proc = _run(['ip', 'netns', 'exec', ns, sys.executable, '-c', code, host, str(port)], timeout=10)
    return proc.stdout.strip() or 'stopped'


def check_tunnel(stand_in_port, net_mode):
    ns = 'zt-far'
    veth = 'utun9'

    def tunnel_rule_count():
        total = 0
        for tool in ('iptables', 'ip6tables'):
            proc = _run([tool, '-t', 'filter', '-S', 'ZT-INPUT'])
            total += sum(1 for line in proc.stdout.splitlines() if 'zt: tunnel' in line)
        return total

    def run_probes():
        targets = [
            ('desktop over IPv4', '10.254.0.1', 6901, 'tcp'),
            ('stand-in over IPv4', '10.254.0.1', stand_in_port, 'tcp'),
            ('stand-in over IPv6', 'fd99::1', stand_in_port, 'tcp'),
            ('stand-in UDP over IPv4', '10.254.0.1', stand_in_port, 'udp'),
            ('stand-in UDP over IPv6', 'fd99::1', stand_in_port, 'udp'),
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as pool:
            futs = [(label, pool.submit(_probe_from_netns, ns, h, p, proto)) for label, h, p, proto in targets]
            return {label: fut.result() for label, fut in futs}

    before_count = tunnel_rule_count()
    _run(['ip', 'netns', 'del', ns])
    _run(['ip', 'link', 'del', veth])
    try:
        setup_cmds = [
            ['ip', 'netns', 'add', ns],
            ['ip', 'link', 'add', veth, 'type', 'veth', 'peer', 'name', 'far'],
            ['ip', 'link', 'set', 'far', 'netns', ns],
            ['ip', 'addr', 'add', '10.254.0.1/24', 'dev', veth],
            ['ip', 'addr', 'add', 'fd99::1/64', 'dev', veth, 'nodad'],
            ['ip', 'link', 'set', veth, 'up'],
            ['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'netns', 'exec', ns, 'ip', 'addr', 'add', '10.254.0.2/24', 'dev', 'far'],
            ['ip', 'netns', 'exec', ns, 'ip', 'addr', 'add', 'fd99::2/64', 'dev', 'far', 'nodad'],
            ['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'far', 'up'],
        ]
        for cmd in setup_cmds:
            proc = _run(cmd)
            if proc.returncode != 0:
                return False, f'tunnel stand-in setup failed ({" ".join(cmd)}): {_flat(proc.stderr, 120)}'
        time.sleep(1.5)

        with_rules = run_probes()
        for tool in ('iptables', 'ip6tables'):
            for proto, comment in (('tcp', 'zt: tunnel'), ('udp', 'zt: tunnel udp')):
                rem = _run([
                    tool, '-t', 'filter', '-D', 'ZT-INPUT', '-i', 'utun+', '-p', proto,
                    '-m', 'comment', '--comment', comment, '-j', 'DROP',
                ])
                if rem.returncode != 0:
                    return False, f'could not remove {tool} {proto} tunnel rule for control: {_flat(rem.stderr, 120)}'
        without_rules = run_probes()
    finally:
        env = dict(os.environ, ZT_NET_MODE=net_mode)
        _run(['/usr/local/bin/zt-net-setup.sh'], env=env)
        _run(['ip', 'netns', 'del', ns])
        _run(['ip', 'link', 'del', veth])

    after_count = tunnel_rule_count()
    ok = (
        all(v == 'stopped' for v in with_rules.values())
        and all(v == 'through' for v in without_rules.values())
        and after_count == before_count
    )
    if ok:
        return True, ''
    return False, (
        f'with rules: {with_rules}; without rules: {without_rules}; '
        f'tunnel rules before {before_count}, after {after_count}'
    )


def check_timezone(tz):
    if not tz:
        return True, ''
    want = f'/usr/share/zoneinfo/{tz}'
    try:
        got = os.readlink('/etc/localtime')
    except OSError as exc:
        return False, f'/etc/localtime is not a symlink: {exc}'
    if got == want:
        return True, tz
    return False, f'/etc/localtime -> {got}, wanted {want}'


def check_log(log_path, needles):
    if not needles or not os.path.exists(log_path):
        return True, ''
    hits = []
    try:
        with open(log_path, errors='replace') as handle:
            for line in handle:
                for needle in needles:
                    if needle and needle in line:
                        hits.append(line.strip())
                        if len(hits) >= 3:
                            return False, _flat('\n'.join(hits))
    except OSError:
        return True, ''
    if hits:
        return False, _flat('\n'.join(hits))
    return True, ''


def check_privilege(ui_name, nnp_units):
    issues = []
    pids = _pgrep_exact(ui_name)
    inspected = 0
    for pid in pids:
        try:
            text = open(f'/proc/{pid}/status', errors='replace').read()
        except OSError:
            continue
        inspected += 1
        fields = {}
        for line in text.splitlines():
            if ':' in line:
                k, v = line.split(':', 1)
                fields[k.strip()] = v.strip()
        uid = fields.get('Uid', '').split()[0] if fields.get('Uid') else ''
        cap_eff = fields.get('CapEff', '')
        nnp = fields.get('NoNewPrivs', '')
        if uid == '0':
            issues.append(f'{pid} runs as root')
        if cap_eff != '0000000000000000':
            issues.append(f'{pid} holds capabilities {cap_eff}')
        if nnp != '1':
            issues.append(f'{pid} could still gain privileges (NoNewPrivs={nnp})')
    if inspected == 0:
        issues.append(f'no running {ui_name} process to inspect')

    for unit in nnp_units:
        val = _run(['systemctl', 'show', unit, '-p', 'NoNewPrivileges', '--value']).stdout.strip()
        if val != 'yes':
            issues.append(f'{unit} can still gain privileges (NoNewPrivileges={val or "missing"})')

    home = '/home/kasm-user'
    try:
        home_st = os.lstat(home)
        if home_st.st_mode & 0o002:
            issues.append('the home directory is world-writable')
        if home_st.st_uid == 0:
            issues.append('root owns /home/kasm-user')
    except OSError as exc:
        issues.append(f'cannot stat {home}: {exc}')

    stray_root = []
    for dirpath, dirnames, filenames in os.walk(home, followlinks=False):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            try:
                if os.lstat(full).st_uid == 0:
                    stray_root.append(full)
                    if len(stray_root) >= 3:
                        break
            except OSError:
                continue
        if len(stray_root) >= 3:
            break
    if stray_root:
        issues.append('root owns files in home: ' + ', '.join(stray_root))

    if issues:
        return False, '; '.join(issues)
    return True, ''


def check_programs(vendor, root_runs):
    must_exist = set()
    optional = set()
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            status = open(f'/proc/{entry}/status', errors='replace').read()
            uid_line = next((l for l in status.splitlines() if l.startswith('Uid:')), '')
            if uid_line and uid_line.split()[1] == '0':
                exe = os.readlink(f'/proc/{entry}/exe')
                if not exe.endswith(' (deleted)') and not exe.startswith('/run/rosetta/'):
                    must_exist.add(exe)
        except OSError:
            continue

    listed = _run(['systemctl', 'list-unit-files', '--type=service', '--no-legend']).stdout
    services = [
        line.split()[0] for line in listed.splitlines()
        if line.strip() and not line.split()[0].endswith('@.service')
    ]
    if services:
        shown = _run([
            'systemctl', 'show',
            '-p', 'ActiveState', '-p', 'User', '-p', 'FragmentPath', '-p', 'DropInPaths',
            '-p', 'ExecStart', '-p', 'ExecStartPre', '-p', 'ExecStartPost', '-p', 'ExecStopPost',
            *services,
        ]).stdout
        unit_files, active_execs, optional_execs = parse_systemd_exec_paths(shown)
        must_exist.update(unit_files)
        must_exist.update(active_execs)
        optional.update(optional_execs)

    for rel in root_runs:
        must_exist.add(os.path.join(vendor, rel))

    problems = []
    for path in sorted(must_exist):
        for problem in check_path_chain(path, must_exist=True):
            if problem not in problems:
                problems.append(problem)
                if len(problems) >= 6:
                    return False, '; '.join(problems)
    for path in sorted(optional - must_exist):
        for problem in check_path_chain(path, must_exist=False):
            if problem not in problems:
                problems.append(problem)
                if len(problems) >= 6:
                    return False, '; '.join(problems)
    if problems:
        return False, '; '.join(problems)
    return True, ''


def run_all(spec):
    stand_in_port = int(spec['stand_in_port'])
    stand_in_ok = start_stand_in(stand_in_port)
    results = {}

    def record(name, ok, detail=''):
        results[name] = {'ok': bool(ok), 'detail': str(detail)}

    ok, detail = check_units(spec['units'])
    record('units', ok, detail)

    ok, detail, log_path = check_ui(spec['ui'], spec.get('launch'))
    record('ui', ok, detail)

    ok, detail = check_libraries(spec['vendor'], spec['libs'])
    record('libraries', ok, detail)

    net_mode = spec.get('net_mode', 'gateway')
    ok, detail = check_policy(net_mode)
    record('policy', ok, detail)

    if not stand_in_ok:
        record('tunnel', False, f'stand-in listener did not start on port {stand_in_port}')
    else:
        ok, detail = check_tunnel(stand_in_port, net_mode)
        record('tunnel', ok, detail)

    ok, detail = check_timezone(spec.get('tz', ''))
    record('timezone', ok, detail)

    ok, detail = check_log(log_path, spec.get('quiet', ()))
    record('log', ok, detail)

    ok, detail = check_privilege(spec['ui'], spec.get('nnp_units', ('kasmvnc.service',)))
    record('privilege', ok, detail)

    ok, detail = check_setuid(spec.get('setuid', ()))
    record('setuid', ok, detail)

    ok, detail = check_ownership(desktop_writes=spec.get('desktop_writes', ()))
    record('ownership', ok, detail)

    ok, detail = check_programs(spec['vendor'], spec.get('root_runs', ()))
    record('programs', ok, detail)

    return {'version': 1, 'checks': results, 'complete': True}


def main():
    report_fd = os.dup(1)
    os.dup2(2, 1)
    spec = json.loads(sys.argv[1])
    report = run_all(spec)
    payload = (json.dumps(report, sort_keys=True) + '\n').encode()
    with os.fdopen(report_fd, 'wb') as out:
        out.write(payload)
        out.flush()


if __name__ == '__main__':
    main()
