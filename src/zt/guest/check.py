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
import ssl
import stat
import struct
import subprocess
import sys
import time
import urllib.request

CHECKS = (
    'units',
    'ui',
    'libraries',
    'policy',
    'routing',
    'loopback_isolation',
    'tunnel',
    'timezone',
    'identity',
    'limits',
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
        'import os, socket, sys, threading\n'
        'port = int(sys.argv[1])\n'
        'has_v6 = os.path.isdir("/proc/sys/net/ipv6")\n'
        'af = socket.AF_INET6 if has_v6 else socket.AF_INET\n'
        'bind_addr = ("::", port) if has_v6 else ("0.0.0.0", port)\n'
        'u = socket.socket(af, socket.SOCK_DGRAM)\n'
        'if has_v6:\n'
        '    u.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n'
        'u.bind(bind_addr)\n'
        'def serve_udp():\n'
        '    while True:\n'
        '        data, addr = u.recvfrom(2048)\n'
        '        u.sendto(b"pong:" + data, addr)\n'
        'threading.Thread(target=serve_udp, daemon=True).start()\n'
        'def serve_tcp(conn):\n'
        '    try:\n'
        '        conn.settimeout(2.0)\n'
        '        data = conn.recv(64)\n'
        '        if data:\n'
        '            conn.sendall(b"echo:" + data)\n'
        '    except OSError:\n'
        '        pass\n'
        '    finally:\n'
        '        conn.close()\n'
        's = socket.socket(af, socket.SOCK_STREAM)\n'
        's.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n'
        'if has_v6:\n'
        '    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)\n'
        's.bind(bind_addr)\n'
        's.listen(32)\n'
        'while True:\n'
        '    c, _ = s.accept()\n'
        '    threading.Thread(target=serve_tcp, args=(c,), daemon=True).start()\n'
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


def _read_wan_info():
    """Return (wan, gateway, subnet) from /run/zt/wan.env, else default route."""
    wan, gateway, subnet = '', '', ''
    try:
        with open('/run/zt/wan.env', encoding='utf-8') as handle:
            for line in handle:
                if '=' not in line:
                    continue
                key, val = line.split('=', 1)
                val = val.strip()
                if key == 'WAN' and val:
                    wan = val
                elif key == 'GATEWAY' and val:
                    gateway = val
                elif key == 'SUBNET' and val:
                    subnet = val
    except OSError:
        pass
    if not wan or not gateway:
        proc = _run(['ip', '-4', 'route', 'show', 'default'])
        for line in proc.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[1] == 'via':
                if not parts[4].startswith(('lo', 'tun', 'utun', 'vnic', 'tap', 'wg')):
                    gateway = gateway or parts[2]
                    wan = wan or parts[4]
                    break
    return wan, gateway, subnet


def _read_wan_iface():
    """Return boot-snapshotted WAN interface from /run/zt/wan.env, else default route."""
    return _read_wan_info()[0]


def _has_ipv6():
    return os.path.isdir('/proc/sys/net/ipv6')


def _zt_rules():
    """Return canonical ZT chain rules plus first filter INPUT/OUTPUT jumps."""
    rules = {}
    tools = ('iptables-save', 'ip6tables-save') if _has_ipv6() else ('iptables-save',)
    for tool in tools:
        proc = _run([tool])
        if proc.returncode != 0:
            return None, f'{tool} failed: {_flat(proc.stderr, 120)}'
        zt_lines = []
        filter_input = []
        filter_output = []
        table = ''
        for line in proc.stdout.splitlines():
            if line.startswith('*'):
                table = line[1:].strip()
                continue
            if table == 'filter' and line.startswith('-A INPUT '):
                filter_input.append(line)
            if table == 'filter' and line.startswith('-A OUTPUT '):
                filter_output.append(line)
            if (
                (table == 'filter' and (
                    line.startswith('-A ZT-INPUT ')
                    or line.startswith('-A ZT-OUTPUT ')
                    or line == '-A INPUT -j ZT-INPUT'
                    or line == '-A OUTPUT -j ZT-OUTPUT'
                ))
                or (table == 'mangle' and (
                    line.startswith('-A ZT-')
                    or line == '-A PREROUTING -j ZT-PREROUTING'
                    or line == '-A OUTPUT -j ZT-OUTPUT'
                    or line == '-A POSTROUTING -j ZT-POSTROUTING'
                ))
                or (line.startswith('-A ') and 'zt:' in line)
            ):
                zt_lines.append(f'{table}:{line}')
        first_input = filter_input[0] if filter_input else ''
        first_output = filter_output[0] if filter_output else ''
        rules[tool] = (zt_lines, first_input, first_output)
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

    if not _read_wan_iface():
        return False, 'missing /run/zt/wan.env WAN snapshot'
    try:
        with open('/run/zt/iptables-backend', encoding='utf-8') as handle:
            backend = handle.read().strip()
    except OSError:
        backend = ''
    if backend not in ('nft', 'legacy'):
        return False, f'missing or invalid /run/zt/iptables-backend ({backend!r})'

    rt90 = _run(['ip', '-4', 'route', 'show', 'table', '90'])
    if rt90.returncode != 0 or 'default via ' not in rt90.stdout:
        return False, f'table 90 asymmetric return route missing: {_flat(rt90.stdout + rt90.stderr, 120)}'

    for tool in before:
        zt_lines, first_input, first_output = before[tool]
        if not zt_lines:
            return False, f'{tool}: no zt rules installed'
        if first_input != '-A INPUT -j ZT-INPUT':
            return False, f'{tool}: first INPUT rule is {first_input!r}, expected -A INPUT -j ZT-INPUT'
        joined = '\n'.join(zt_lines)
        for sentinel in ('zt: loopback guard', 'zt: host only', 'zt: host only udp', 'zt: tunnel', 'zt: tunnel udp'):
            if sentinel not in joined:
                return False, f'{tool}: missing required sentinel {sentinel!r}'
        if tool == 'iptables-save':
            if first_output != '-A OUTPUT -j ZT-OUTPUT':
                return False, f'{tool}: first OUTPUT rule is {first_output!r}, expected -A OUTPUT -j ZT-OUTPUT'
            for sentinel in ('zt: kasmvnc out', 'zt: tunnel nat'):
                if sentinel not in joined:
                    return False, f'{tool}: missing required sentinel {sentinel!r}'
            if os.path.exists('/run/zt/mangle.ok') and 'zt: mss' not in joined:
                return False, f'{tool}: mangle.ok set but missing zt: mss rules'
            if os.path.exists('/run/zt/connmark.ok') and 'zt: kasmvnc mark' not in joined:
                return False, f'{tool}: connmark.ok set but missing zt: kasmvnc mark rules'
        if before[tool] != after[tool]:
            added = [line for line in after[tool][0] if line not in before[tool][0]]
            return False, f'{tool}: policy drifted until re-applied: {_flat(chr(10).join(added), 180)}'

    # Verify unified backend (iptables-legacy sees ZT-INPUT) and live OUTPUT #1 self-healing.
    legacy_probe = _run(['iptables-legacy', '-t', 'filter', '-L', 'ZT-INPUT', '-n'])
    if legacy_probe.returncode != 0:
        return False, f'iptables-legacy split-brain: {_flat(legacy_probe.stderr, 120)}'

    tamper_chain = 'ZT-VERIFY-TAMPER'
    internal_env = dict(os.environ, ZT_IPT_INTERNAL='1')
    try:
        _run(['iptables', '-t', 'filter', '-N', tamper_chain])
        ins = _run(['iptables', '-t', 'filter', '-I', 'OUTPUT', '1', '-j', tamper_chain])
        if ins.returncode != 0:
            return False, f'tamper probe failed: {_flat(ins.stderr, 120)}'
        healed, err = _zt_rules()
        if err:
            return False, err
        if healed['iptables-save'][2] != '-A OUTPUT -j ZT-OUTPUT':
            return False, f'zt-iptables failed to self-heal OUTPUT #1: got {healed["iptables-save"][2]!r}'
    finally:
        _run(['iptables', '-t', 'filter', '-D', 'OUTPUT', '-j', tamper_chain], env=internal_env)
        _run(['iptables', '-t', 'filter', '-X', tamper_chain], env=internal_env)

    # Adversarial full-table iptables-restore (without --noflush) wiping filter & nat MASQUERADE.
    try:
        wipe_filter = (
            '*filter\n'
            ':INPUT ACCEPT [0:0]\n'
            ':FORWARD ACCEPT [0:0]\n'
            ':OUTPUT ACCEPT [0:0]\n'
            'COMMIT\n'
        )
        proc_f = subprocess.run(
            ['iptables-restore'],
            input=wipe_filter, capture_output=True, text=True, errors='replace', timeout=30,
        )
        if proc_f.returncode != 0:
            return False, f'iptables-restore filter tamper failed: {_flat(proc_f.stderr, 120)}'
        healed_f, err = _zt_rules()
        if err:
            return False, err
        f_lines, f_in, f_out = healed_f['iptables-save']
        f_joined = '\n'.join(f_lines)
        if f_in != '-A INPUT -j ZT-INPUT' or f_out != '-A OUTPUT -j ZT-OUTPUT':
            return False, f'iptables-restore filter wipe broke jumps: INPUT={f_in!r} OUTPUT={f_out!r}'
        for sentinel in ('zt: loopback guard', 'zt: host only', 'zt: tunnel', 'zt: kasmvnc out'):
            if sentinel not in f_joined:
                return False, f'iptables-restore filter wipe lost sentinel {sentinel!r}'

        # Strip zt: tunnel nat rules from *nat and restore without --noflush (preserving engine chains).
        nat_save = _run(['iptables-save', '-t', 'nat'])
        if nat_save.returncode == 0 and 'zt: tunnel nat' in nat_save.stdout:
            stripped_nat = '\n'.join(
                line for line in nat_save.stdout.splitlines() if 'zt: tunnel nat' not in line
            ) + '\n'
            proc_n = subprocess.run(
                ['iptables-restore'],
                input=stripped_nat, capture_output=True, text=True, errors='replace', timeout=30,
            )
            if proc_n.returncode != 0:
                return False, f'iptables-restore nat tamper failed: {_flat(proc_n.stderr, 120)}'
            healed_nat = _run(['iptables-save', '-t', 'nat']).stdout
            if healed_nat.count('zt: tunnel nat') < 3:
                return False, 'iptables-restore nat wipe lost zt: tunnel nat MASQUERADE rules'
    finally:
        _run(['/usr/local/bin/zt-net-setup.sh', '--reapply'], env=internal_env)

    return True, f'backend={backend}'


def check_routing(is_rootless=False):
    """Verify table 90 asymmetric return routing and $WAN rp_filter=2 hold under default-route hijack."""
    wan, gateway, _ = _read_wan_info()
    if not wan or not gateway:
        return False, 'missing WAN/gateway in /run/zt/wan.env'
    veth = 'utun9'
    peer = 'utun9p'
    all_rpf_path = '/proc/sys/net/ipv4/conf/all/rp_filter'
    wan_rpf_path = f'/proc/sys/net/ipv4/conf/{wan}/rp_filter'
    orig_all_rpf = None
    _run(['ip', 'link', 'del', veth])
    try:
        for cmd in (
            ['ip', 'link', 'add', veth, 'type', 'veth', 'peer', 'name', peer],
            ['ip', 'addr', 'add', '10.253.0.1/24', 'dev', veth],
            ['ip', 'link', 'set', veth, 'up'],
            ['ip', 'link', 'set', peer, 'up'],
            ['ip', '-4', 'route', 'replace', '0.0.0.0/1', 'dev', veth],
            ['ip', '-4', 'route', 'replace', '128.0.0.0/1', 'dev', veth],
        ):
            proc = _run(cmd)
            if proc.returncode != 0:
                return False, f'routing hijack setup failed ({" ".join(cmd)}): {_flat(proc.stderr, 120)}'

        if os.access(all_rpf_path, os.W_OK):
            try:
                with open(all_rpf_path, encoding='utf-8') as handle:
                    orig_all_rpf = handle.read().strip()
                with open(all_rpf_path, 'w', encoding='utf-8') as handle:
                    handle.write('1\n')
            except OSError:
                orig_all_rpf = None

        # Positive control: unmarked traffic routes into the simulated VPN tunnel.
        unmarked = _run(['ip', '-4', 'route', 'get', '203.0.113.10'])
        if unmarked.returncode != 0 or f'dev {veth}' not in unmarked.stdout:
            return False, f'simulated default-route hijack did not take effect: {_flat(unmarked.stdout + unmarked.stderr, 120)}'

        # Marked KasmVNC return traffic MUST bypass tunnel via table 90 -> $GATEWAY dev $WAN.
        if os.path.exists('/run/zt/connmark.ok'):
            marked = _run(['ip', '-4', 'route', 'get', '203.0.113.10', 'mark', '0x10000'])
            want = f'via {gateway} dev {wan}'
            if marked.returncode != 0 or want not in marked.stdout:
                return False, f'marked route bypassed table 90 (got {_flat(marked.stdout + marked.stderr, 120)!r}, want {want!r})'
            route_note = f'mark 0x10000 -> {want}'
        else:
            rt90 = _run(['ip', '-4', 'route', 'show', 'table', '90'])
            want = f'default via {gateway} dev {wan}'
            if rt90.returncode != 0 or want not in rt90.stdout:
                return False, f'table 90 fallback route missing: {_flat(rt90.stdout + rt90.stderr, 120)}'
            route_note = f'table 90 fallback -> {want}'

        try:
            with open(wan_rpf_path, encoding='utf-8') as handle:
                wan_rpf = handle.read().strip()
        except OSError as exc:
            return False, f'cannot read {wan_rpf_path}: {exc}'
        try:
            with open(all_rpf_path, encoding='utf-8') as handle:
                all_rpf = handle.read().strip()
        except OSError:
            all_rpf = ''

        if is_rootless and _is_mount_readonly('/proc/sys/net/ipv4/conf'):
            if wan_rpf != '2' and all_rpf != '2':
                return False, f'rootless rp_filter not loose (all={all_rpf!r}, {wan}={wan_rpf!r})'
        elif wan_rpf != '2':
            return False, f'{wan_rpf_path}={wan_rpf!r} (want 2 to override all.rp_filter=1)'

        return True, f'{route_note}; {wan}.rp_filter={wan_rpf}'
    finally:
        _run(['ip', '-4', 'route', 'del', '0.0.0.0/1', 'dev', veth])
        _run(['ip', '-4', 'route', 'del', '128.0.0.0/1', 'dev', veth])
        _run(['ip', 'link', 'del', veth])
        if orig_all_rpf is not None:
            try:
                with open(all_rpf_path, 'w', encoding='utf-8') as handle:
                    handle.write(orig_all_rpf + '\n')
            except OSError:
                pass


def _loopback_guard_packets():
    """Return total packet counter on `zt: loopback guard` in IPv4 ZT-INPUT."""
    proc = _run(['iptables', '-t', 'filter', '-L', 'ZT-INPUT', '-v', '-n', '-x'])
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        if 'zt: loopback guard' in line:
            parts = line.split()
            if parts and parts[0].isdigit():
                return int(parts[0])
    return None


def check_loopback_isolation(stand_in_port, net_mode, engine_cli='', is_rootless_podman=False, is_rootless=False):
    """Verify non-lo -> 127.0.0.1 is dropped even under route_localnet=1, and /proc/sys/net/core stays ro."""
    if engine_cli == 'docker' and not is_rootless_podman and os.path.isdir('/proc/sys/net/core'):
        if not _is_mount_readonly('/proc/sys/net/core'):
            return False, '/proc/sys/net/core is writable on Docker'
        try:
            with open('/proc/sys/net/core/somaxconn', 'w', encoding='utf-8'):
                pass
            return False, '/proc/sys/net/core/somaxconn accepted write open on Docker'
        except OSError:
            pass

    wan = _read_wan_iface()
    if not wan:
        return False, 'missing WAN interface for loopback isolation probe'
    ns = 'zt-lo-far'
    veth = 'utun8'
    internal_env = dict(os.environ, ZT_IPT_INTERNAL='1')
    _run(['ip', 'netns', 'del', ns])
    _run(['ip', 'link', 'del', veth])
    try:
        # Leave `lo` down in the disposable probe netns so 127.0.0.1 is NOT in its local
        # table and packets to 127.0.0.1 actually egress `far` -> `utun8` into the container.
        setup_cmds = [
            ['ip', 'netns', 'add', ns],
            ['ip', 'link', 'add', veth, 'type', 'veth', 'peer', 'name', 'far'],
            ['ip', 'link', 'set', 'far', 'netns', ns],
            ['ip', 'addr', 'add', '10.253.1.1/24', 'dev', veth],
            ['ip', 'link', 'set', veth, 'up'],
            ['ip', 'netns', 'exec', ns, 'ip', 'addr', 'add', '10.253.1.2/24', 'dev', 'far'],
            ['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'far', 'up'],
            ['ip', 'netns', 'exec', ns, 'ip', 'route', 'add', '127.0.0.1/32', 'via', '10.253.1.1', 'dev', 'far'],
        ]
        for cmd in setup_cmds:
            proc = _run(cmd)
            if proc.returncode != 0:
                return False, f'loopback probe setup failed ({" ".join(cmd)}): {_flat(proc.stderr, 120)}'

        # Enable route_localnet=1 on both ends to simulate aTrust sysctl-hook.
        rl_path = f'/proc/sys/net/ipv4/conf/{veth}/route_localnet'
        try:
            with open(rl_path, 'w', encoding='utf-8') as handle:
                handle.write('1\n')
        except OSError as exc:
            cur_rl = ''
            try:
                with open(rl_path, encoding='utf-8') as handle:
                    cur_rl = handle.read().strip()
            except OSError:
                pass
            if cur_rl != '1':
                if is_rootless and _is_mount_readonly('/proc/sys/net/ipv4/conf'):
                    return True, 'rootless /proc/sys/net/ipv4/conf ro (route_localnet=0); zt: loopback guard active'
                return False, f'cannot set {veth}.route_localnet=1: {exc}'
        proc_far_rl = _run([
            'ip', 'netns', 'exec', ns, '/bin/sh', '-c',
            'if ! printf 1 > /proc/sys/net/ipv4/conf/far/route_localnet 2>/dev/null; then '
            'mount --bind /proc/sys/net/ipv4/conf /proc/sys/net/ipv4/conf && '
            'mount -o remount,rw /proc/sys/net/ipv4/conf && '
            'printf 1 > /proc/sys/net/ipv4/conf/far/route_localnet; fi',
        ])
        if proc_far_rl.returncode != 0:
            return False, f'cannot set far.route_localnet=1: {_flat(proc_far_rl.stderr, 120)}'

        before_pkts = _loopback_guard_packets()
        with_guard = _probe_from_netns(ns, '127.0.0.1', stand_in_port, 'tcp')
        after_pkts = _loopback_guard_packets()
        if with_guard != 'stopped':
            return False, f'non-lo packet to 127.0.0.1:{stand_in_port} was NOT blocked (got {with_guard!r})'
        if before_pkts is not None and after_pkts is not None and after_pkts <= before_pkts:
            return False, f'zt: loopback guard counter did not increment ({before_pkts} -> {after_pkts})'

        # Negative control: removing loopback guard + tunnel drop lets route_localnet=1 reach 127.0.0.1.
        for rule in (
            ['iptables', '-t', 'filter', '-D', 'ZT-INPUT', '!', '-i', 'lo', '-d', '127.0.0.0/8',
             '-m', 'comment', '--comment', 'zt: loopback guard', '-j', 'DROP'],
            ['iptables', '-t', 'filter', '-D', 'ZT-INPUT', '!', '-i', wan, '-p', 'tcp',
             '-m', 'comment', '--comment', 'zt: tunnel', '-j', 'DROP'],
        ):
            rem = _run(rule, env=internal_env)
            if rem.returncode != 0:
                return False, f'loopback negative control delete failed: {_flat(rem.stderr, 120)}'
        without_guard = _probe_from_netns(ns, '127.0.0.1', stand_in_port, 'tcp')
        if without_guard != 'through':
            return False, f'loopback negative control expected through, got {without_guard!r}'

        delta = (after_pkts - before_pkts) if (before_pkts is not None and after_pkts is not None) else 0
        return True, f'route_localnet=1 blocked by zt: loopback guard (+{delta} pkts), through with guard removed'
    finally:
        env = dict(os.environ, ZT_NET_MODE=net_mode)
        _run(['/usr/local/bin/zt-net-setup.sh'], env=env)
        _run(['ip', 'netns', 'del', ns])
        _run(['ip', 'link', 'del', veth])


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
    has_v6 = _has_ipv6()
    ipt_tools = ('iptables', 'ip6tables') if has_v6 else ('iptables',)

    def tunnel_rule_count():
        total = 0
        for tool in ipt_tools:
            proc = _run([tool, '-t', 'filter', '-S', 'ZT-INPUT'])
            total += sum(1 for line in proc.stdout.splitlines() if 'zt: tunnel' in line)
        return total

    def run_probes():
        targets = [
            ('desktop over IPv4', '10.254.0.1', 6901, 'tcp'),
            ('stand-in over IPv4', '10.254.0.1', stand_in_port, 'tcp'),
            ('stand-in UDP over IPv4', '10.254.0.1', stand_in_port, 'udp'),
        ]
        if has_v6:
            targets.extend([
                ('stand-in over IPv6', 'fd99::1', stand_in_port, 'tcp'),
                ('stand-in UDP over IPv6', 'fd99::1', stand_in_port, 'udp'),
            ])
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
            *([['ip', 'addr', 'add', 'fd99::1/64', 'dev', veth, 'nodad']] if has_v6 else []),
            ['ip', 'link', 'set', veth, 'up'],
            ['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'lo', 'up'],
            ['ip', 'netns', 'exec', ns, 'ip', 'addr', 'add', '10.254.0.2/24', 'dev', 'far'],
            *([['ip', 'netns', 'exec', ns, 'ip', 'addr', 'add', 'fd99::2/64', 'dev', 'far', 'nodad']] if has_v6 else []),
            ['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'far', 'up'],
        ]
        for cmd in setup_cmds:
            proc = _run(cmd)
            if proc.returncode != 0:
                return False, f'tunnel stand-in setup failed ({" ".join(cmd)}): {_flat(proc.stderr, 120)}'
        time.sleep(1.5)

        with_rules = run_probes()
        wan = _read_wan_iface()
        if not wan:
            return False, 'cannot determine WAN interface for tunnel control'
        internal_env = dict(os.environ, ZT_IPT_INTERNAL='1')
        for tool in ipt_tools:
            for proto, comment in (('tcp', 'zt: tunnel'), ('udp', 'zt: tunnel udp')):
                rem = _run([
                    tool, '-t', 'filter', '-D', 'ZT-INPUT', '!', '-i', wan, '-p', proto,
                    '-m', 'comment', '--comment', comment, '-j', 'DROP',
                ], env=internal_env)
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


_FORBIDDEN_VENDOR_CAPS = (
    ('CAP_SYS_MODULE', 16),
    ('CAP_SYS_RAWIO', 17),
    ('CAP_SYS_CHROOT', 18),
    ('CAP_SYS_PTRACE', 19),
    ('CAP_SYS_ADMIN', 21),
)
_NOFILE_HARD_MAX = 65536


def _parse_proc_limits(text):
    """Parse `/proc/<pid>/limits` into {limit_name: (soft_int_or_None, hard_int_or_None)}."""
    parsed = {}
    for line in (text or '').splitlines():
        if line.startswith('Limit'):
            continue
        parts = re.split(r'\s{2,}', line.strip())
        if len(parts) < 3:
            continue
        name, soft_raw, hard_raw = parts[0], parts[1], parts[2]
        soft = None if soft_raw == 'unlimited' else (int(soft_raw) if soft_raw.isdigit() else None)
        hard = None if hard_raw == 'unlimited' else (int(hard_raw) if hard_raw.isdigit() else None)
        parsed[name] = (soft, hard)
    return parsed


def _parse_cap_bnd(status_text):
    """Extract integer `CapBnd` bitmask from `/proc/<pid>/status`, or None."""
    for line in (status_text or '').splitlines():
        if line.startswith('CapBnd:'):
            raw = line.split(':', 1)[1].strip()
            try:
                return int(raw, 16)
            except ValueError:
                return None
    return None


def _is_mount_readonly(path):
    """True when `path` sits on a read-only mount (ST_RDONLY via statvfs)."""
    try:
        return bool(os.statvfs(path).f_flag & getattr(os, 'ST_RDONLY', 1))
    except OSError:
        return False


def check_identity(
    machine_id_path='/etc/machine-id',
    dbus_machine_id_path='/var/lib/dbus/machine-id',
    firmware_dir='/sys/firmware',
    dmi_id_dir='/sys/devices/virtual/dmi/id',
    check_ro=True,
):
    """Verify deterministic machine-id, D-Bus sync, SMBIOS 3.0, and sysfs DMI tables."""
    issues = []
    mid = ''
    try:
        with open(machine_id_path, encoding='utf-8') as handle:
            mid = handle.read().strip()
    except OSError as exc:
        issues.append(f'{machine_id_path} unreadable: {exc}')
    if mid and not re.fullmatch(r'[0-9a-f]{32}', mid):
        issues.append(f'{machine_id_path} invalid: {mid!r}')
    elif not mid and not issues:
        issues.append(f'{machine_id_path} is empty')

    if os.path.lexists(dbus_machine_id_path):
        try:
            with open(dbus_machine_id_path, encoding='utf-8') as handle:
                dbus_mid = handle.read().strip()
            if mid and dbus_mid != mid:
                issues.append(f'{dbus_machine_id_path} differs from {machine_id_path}')
        except OSError as exc:
            issues.append(f'{dbus_machine_id_path} unreadable: {exc}')
    elif os.path.isdir(os.path.dirname(dbus_machine_id_path)):
        issues.append(f'{dbus_machine_id_path} is missing')

    tables_dir = os.path.join(firmware_dir, 'dmi', 'tables')
    for fname in ('smbios_entry_point', 'DMI'):
        fpath = os.path.join(tables_dir, fname)
        try:
            st = os.lstat(fpath)
            if not stat.S_ISREG(st.st_mode) or st.st_size == 0:
                issues.append(f'{fpath} is empty or not a regular file')
            elif (st.st_mode & 0o777) != 0o444:
                issues.append(f'{fpath} mode is {st.st_mode & 0o777:04o} (want 0444)')
        except OSError as exc:
            issues.append(f'{fpath} missing: {exc}')
    if check_ro and os.path.isdir(firmware_dir) and not _is_mount_readonly(firmware_dir):
        issues.append(f'{firmware_dir} is not mounted read-only')

    if os.path.isdir(dmi_id_dir):
        for fname in ('product_serial', 'product_uuid'):
            fpath = os.path.join(dmi_id_dir, fname)
            try:
                st = os.lstat(fpath)
                if not stat.S_ISREG(st.st_mode):
                    issues.append(f'{fpath} is not a regular file')
                elif (st.st_mode & 0o777) != 0o444:
                    issues.append(f'{fpath} mode is {st.st_mode & 0o777:04o} (want 0444)')
                else:
                    with open(fpath, encoding='utf-8', errors='replace') as handle:
                        if not handle.read().strip():
                            issues.append(f'{fpath} is empty')
            except OSError as exc:
                issues.append(f'{fpath} missing: {exc}')
        if check_ro and not _is_mount_readonly(dmi_id_dir):
            issues.append(f'{dmi_id_dir} is not mounted read-only')

    if issues:
        return False, '; '.join(issues[:6])
    return True, ''


def check_limits(units, nnp_units, engine_cli='', is_rootless_podman=False, is_rootless=False):
    """Verify NOFILE/CORE limits, vendor CapBnd hardening, and /proc/sys/net/core isolation."""
    issues = []

    def inspect_pid_limits(label, pid):
        try:
            with open(f'/proc/{pid}/limits', errors='replace') as handle:
                lim = _parse_proc_limits(handle.read())
        except OSError:
            return
        nofile = lim.get('Max open files')
        if nofile is None or nofile[1] is None or nofile[1] > _NOFILE_HARD_MAX:
            issues.append(f'{label}(pid {pid}) Max open files hard={nofile[1] if nofile else "?"} (> {_NOFILE_HARD_MAX})')
        core = lim.get('Max core file size')
        if core is None or core[1] != 0:
            issues.append(f'{label}(pid {pid}) Max core file size hard={core[1] if core else "?"} (want 0)')

    if engine_cli == 'docker':
        inspect_pid_limits('pid1', 1)

    vendor_units = [u for u in nnp_units if u not in ('kasmvnc.service', 'zt-sangfor-ui.service')]
    all_units = sorted(set(units) | set(nnp_units))
    inspected_pids = 0
    for unit in all_units:
        raw = _run([
            'systemctl', 'show', unit,
            '-p', 'MainPID', '-p', 'CapabilityBoundingSet',
        ]).stdout
        props = {}
        for line in raw.splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                props[k.strip()] = v.strip()
        pid = int(props['MainPID']) if props.get('MainPID', '').isdigit() else 0
        if pid > 0:
            inspected_pids += 1
            inspect_pid_limits(unit, pid)
        if unit in vendor_units:
            if pid > 0:
                try:
                    with open(f'/proc/{pid}/status', errors='replace') as handle:
                        bnd = _parse_cap_bnd(handle.read())
                except OSError:
                    bnd = None
                if bnd is None:
                    issues.append(f'{unit}(pid {pid}) unreadable CapBnd')
                else:
                    leaked = [name for name, bit in _FORBIDDEN_VENDOR_CAPS if bnd & (1 << bit)]
                    if leaked:
                        issues.append(f'{unit}(pid {pid}) retains forbidden caps: {", ".join(leaked)}')
            else:
                cap_prop = props.get('CapabilityBoundingSet', '').lower().strip()
                tokens = cap_prop.split()
                if not tokens:
                    issues.append(f'{unit} has unrestricted CapabilityBoundingSet')
                elif cap_prop.startswith('~'):
                    if 'cap_sys_admin' not in cap_prop:
                        issues.append(f'{unit} CapabilityBoundingSet does not drop cap_sys_admin')
                elif 'cap_sys_admin' in tokens:
                    issues.append(f'{unit} CapabilityBoundingSet retains cap_sys_admin')

    if inspected_pids == 0:
        issues.append('no active unit MainPID found to verify resource limits')

    if engine_cli == 'docker' and not is_rootless_podman:
        if os.path.isdir('/proc/sys/net/core') and not _is_mount_readonly('/proc/sys/net/core'):
            issues.append('/proc/sys/net/core is writable on Docker (must remain read-only)')
        if not is_rootless and os.path.isdir('/proc/sys/net/ipv4/conf') and _is_mount_readonly('/proc/sys/net/ipv4/conf'):
            issues.append('/proc/sys/net/ipv4/conf is read-only (expected rw bind-remount)')

    if issues:
        return False, '; '.join(issues[:6])
    return True, ''


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


def check_device_mid(mid_url, timeout=10.0):
    """Verify a client daemon's local get_mid endpoint returns a non-empty device UUID."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    deadline = time.monotonic() + timeout
    last_err = ''
    while True:
        try:
            with opener.open(mid_url, timeout=3) as resp:
                raw = resp.read().decode('utf-8', errors='replace').strip().rstrip(';').strip()
            if raw.startswith('(') and raw.endswith(')'):
                raw = raw[1:-1].strip()
            data = json.loads(raw)
            if not isinstance(data, dict):
                return False, f'get_mid returned non-object: {_flat(raw, 120)}'
            uid = str(data.get('uuid') or '').strip()
            encoded = str(data.get('result') or '').strip()
            if not uid:
                return False, 'get_mid returned empty device uuid (DMI/SMBIOS collection failed)'
            if len(encoded) < 32:
                return False, 'get_mid returned empty or truncated mid payload'
            return True, ''
        except Exception as exc:
            last_err = str(exc)
            if time.monotonic() >= deadline:
                return False, f'get_mid probe failed: {last_err}'
            time.sleep(0.5)


def check_log(log_path, needles, extra_logs=(), mid_url=''):
    if mid_url:
        ok, detail = check_device_mid(mid_url)
        if not ok:
            return False, detail

    targets = [(log_path, needles), *((p, n) for p, n in extra_logs)]
    hits = []
    for path, path_needles in targets:
        if not path_needles or not path or not os.path.exists(path):
            continue
        try:
            with open(path, errors='replace') as handle:
                for line in handle:
                    for needle in path_needles:
                        if needle and needle in line:
                            hits.append(line.strip())
                            if len(hits) >= 3:
                                return False, _flat('\n'.join(hits))
        except OSError:
            continue
    if hits:
        return False, _flat('\n'.join(hits))
    return True, ''


def check_privilege(ui_name, nnp_units):
    issues = []
    pids = _pgrep_exact(ui_name)
    inspected = 0
    for pid in pids:
        try:
            with open(f'/proc/{pid}/status', errors='replace') as handle:
                text = handle.read()
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

    events_dir = '/run/zt-events'
    try:
        ev_st = os.lstat(events_dir)
        kasm_uid = pwd.getpwnam('kasm-user').pw_uid
        if not stat.S_ISDIR(ev_st.st_mode):
            issues.append(f'{events_dir} is not a directory')
        elif ev_st.st_uid != kasm_uid or (ev_st.st_mode & 0o002):
            issues.append(f'{events_dir} has unsafe ownership/mode (uid={ev_st.st_uid} {ev_st.st_mode & 0o777:04o})')
    except (OSError, KeyError) as exc:
        issues.append(f'{events_dir} missing: {exc}')

    if issues:
        return False, '; '.join(issues)
    return True, ''


def _resolve_proc_exe(pid_dir, root='/'):
    """Resolve the real rootfs executable path for a /proc/<pid> entry.

    Returns None for deleted executables or host-only emulator shims that have
    no in-container binary (e.g. macOS Rosetta), and resolves Linux QEMU
    binfmt_misc (`qemu-*-static`) wrappers back to the real guest ELF path from
    cmdline so `check_path_chain` still audits the executed container binary.
    """
    try:
        exe = os.readlink(os.path.join(pid_dir, 'exe'))
    except OSError:
        return None
    if not exe or exe.endswith(' (deleted)') or exe.startswith('/run/rosetta/'):
        return None

    root_norm = os.path.normpath(root)

    def _in_root(abs_path):
        if root_norm == '/':
            return abs_path
        return os.path.join(root_norm, abs_path.lstrip('/'))

    if os.path.basename(exe).startswith('qemu-') and not os.path.lexists(_in_root(exe)):
        try:
            with open(os.path.join(pid_dir, 'cmdline'), 'rb') as handle:
                raw_cmd = handle.read()
        except OSError:
            return None
        args = [tok.decode('utf-8', errors='surrogateescape') for tok in raw_cmd.split(b'\x00') if tok]
        for arg in args:
            if not arg or arg.startswith('-'):
                continue
            if os.path.basename(arg).startswith('qemu-'):
                continue
            if os.path.isabs(arg) and os.path.lexists(_in_root(arg)):
                return arg
            if not os.path.isabs(arg):
                for search_dir in ('/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin'):
                    cand = os.path.join(search_dir, arg)
                    if os.path.lexists(_in_root(cand)):
                        return cand
        return None

    return exe


def check_programs(vendor, root_runs):
    must_exist = set()
    optional = set()
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            with open(f'/proc/{entry}/status', errors='replace') as handle:
                status = handle.read()
            uid_line = next((l for l in status.splitlines() if l.startswith('Uid:')), '')
            if uid_line and uid_line.split()[1] == '0':
                exe = _resolve_proc_exe(f'/proc/{entry}')
                if exe:
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

    ok, detail = check_routing(is_rootless=bool(spec.get('is_rootless', False)))
    record('routing', ok, detail)

    if not stand_in_ok:
        record('loopback_isolation', False, f'stand-in listener did not start on port {stand_in_port}')
        record('tunnel', False, f'stand-in listener did not start on port {stand_in_port}')
    else:
        ok, detail = check_loopback_isolation(
            stand_in_port,
            net_mode,
            engine_cli=spec.get('engine_cli', ''),
            is_rootless_podman=bool(spec.get('is_rootless_podman', False)),
            is_rootless=bool(spec.get('is_rootless', False)),
        )
        record('loopback_isolation', ok, detail)

        ok, detail = check_tunnel(stand_in_port, net_mode)
        record('tunnel', ok, detail)

    ok, detail = check_timezone(spec.get('tz', ''))
    record('timezone', ok, detail)

    ok, detail = check_identity()
    record('identity', ok, detail)

    ok, detail = check_limits(
        spec['units'],
        spec.get('nnp_units', ('kasmvnc.service',)),
        engine_cli=spec.get('engine_cli', ''),
        is_rootless_podman=bool(spec.get('is_rootless_podman', False)),
        is_rootless=bool(spec.get('is_rootless', False)),
    )
    record('limits', ok, detail)

    ok, detail = check_log(
        log_path,
        spec.get('quiet', ()),
        extra_logs=spec.get('extra_logs', ()),
        mid_url=spec.get('mid_url', ''),
    )
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
