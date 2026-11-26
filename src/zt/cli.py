"""Encapsulated 7-command CLI: up, down, status, doctor, purge, accept, password."""
import argparse
import getpass
import os
import shutil
import socket
import subprocess
import sys

from zt import VERSION
from zt.bridge import (
    bridge_record,
    bridge_start,
    bridge_stop,
    run_bridge,
    socks_any_listener,
    socks_ready,
)
from zt.build import build, current_ref
from zt.config import (
    accept_mode,
    auth_fingerprint,
    bind_address,
    cache_dir,
    config_file,
    container_env,
    die,
    host_timezone,
    password_valid,
    say,
    setting,
    target_arch,
    warn,
    write_setting,
)
from zt.engine import make_engine, named
from zt.spec import (
    ACCEPT_MODES,
    AUTH_USER,
    BASE,
    CLIENTS,
    ENGINE_NAMES,
    all_blob_shas,
    container_name,
    desktop_backend_port,
    desktop_port,
    desktop_url,
    platform_for,
    resolve_targets,
    socks_port,
    state_volume_name,
)
from zt.verify import http_status, verify


def _prune_stale_for(engine, profile, arch):
    """Quietly remove outdated zt-managed images for `profile` after an upgrade."""
    keep = {current_ref(profile, arch)}
    info = engine.inspect(container_name(profile)) or {}
    keep.add(info.get('configuration', {}).get('image', {}).get('reference'))
    for tag in engine.managed_images(profile):
        if tag not in keep:
            engine.run_cli('image', 'rm', tag, quiet=True, check=False)


def ensure_image(engine, profile, mode, arch):
    ref = current_ref(profile, arch)
    if engine.image_exists(ref):
        return ref
    build(engine, profile, force=True, arch=arch)
    if verify(engine, profile, mode=mode, arch=arch):
        die(f'the {profile} image did not pass verification')
    return ref


def _mode_summary(mode):
    if mode == 'local':
        return '127.0.0.1, no password'
    if mode == 'lan':
        return '0.0.0.0 LAN only, no password'
    return f'0.0.0.0, password required, user {AUTH_USER}'


def ensure_container(engine, profile, env, mode, arch=None):
    """Converge the client's container to its desired image, bind host, settings, and state volume."""
    arch = arch or target_arch()
    name = container_name(profile)
    ref = current_ref(profile, arch)
    volume = state_volume_name(profile)
    # In `accept lan`, the container publishes only to loopback backend port;
    # the host bridge guards 0.0.0.0:<desktop_port> by source IP.
    publish_host = '127.0.0.1' if mode in ('local', 'lan') else '0.0.0.0'
    publish_port = desktop_backend_port(profile) if mode == 'lan' else desktop_port(profile)
    wanted = {
        'zt.profile': profile,
        'zt.image': ref,
        'zt.state': engine.fingerprint(ref, env, publish_port, bind_host=publish_host, volume=volume),
    }
    info = engine.inspect(name)
    recreated = False
    if info:
        labels = info['configuration'].get('labels') or {}
        changed = [key for key in wanted if labels.get(key) != wanted[key]]
        if changed:
            reason = (
                'it was not made by this zt'
                if 'zt.profile' not in labels
                else 'its image is out of date'
                if 'zt.image' in changed
                else 'its settings changed'
            )
            say(f'{profile}: recreating, {reason} (login state preserved)')
            bridge_stop(profile, engine_cli=engine.cli)
            if info['status']['state'] == 'running':
                engine.run_cli('stop', '--time', '8', name, quiet=True)
            engine.run_cli('rm', '-f', name, quiet=True)
            info = None
            recreated = True

    if not info:
        taken = engine.port_holders(publish_port)
        if taken:
            return f'{publish_host}:{publish_port} is {taken}, and it is the desktop port of {profile}'
        engine.ensure_volume(volume, profile)
        engine.run_container(
            name, ref, env, publish_port, wanted,
            bind_host=publish_host, arch=arch, volume=volume, quiet=True,
        )
        if engine.container_state(profile) in ('exited', 'dead'):
            return f'{profile}: the container exited as soon as it started'
        say(f'{profile}: created')
        if recreated:
            _prune_stale_for(engine, profile, arch)
    elif info['status']['state'] != 'running':
        engine.run_cli('start', name, quiet=True)
        say(f'{profile}: started')
    else:
        say(f'{profile}: already running')
    return None


def _prompt_and_save_password():
    if 'ZT_VNC_PW' in os.environ:
        die('ZT_VNC_PW is set in the environment; unset it to store a password in the file instead')
    password = getpass.getpass('Password (6 to 8 characters): ')
    if not password_valid(password):
        die(
            'the password must be 6 to 8 characters, without spaces at the ends and '
            'without starting with #, a quote or an apostrophe'
        )
    if getpass.getpass('Once more: ') != password:
        die('the two passwords differ')
    path = write_setting('VNC_PW', password)
    say(f'Password saved in {path}')
    return password


def cmd_password(args):
    _prompt_and_save_password()
    if accept_mode() == 'all':
        say('Run "zt up" to apply the new password to running clients.')


def cmd_accept(args):
    if not args.mode:
        mode = accept_mode()
        source = 'from ZT_ACCEPT' if 'ZT_ACCEPT' in os.environ else f'config: {config_file()}'
        say(f'{mode} ({_mode_summary(mode)}; {source})')
        return

    if 'ZT_ACCEPT' in os.environ:
        die('ZT_ACCEPT is set in the environment; unset it to persist accept mode instead')

    target = args.mode
    if target == 'all' and not password_valid(setting('VNC_PW')):
        if not sys.stdin.isatty():
            die('accept all requires a password; run "zt password" first')
        say('accept all exposes desktop and SOCKS5 on 0.0.0.0 and requires a password.')
        _prompt_and_save_password()

    write_setting('ACCEPT', target)
    say(f'accept set to {target} ({_mode_summary(target)}); run "zt up" to apply')


def cmd_up(args):
    arch = target_arch()
    engine = make_engine()
    engine.require()
    mode = accept_mode()
    bind_host = bind_address(mode)
    net_mode = engine.net_mode_for(mode)
    profiles = resolve_targets(args.target)
    envs = {profile: container_env(profile, net_mode=net_mode, mode=mode) for profile in profiles}
    engine.container_flags()
    if engine.is_rootless_podman:
        warn(
            'rootless Podman cannot confine capabilities; its containers run --privileged '
            '(confined by the user namespace), CAPS is not enforced, and IPv4 peer filtering '
            'uses subnet mode for gvproxy'
        )
    for profile in profiles:
        ensure_image(engine, profile, mode, arch)
    problems = []
    for profile in profiles:
        problem = ensure_container(engine, profile, envs[profile], mode=mode, arch=arch)
        if problem:
            problems.append(f'{profile}: {problem}')
        else:
            problem = bridge_start(engine, profile, mode=mode)
            if problem:
                what = 'LAN bridge' if mode == 'lan' else f'SOCKS5 on {bind_host}:{socks_port(profile)}'
                warn(f'{profile}: {what} did not start: {problem}')
            elif mode == 'lan':
                say(
                    f'{profile}: LAN guard on {bind_host}:{desktop_port(profile)} '
                    f'and SOCKS5 on {bind_host}:{socks_port(profile)}'
                )
            else:
                say(f'{profile}: SOCKS5 on {bind_host}:{socks_port(profile)}')
    cmd_status(args, engine=engine)
    if problems:
        die('; '.join(problems))


def cmd_down(args):
    engine = make_engine()
    engine.require()
    for profile in resolve_targets(args.target):
        bridge_stop(profile, engine_cli=engine.cli)
        if engine.container_state(profile) == 'running':
            engine.run_cli('stop', '--time', '8', container_name(profile), quiet=True)
            say(f'{profile}: stopped')
        else:
            say(f'{profile}: not running')


def cmd_purge(args):
    """Stop and remove containers, state volumes, built images, and host cache for target."""
    engine = make_engine()
    engine.require()
    profiles = resolve_targets(args.target)
    cache = cache_dir()

    for profile in profiles:
        bridge_stop(profile, engine_cli=engine.cli)
        did_something = False
        if engine.inspect(container_name(profile)):
            engine.run_cli('rm', '-f', container_name(profile), quiet=True)
            say(f'{profile}: container removed')
            did_something = True
        vol = state_volume_name(profile)
        if engine.remove_volume(vol):
            say(f'{profile}: state volume removed ({vol})')
            did_something = True
        for tag in engine.managed_images(profile):
            if engine.run_cli('image', 'rm', tag, quiet=True, check=False).returncode == 0:
                say(f'{profile}: image removed ({tag})')
                did_something = True
        build_dir = cache / 'build'
        if build_dir.is_dir():
            for ctx in build_dir.glob(f'{profile}-*'):
                shutil.rmtree(ctx, ignore_errors=True)
                did_something = True
        if not did_something:
            say(f'{profile}: nothing to purge')

    if args.target == 'all':
        for tag in engine.managed_images('base'):
            if engine.run_cli('image', 'rm', tag, quiet=True, check=False).returncode == 0:
                say(f'base: image removed ({tag})')
        if cache.exists():
            shutil.rmtree(cache, ignore_errors=True)
            say(f'cache removed ({cache})')
    else:
        kept_shas = set(all_blob_shas(BASE))
        for other, client in CLIENTS.items():
            if other not in profiles:
                kept_shas.update(all_blob_shas(client))
        blobs_dir = cache / 'blobs'
        for profile in profiles:
            for sha in sorted(all_blob_shas(CLIENTS[profile])):
                if sha not in kept_shas:
                    blob = blobs_dir / sha
                    if blob.exists():
                        blob.unlink(missing_ok=True)
                        say(f'{profile}: cached blob removed ({sha[:12]})')


def cmd_status(args=None, engine=None):
    arch = target_arch()
    if engine is None:
        engine = make_engine()
        engine.require()
    mode = accept_mode()
    bind_host = bind_address(mode)
    password = setting('VNC_PW')
    auth = (AUTH_USER, password) if (mode == 'all' and password_valid(password)) else None
    wanted_hash = auth_fingerprint(mode, password) if (mode != 'all' or auth) else ''
    target = getattr(args, 'target', 'all') if args is not None else 'all'
    profiles = resolve_targets(target)

    say(f'accept: {mode} ({_mode_summary(mode)}) | platform: {platform_for(arch)}')
    say(f'{"client":<12} {"container":<10} {"image":<8} {"desktop":<26} socks')
    foreign = False
    for profile in profiles:
        info = engine.inspect(container_name(profile))
        state = info['status']['state'] if info else '-'
        labels = (info['configuration'].get('labels') or {}) if info else {}
        image = (
            'current'
            if labels.get('zt.image') == current_ref(profile, arch)
            else 'stale'
            if info
            else '-'
        )
        desktop = desktop_url(profile, bind_host=bind_host) if state == 'running' else '-'
        port = socks_port(profile)
        live_pid, live_engine, live_accept, live_hash = bridge_record(profile)
        ours = bool(live_pid and live_engine == engine.cli)
        if ours:
            if live_accept != mode or (mode == 'all' and live_hash != wanted_hash):
                socks = 'stale (run zt up)'
            elif socks_ready(port, auth=auth):
                socks = f'{bind_host}:{port}'
            else:
                socks = '-'
        elif socks_any_listener(port):
            foreign = True
            socks = f'other ({live_engine})' if live_pid and live_engine else 'other'
        else:
            socks = '-'
        say(f'{profile:<12} {state:<10} {image:<8} {desktop:<26} {socks}')
    if foreign:
        say(f'socks "other": port is served by something other than a {engine.display_name} zt bridge')


def cmd_doctor(args):
    arch = target_arch()
    engine = make_engine()
    mode = accept_mode()
    bind_host = bind_address(mode)
    findings = []

    def check(name, good, detail=''):
        findings.append(good)
        say(f'{"OK  " if good else "FAIL"} {name:<22}{detail}')

    def port_free(port, host=None):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind((host or bind_host, port))
                return True
            except OSError:
                return False

    present = engine.is_installed()
    check(f'{engine.cli} CLI', present, shutil.which(engine.cli) or 'not found')
    running = engine.is_running() if present else False
    check(f'{engine.cli} engine', running, '' if running else 'not running')
    check('target platform', True, platform_for(arch))
    check('accept mode', True, f'{mode} ({bind_host})')

    password = setting('VNC_PW')
    pw_ok = password_valid(password)
    if mode == 'all':
        pw_detail = (
            ''
            if pw_ok
            else f'must be 6 to 8 characters (got {len(password)}); run "zt password"'
            if password
            else 'required for accept all; run "zt password"'
        )
        check('password', pw_ok, pw_detail)
    else:
        check('password', True, f'not required (accept {mode})')

    zone = host_timezone()
    tz_missing = (
        'could not detect Windows time zone; containers stay on UTC'
        if sys.platform == 'win32'
        else '/etc/localtime does not name a zone; containers stay on UTC'
    )
    check('host time zone', bool(zone), zone or tz_missing)
    if not (present and running):
        sys.exit(0 if all(findings) else 1)

    for name in ('base', *CLIENTS):
        ref = current_ref(name, arch)
        built = engine.image_exists(ref)
        check(f'image {name}', built, ref if built else 'not built (built automatically by zt up)')

    auth = (AUTH_USER, password) if (mode == 'all' and pw_ok) else None
    wanted_hash = auth_fingerprint(mode, password) if (mode != 'all' or auth) else ''

    for profile in CLIENTS:
        up = engine.container_state(profile) == 'running'
        port = desktop_port(profile)
        if up:
            url = desktop_url(profile, bind_host='127.0.0.1')
            unauth = http_status(url)
            if mode == 'all':
                if pw_ok:
                    authed = http_status(url, auth=auth)
                    good = unauth == 401 and authed == 200
                    detail = f'{desktop_url(profile, bind_host=bind_host)} ({unauth} unauth / {authed} auth)'
                else:
                    good = False
                    detail = 'password missing for accept all'
            else:
                good = unauth == 200
                detail = f'{desktop_url(profile, bind_host=bind_host)} answers {unauth}'
            check(f'desktop {profile}', good, detail)
        else:
            free = port_free(port)
            check(f'port {port}', free, '' if free else engine.port_holders(port) or 'taken')
            if mode == 'lan':
                bport = desktop_backend_port(profile)
                bfree = port_free(bport, '127.0.0.1')
                if not bfree:
                    check(f'port {bport}', False, engine.port_holders(bport) or 'taken')

        port = socks_port(profile)
        live_pid, live_engine, live_accept, live_hash = bridge_record(profile)
        if live_pid and live_engine == engine.cli:
            if live_accept != mode or (mode == 'all' and live_hash != wanted_hash):
                check(f'socks {profile}', False, 'bridge settings changed; run "zt up"')
            else:
                ready = socks_ready(port, auth=auth)
                check(
                    f'socks {profile}',
                    ready,
                    f'{bind_host}:{port}' if ready else 'bridge is up, no handshake',
                )
        elif live_pid:
            other = ENGINE_NAMES.get(live_engine, live_engine or 'another engine')
            check(
                f'socks {profile}',
                False,
                f'127.0.0.1:{port} is served by a zt bridge for {other} (pid {live_pid})',
            )
        elif socks_any_listener(port):
            check(
                f'socks {profile}',
                False,
                f'127.0.0.1:{port} is served by something else '
                f'({engine.port_holders(port) or "a listener this user cannot see"}), not a bridge of zt',
            )
        else:
            free = port_free(port)
            check(f'port {port}', free, '' if free else engine.port_holders(port) or 'taken')
    sys.exit(0 if all(findings) else 1)


def cmd_bridge(args):
    engine = make_engine()
    run_bridge(engine, args.client)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ['bridge']:
        # Internal background bridge entrypoint spawned by `zt up`.
        if len(argv) != 2 or argv[1] not in CLIENTS:
            die('usage: zt bridge <client>', 2)
        return cmd_bridge(argparse.Namespace(client=argv[1]))

    parser = argparse.ArgumentParser(
        prog='zt',
        description='Zero-trust VPN client desktops with SOCKS5 proxy (TrustAgent, aTrust, EasyConnect).',
        epilog=(
            'By default zt accepts local connections only (127.0.0.1) with no password. '
            'Run "zt accept lan" for passwordless LAN access (source-IP filtered), or '
            '"zt accept all" for open remote access (0.0.0.0) with password authentication '
            'on both web desktops and SOCKS5 ports.'
        ),
    )
    parser.add_argument('--version', action='version', version=f'zt {VERSION}')
    commands = parser.add_subparsers(dest='command', metavar='<command>')

    def add(name, help_text, handler, choices=None, metavar='<all|client>'):
        sub = commands.add_parser(name, help=help_text, description=help_text)
        if choices:
            sub.add_argument('target', nargs='?', default='all', metavar=metavar, choices=choices)
        sub.set_defaults(handler=handler)
        return sub

    everything = ['all', *CLIENTS]
    add('up', 'build if needed, start, and bring up the SOCKS5 bridge', cmd_up, everything)
    add('down', 'stop container and SOCKS5 bridge (keep client login state)', cmd_down, everything)
    add('status', 'show client status, desktop URLs, and SOCKS5 ports', cmd_status, everything)
    add('doctor', 'check host engine, platform, settings, images, ports, and bridges', cmd_doctor)
    add('purge', 'stop and delete containers, login state volumes, images, and cache', cmd_purge, everything)

    accepting = commands.add_parser(
        'accept',
        help='choose bind scope: local (127.0.0.1), lan (0.0.0.0 LAN only), or all (0.0.0.0 + password)',
        description='choose bind scope: local (127.0.0.1), lan (0.0.0.0 LAN only), or all (0.0.0.0 + password)',
    )
    accepting.add_argument('mode', nargs='?', choices=ACCEPT_MODES)
    accepting.set_defaults(handler=cmd_accept)

    add('password', 'set or change the password silently (required for accept all)', cmd_password)

    args = parser.parse_args(argv)
    if not getattr(args, 'handler', None):
        parser.print_help()
        sys.exit(2)
    args.handler(args)


def run_main():
    """Run `main`, formatting operational errors as one clean line."""
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except subprocess.TimeoutExpired as error:
        command = list(error.cmd) if isinstance(error.cmd, (list, tuple)) else [str(error.cmd)]
        prog = command[0] if command else 'zt'
        sub = named(command[1:])
        label = f'{prog} {sub}'.strip()
        how_long = f' in {int(error.timeout)} seconds' if error.timeout else ''
        sys.exit(f'zt: "{label}" did not finish{how_long}')
    except OSError as error:
        sys.exit(f'zt: {error}')
