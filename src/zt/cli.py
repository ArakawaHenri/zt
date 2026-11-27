"""Encapsulated 9-command CLI: up, down, status, doctor, purge, accept, password, use, update."""
import argparse
import getpass
import os
import shutil
import socket
import subprocess
import sys

from zt import VERSION
from zt.bridge import (
    bridge_matches,
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
    clear_engine,
    config_file,
    container_env,
    delete_setting,
    die,
    host_timezone,
    password_valid,
    save_engine,
    say,
    setting,
    target_arch,
    warn,
    write_setting,
)
from zt.engine import make_engine, named, resolve_engine
from zt.spec import (
    ACCEPT_MODES,
    AUTH_USER,
    BASE,
    CAPABILITIES,
    CLIENTS,
    ENGINE_NAMES,
    ENGINES,
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
from zt.update import run_update
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
    """Build into a staging tag, verify live, and promote to `ref` only if all checks pass.

    Using a separate `-unverified` staging tag guarantees crash/SIGKILL/retry
    fail-closed semantics: a failed or interrupted verification can never leave
    the canonical `ref` behind to bypass verification on the next `zt up`.
    """
    ref = current_ref(profile, arch)
    if engine.image_exists(ref):
        return ref
    staging = f'{ref}-unverified'
    engine.run_cli('image', 'rm', staging, quiet=True, check=False)
    build(engine, profile, force=True, arch=arch, tag=staging)
    try:
        if verify(engine, profile, mode=mode, arch=arch, ref=staging):
            die(f'the {profile} image did not pass verification')
        engine.run_cli('image', 'tag', staging, ref, quiet=True)
    finally:
        engine.run_cli('image', 'rm', staging, quiet=True, check=False)
    return ref


def _scope_summary(mode):
    if mode == 'local':
        return '127.0.0.1'
    if mode == 'lan':
        return '0.0.0.0 LAN only'
    return '0.0.0.0'


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
    # `zt.*` labels track container reconcile state (distinct from `org.zt.*` image/volume ownership).
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
                engine.run_cli('stop', '-t', '8', name, quiet=True)
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
    if getattr(args, 'clear', False):
        if 'ZT_VNC_PW' in os.environ:
            die('ZT_VNC_PW is set in the environment; unset it to clear the password')
        if accept_mode() == 'all':
            die('cannot clear password while accept mode is "all"; run "zt accept local" or "zt accept lan" first')
        path, removed = delete_setting('VNC_PW')
        if removed:
            say(f'Password cleared from {path}')
            say('Run "zt up" to apply to running clients.')
        else:
            say('No password is set.')
        return
    _prompt_and_save_password()
    say('Run "zt up" to apply to running clients.')


def cmd_accept(args):
    if not args.mode:
        mode = accept_mode()
        source = 'from ZT_ACCEPT' if 'ZT_ACCEPT' in os.environ else f'config: {config_file()}'
        say(f'{mode} ({_scope_summary(mode)}; {source})')
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
    say(f'accept set to {target} ({_scope_summary(target)}); run "zt up" to apply')


def _warn_other_engine_bridges(active_cli):
    other = [
        (profile, live_engine)
        for profile in CLIENTS
        for live_pid, live_engine, _, _, _ in (bridge_record(profile),)
        if live_pid and live_engine and live_engine != active_cli
    ]
    if other:
        names = ', '.join(profile for profile, _ in other)
        engines = ', '.join(sorted({eng for _, eng in other}))
        warn(
            f'note: {names} still has a running bridge on {engines}; '
            f'stop it before running "zt up" on {active_cli}'
        )


def cmd_use(args):
    if not args.engine:
        eng, reason = resolve_engine()
        say(f'{eng.cli} ({eng.display_name}; {reason})')
        return

    if os.environ.get('ZT_ENGINE'):
        die('ZT_ENGINE is set in the environment; unset it to persist engine choice instead')

    target = args.engine
    if target == 'auto':
        clear_engine()
        eng, reason = resolve_engine()
        say(f'engine set to auto -> {eng.cli} ({eng.display_name}; {reason})')
        _warn_other_engine_bridges(eng.cli)
        return

    if not shutil.which(target):
        die(f'{ENGINE_NAMES[target]} is not installed (the `{target}` command was not found)')
    path = save_engine(target)
    say(f'engine set to {target} ({ENGINE_NAMES[target]}; saved in {path})')
    _warn_other_engine_bridges(target)


def cmd_update(args):
    run_update(check_only=getattr(args, 'check', False))


def cmd_up(args):
    arch = target_arch()
    engine = make_engine()
    engine.require()
    mode = accept_mode()
    bind_host = bind_address(mode)
    net_mode = engine.net_mode_for(mode)
    profiles = resolve_targets(args.target)
    envs = {profile: container_env(profile, net_mode=net_mode, mode=mode) for profile in profiles}
    caps = engine.resolved_caps()
    if engine.is_rootless_podman:
        warn(
            'rootless Podman cannot confine capabilities; its containers run --privileged '
            '(confined by the user namespace), CAPS is not enforced, and IPv4 peer filtering '
            'uses subnet mode for gvproxy'
        )
    elif engine.is_linux_rootful and caps == 'all':
        warn(
            'CAPS=all grants full capabilities on a shared Linux kernel; '
            'unset CAPS (default: least) or use rootless Docker/Podman for stronger isolation'
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
            engine.run_cli('stop', '-t', '8', container_name(profile), quiet=True)
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
    pw_ok = bool(password) and password_valid(password)
    auth = (AUTH_USER, password) if pw_ok else None
    wanted_hash = auth_fingerprint(mode, password) if pw_ok else ''
    target = getattr(args, 'target', 'all') if args is not None else 'all'
    profiles = resolve_targets(target)

    auth_summary = f'password ({AUTH_USER})' if auth else ('invalid' if password else 'none')
    say(
        f'engine: {engine.cli} | accept: {mode} ({_scope_summary(mode)}) '
        f'| auth: {auth_summary} | platform: {platform_for(arch)}'
    )
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
        live_pid, live_engine, live_accept, live_hash, live_proto = bridge_record(profile)
        ours = bool(live_pid and live_engine == engine.cli)
        if ours:
            if not bridge_matches(live_accept, live_hash, live_proto, mode, wanted_hash):
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
    cli_path = shutil.which(engine.cli) or 'not found'
    reason = getattr(engine, '_choice_reason', '')
    cli_detail = f'{cli_path} ({reason})' if (present and reason) else cli_path
    check(f'{engine.cli} CLI', present, cli_detail)
    running = engine.is_running() if present else False
    check(f'{engine.cli} engine', running, '' if running else 'not running')
    check('target platform', True, platform_for(arch))
    check('accept mode', True, f'{mode} ({bind_host})')

    password = setting('VNC_PW')
    pw_ok = bool(password) and password_valid(password)
    if not password:
        if mode == 'all':
            check('password', False, 'required for accept all; run "zt password"')
        else:
            check('password', True, 'not set (passwordless)')
    elif pw_ok:
        check('password', True, f'set (required on desktop and SOCKS5, user {AUTH_USER})')
    else:
        check(
            'password',
            False,
            f'must be 6 to 8 characters (got {len(password)}); run "zt password"',
        )

    zone = host_timezone()
    tz_missing = (
        'could not detect Windows time zone; containers stay on UTC'
        if sys.platform == 'win32'
        else '/etc/localtime does not name a zone; containers stay on UTC'
    )
    check('host time zone', bool(zone), zone or tz_missing)
    if not (present and running):
        sys.exit(0 if all(findings) else 1)

    if getattr(engine, 'is_rootless_podman', False):
        check('capabilities', True, 'privileged (confined by rootless Podman user namespace)')
    else:
        raw_caps = setting('CAPS') or getattr(engine, 'default_caps', 'all')
        if raw_caps not in CAPABILITIES:
            check(
                'capabilities',
                False,
                f'CAPS is {raw_caps!r}; must be one of: {", ".join(CAPABILITIES)}',
            )
        else:
            if getattr(engine, 'is_linux_rootful', False):
                cap_detail = (
                    f'{raw_caps} (shared Linux kernel; rootless Docker/Podman adds userns isolation)'
                )
            elif engine.cli == 'docker':
                cap_detail = (
                    f'{raw_caps} (--cap-drop ALL + minimal allowlist)'
                    if raw_caps == 'least'
                    else raw_caps
                )
            else:
                cap_detail = f'{raw_caps} (microVM isolated)'
            check('capabilities', True, cap_detail)

    for name in ('base', *CLIENTS):
        ref = current_ref(name, arch)
        built = engine.image_exists(ref)
        check(f'image {name}', built, ref if built else 'not built (built automatically by zt up)')

    auth = (AUTH_USER, password) if pw_ok else None
    wanted_hash = auth_fingerprint(mode, password) if pw_ok else ''

    for profile in CLIENTS:
        up = engine.container_state(profile) == 'running'
        port = desktop_port(profile)
        if up:
            url = desktop_url(profile, bind_host='127.0.0.1')
            unauth = http_status(url)
            if auth is not None:
                authed = http_status(url, auth=auth)
                good = unauth == 401 and authed == 200
                detail = f'{desktop_url(profile, bind_host=bind_host)} ({unauth} unauth / {authed} auth)'
            elif mode == 'all' or password:
                good = False
                detail = 'password invalid or missing'
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
        live_pid, live_engine, live_accept, live_hash, live_proto = bridge_record(profile)
        if live_pid and live_engine == engine.cli:
            if not bridge_matches(live_accept, live_hash, live_proto, mode, wanted_hash):
                check(f'socks {profile}', False, 'bridge settings or protocol changed; run "zt up"')
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
            'Run "zt accept lan" for LAN access (source-IP filtered) or "zt accept all" for '
            'open remote access (0.0.0.0, password required). Run "zt password" to enable '
            'password auth on both web desktops and SOCKS5 in any mode, or "zt password --clear" '
            'to remove it.'
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
        help='choose bind scope: local (127.0.0.1), lan (0.0.0.0 LAN only), or all (0.0.0.0, requires password)',
        description='choose bind scope: local (127.0.0.1), lan (0.0.0.0 LAN only), or all (0.0.0.0, requires password)',
    )
    accepting.add_argument('mode', nargs='?', choices=ACCEPT_MODES)
    accepting.set_defaults(handler=cmd_accept)

    pw_cmd = add(
        'password',
        'set, change, or --clear the password (active in all modes when set; required for accept all)',
        cmd_password,
    )
    pw_cmd.add_argument('--clear', action='store_true', help='remove the saved password (disallowed under accept all)')

    using = commands.add_parser(
        'use',
        help='choose container engine: container, docker, or auto; omit argument to show active engine',
        description='choose container engine: container, docker, or auto; omit argument to show active engine',
    )
    using.add_argument('engine', nargs='?', choices=[*ENGINES, 'auto'])
    using.set_defaults(handler=cmd_use)

    updating = add('update', 'self-update zt to the latest stable GitHub release', cmd_update)
    updating.add_argument('--check', action='store_true', help='check for a newer release without installing')

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
