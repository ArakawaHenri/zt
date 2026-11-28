"""Container engine boundary: AppleContainerEngine and DockerEngine (macOS, Linux, Windows)."""
import csv
import functools
import hashlib
import io
import itertools
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import NamedTuple

try:
    import resource
except ImportError:  # Windows
    resource = None

from zt.config import configured_engine, die, setting, target_arch, warn
from zt.spec import (
    CAPABILITIES,
    CLIENTS,
    DOCKER_LEAST_CAPS,
    ENGINE_NAMES,
    ENGINES,
    STATE_MOUNT,
    container_name,
    host_arch,
    normalize_arch,
    platform_for,
)

ENGINE_TRIES = 5
ENGINE_REFUSED = 'Connection refused'

# Matches legacy (<ver>-<12hex>), multi-arch (<ver>-<arch>-<12hex>), and staging (-unverified) tags.
_MANAGED_TAG_RE = re.compile(
    r'^localhost/zt-(base|' + '|'.join(CLIENTS) + r'):.+-[0-9a-f]{12}(-unverified)?$'
)
_BUILDX_VER_RE = re.compile(r'\bv?(\d+)\.(\d+)(?:\.(\d+))?\b')

_NOFILE_SOFT = 1024
_NOFILE_HARD = 65536
_DOCKER_STATIC_SYSCTLS = (
    'net.ipv4.tcp_mtu_probing=1',
    'net.ipv4.tcp_keepalive_time=60',
    'net.ipv4.tcp_keepalive_intvl=15',
    'net.ipv4.tcp_keepalive_probes=4',
    'net.ipv4.tcp_retries2=8',
)


def _nofile_ulimit(is_rootless=False):
    """Return `nofile=<soft>:<hard>` clamped to the host hard limit on rootless Linux."""
    soft, hard = _NOFILE_SOFT, _NOFILE_HARD
    if is_rootless and sys.platform.startswith('linux') and resource is not None:
        try:
            _, host_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            if 0 < host_hard < hard:
                hard = host_hard
                soft = min(soft, hard)
        except (OSError, ValueError):
            pass
    return f'nofile={soft}:{hard}'


def _is_cross_arch(arch):
    """True when target container `arch` differs from the physical host CPU arch."""
    if not arch:
        return False
    native = normalize_arch(platform.machine())
    return bool(native and arch != native)


def refused(proc):
    """True when the engine daemon itself refused the connection."""
    errors = proc.stderr or ''
    if isinstance(errors, bytes):
        errors = errors.decode(errors='replace')
    return any(
        line.strip().startswith('Error:') and ENGINE_REFUSED in line
        for line in errors.splitlines()
    )


def tried(call):
    """Retry an engine invocation while the engine itself refuses it."""
    for attempt in range(1, ENGINE_TRIES + 1):
        proc = call()
        if proc.returncode == 0 or not refused(proc) or attempt == ENGINE_TRIES:
            return proc
        warn(f'the engine refused the call, trying again ({attempt} of {ENGINE_TRIES - 1})')
        time.sleep(attempt)
    return proc


def named(args):
    """Command words without options, for concise error messages."""
    return ' '.join(
        itertools.takewhile(lambda part: not part.startswith('-'), (str(part) for part in args))
    )


def _error_summary(stderr, stdout):
    """Extract the most informative error line, ignoring Docker Desktop's advisory footer."""
    text = ((stderr or '') + '\n' + (stdout or '')).strip()
    if not text:
        return ''
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "What's next:":
            break
        if stripped:
            kept.append(stripped)
    return kept[-1] if kept else ''


def json_lines(text):
    """Parse newline-delimited JSON objects, skipping blank lines."""
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def passed_through(cli_bin, args, timeout=None, env=None):
    """Run engine CLI streaming stderr live while retaining its tail (POSIX + Windows safe).

    stdout is intentionally inherited directly to the user's terminal rather than
    captured, so the returned `CompletedProcess.stdout` is always `''`. Callers
    that need stdout must use `Engine.run_cli(..., quiet=True)`.
    """
    process = subprocess.Popen([cli_bin, *args], stderr=subprocess.PIPE, env=env)
    kept = []
    kept_bytes = 0
    max_kept = 256 * 1024

    def drain_stderr():
        nonlocal kept_bytes
        stream = process.stderr
        if stream is None:
            return
        read_fn = getattr(stream, 'read1', stream.read)
        try:
            while True:
                chunk = read_fn(65536)
                if not chunk:
                    break
                kept.append(chunk)
                kept_bytes += len(chunk)
                while kept_bytes > max_kept and len(kept) > 1:
                    kept_bytes -= len(kept.pop(0))
                try:
                    sys.stderr.buffer.write(chunk)
                    sys.stderr.buffer.flush()
                except OSError:
                    pass
        except OSError:
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    reader = threading.Thread(target=drain_stderr, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
    except BaseException:
        process.kill()
        process.wait()
        reader.join(timeout=2)
        raise
    reader.join(timeout=5)
    return subprocess.CompletedProcess(
        process.args,
        process.returncode,
        '',
        b''.join(kept).decode(errors='replace'),
    )


def docker_record(record):
    """Normalize a Docker/Podman inspect JSON record into zt's unified shape."""
    config = record.get('Config') or {}
    bindings = (record.get('HostConfig') or {}).get('PortBindings') or {}
    published = [
        {'hostPort': int(entry['HostPort'])}
        for entries in bindings.values()
        for entry in (entries or [])
        if entry.get('HostPort')
    ]
    networks = []
    for net in ((record.get('NetworkSettings') or {}).get('Networks') or {}).values():
        address = {}
        if net.get('IPAddress'):
            prefix = net.get('IPPrefixLen')
            address['ipv4Address'] = f"{net['IPAddress']}/{prefix if prefix else 24}"
        if net.get('GlobalIPv6Address'):
            prefix6 = net.get('GlobalIPv6PrefixLen')
            address['ipv6Address'] = f"{net['GlobalIPv6Address']}/{prefix6 if prefix6 else 64}"
        if address:
            networks.append(address)
    return {
        'configuration': {
            'id': (record.get('Name') or '').lstrip('/'),
            'labels': config.get('Labels') or {},
            'image': {'reference': config.get('Image')},
            'publishedPorts': published,
        },
        'status': {
            'state': (record.get('State') or {}).get('Status'),
            'networks': networks,
        },
    }


def _windows_process_name(pid):
    try:
        proc = subprocess.run(
            ['tasklist', '/FI', f'PID eq {pid}', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, check=False, timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            rows = list(csv.reader(io.StringIO(proc.stdout.strip())))
            if rows and len(rows[0]) >= 2 and rows[0][1].strip() == str(pid):
                return rows[0][0].strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return 'a process'


def _parse_windows_netstat(output, port):
    """Return PID listening on TCP `port` from `netstat -ano -p tcp`, or None."""
    suffix = f':{port}'
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == 'TCP' and parts[3].upper() == 'LISTENING':
            if parts[1].endswith(suffix) and parts[4].isdigit():
                return parts[4]
    return None


def _host_listener(port):
    """Identify a host process listening on TCP `port`, portable across macOS, Linux, Windows."""
    if os.name == 'nt':
        netstat = shutil.which('netstat')
        if netstat:
            try:
                proc = subprocess.run(
                    [netstat, '-ano', '-p', 'tcp'],
                    capture_output=True, text=True, check=False, timeout=10,
                )
                pid = _parse_windows_netstat(proc.stdout, port)
                if pid:
                    return f'held by {_windows_process_name(pid)} (pid {pid})'
            except (OSError, subprocess.TimeoutExpired):
                pass
        return None

    lsof = shutil.which('lsof') or ('/usr/sbin/lsof' if os.path.exists('/usr/sbin/lsof') else None)
    if lsof:
        try:
            proc = subprocess.run(
                [lsof, '-nP', f'-iTCP:{port}', '-sTCP:LISTEN', '-Fpc'],
                capture_output=True, text=True, check=False,
            )
            fields = {line[0]: line[1:] for line in proc.stdout.splitlines() if line}
            if fields:
                return f"held by {fields.get('c', 'a process')} (pid {fields.get('p', '?')})"
        except OSError:
            pass

    ss = shutil.which('ss')
    if ss:
        try:
            proc = subprocess.run(
                [ss, '-H', '-tlnp', f'sport = :{port}'],
                capture_output=True, text=True, check=False,
            )
            for line in proc.stdout.splitlines():
                match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                if match:
                    return f'held by {match.group(1)} (pid {match.group(2)})'
        except OSError:
            pass
    return None


class Engine:
    """Explicit boundary isolating all container-engine-specific behavior."""

    cli = ''
    display_name = ''
    start_hint = ''
    pass_hostname = False
    default_caps = 'all'

    @property
    def is_rootless_podman(self):
        return False

    @property
    def is_linux_rootful(self):
        return False

    @property
    def needs_external_build_load(self):
        return False

    @property
    def net_mode(self):
        return self.net_mode_for('local')

    def net_mode_for(self, accept='local'):
        return 'subnet' if self.is_rootless_podman else 'gateway'

    def run_cli(self, *args, quiet=False, check=True, timeout=None, env=None, retry=True):
        if quiet:
            call = lambda: subprocess.run(
                [self.cli, *args],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace',
                timeout=timeout, env=env,
            )
        else:
            call = lambda: passed_through(self.cli, args, timeout=timeout, env=env)
        proc = tried(call) if retry else call()
        if check and proc.returncode:
            detail = _error_summary(proc.stderr, proc.stdout)
            die(
                f'"{self.cli} {named(args)}" failed'
                + (f': {detail}' if detail else f' with exit status {proc.returncode}')
            )
        return proc

    def exec_capture(self, name, user, command, stdin=None, timeout=120):
        if stdin is None:
            def call():
                return subprocess.run(
                    [self.cli, 'exec', '--user', user, name, *command],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True,
                    errors='replace', timeout=timeout,
                )
        else:
            def call():
                return subprocess.run(
                    [self.cli, 'exec', '--interactive', '--user', user, name, *command],
                    input=stdin, capture_output=True, timeout=timeout,
                )
        return tried(call)

    def is_installed(self):
        return bool(shutil.which(self.cli))

    def is_running(self):
        raise NotImplementedError

    def require(self):
        if not self.is_installed():
            die(f'{self.display_name} is not installed (the `{self.cli}` command was not found)')
        if not self.is_running():
            die(f'{self.display_name} is not running; {self.start_hint}')

    def resolved_caps(self, caps_override=None):
        caps = (setting('CAPS') if caps_override is None else caps_override) or self.default_caps
        if caps not in CAPABILITIES:
            die(f'CAPS is {caps!r}; it must be one of: {", ".join(CAPABILITIES)}')
        return caps

    def _cap_flags(self, caps_override=None):
        caps = self.resolved_caps(caps_override)
        return [arg for cap in CAPABILITIES[caps] for arg in ('--cap-add', cap)]

    def container_flags(self, caps_override=None, profile=None, arch=None, mac_address=None):
        raise NotImplementedError

    def fingerprint(self, ref, env, port, bind_host='127.0.0.1', volume=None,
                    profile=None, mac_address=None, arch=None):
        """Digest of everything a container was created from."""
        if profile is None and isinstance(volume, str) and volume.startswith('zt-state-'):
            profile = volume[len('zt-state-'):]
        effective_arch = arch
        if effective_arch is None:
            try:
                effective_arch = host_arch()
            except ValueError:
                effective_arch = None
        flags = self.container_flags(
            profile=profile, arch=effective_arch, mac_address=mac_address,
        )
        return hashlib.sha256(
            json.dumps(
                [ref, env, port, bind_host, volume or '', flags],
                sort_keys=True,
            ).encode()
        ).hexdigest()[:12]

    def volume_exists(self, name):
        return self.run_cli('volume', 'inspect', name, quiet=True, check=False).returncode == 0

    def ensure_volume(self, name, profile):
        raise NotImplementedError

    def remove_volume(self, name):
        raise NotImplementedError

    def run_container(self, name, ref, env, port, labels, bind_host='127.0.0.1',
                      arch=None, volume=None, quiet=False, mac_address=None):
        """Create and start a container; VNC_PW is passed via child env, never argv."""
        arch = arch or target_arch()
        profile = (labels or {}).get('zt.profile') or (labels or {}).get('zt.verify')
        args = ['run', '-d', '--name', name, '--platform', platform_for(arch)]
        if self.pass_hostname:
            args += ['--hostname', name]
        args += [*self.container_flags(profile=profile, arch=arch, mac_address=mac_address)]
        child_env = dict(os.environ)
        for key, value in env.items():
            if key == 'VNC_PW':
                args += ['-e', 'VNC_PW']
                child_env['VNC_PW'] = value
            else:
                args += ['-e', f'{key}={value}']
        for key, value in labels.items():
            args += ['--label', f'{key}={value}']
        if volume:
            args += ['-v', f'{volume}:{STATE_MOUNT}']
        args += ['-p', f'{bind_host}:{port}:6901', ref]
        self.run_cli(*args, quiet=quiet, timeout=600, env=child_env)

    def inspect(self, name):
        raise NotImplementedError

    def container_state(self, profile):
        info = self.inspect(container_name(profile))
        return info['status']['state'] if info else None

    def containers_on(self, port):
        raise NotImplementedError

    def port_holders(self, port):
        publishing = self.containers_on(port)
        if publishing:
            return f'published by the container {", ".join(publishing)}'
        return _host_listener(port)

    def image_exists(self, ref):
        return self.run_cli('image', 'inspect', ref, quiet=True, check=False).returncode == 0

    def managed_images(self, profile=None):
        raise NotImplementedError


def _matches_profile(ref, labels, profile):
    if profile is None:
        return True
    if labels.get('org.zt.profile') == profile:
        return True
    return ref.startswith(f'localhost/zt-{profile}:')


class AppleContainerEngine(Engine):
    cli = 'container'
    display_name = ENGINE_NAMES['container']
    start_hint = 'start it with: container system start'
    pass_hostname = False  # Apple Container uses --name as container hostname automatically.

    def is_running(self):
        try:
            proc = self.run_cli(
                'system', 'status', '--format', 'json',
                quiet=True, check=False, timeout=5, retry=False,
            )
            status = json.loads(proc.stdout) if proc.returncode == 0 else {}
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return False
        return isinstance(status, dict) and status.get('status') == 'running'

    @functools.cached_property
    def _run_help_text(self):
        cli_bin = shutil.which(self.cli)
        if not cli_bin:
            return ''
        try:
            proc = subprocess.run(
                [cli_bin, 'run', '--help'],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                errors='replace', check=False, timeout=5,
            )
            return (proc.stdout + proc.stderr) if proc.returncode == 0 else ''
        except (OSError, subprocess.TimeoutExpired):
            return ''

    @property
    def _supports_ulimit(self):
        return '--ulimit' in self._run_help_text

    @property
    def _supports_network_mac(self):
        return ',mac=' in self._run_help_text

    @property
    def _supports_read_only_path(self):
        # Apple Container isolates each container in its own Virtualization.framework
        # microVM and has no `--sysctl` flag, so `--read-only-path NONE` lets
        # zt-net-setup.sh write netns sysctls (tcp_mtu_probing, keepalive, rp_filter,
        # utun*.route_localnet) inside the microVM. Degrade cleanly if a future CLI
        # removes this experimental flag.
        return (not self._run_help_text) or ('--read-only-path' in self._run_help_text)

    def container_flags(self, caps_override=None, profile=None, arch=None, mac_address=None):
        adds = self._cap_flags(caps_override)
        memory = '3G' if _is_cross_arch(arch) else '2G'
        ro_path = ('--read-only-path', 'NONE') if self._supports_read_only_path else ()
        ulimits = (
            ('--ulimit', _nofile_ulimit(False), '--ulimit', 'core=0:0')
            if self._supports_ulimit
            else ()
        )
        network = (
            ('--network', f'default,mac={mac_address}')
            if (mac_address and self._supports_network_mac)
            else ()
        )
        return (
            '--cpus', '2', '--memory', memory, *adds,
            *ro_path, '--shm-size', '256m',
            *ulimits, *network, '--user', 'root',
        )

    def ensure_volume(self, name, profile):
        if self.volume_exists(name):
            return False
        self.run_cli(
            'volume', 'create',
            '--label', 'org.zt.managed=true',
            '--label', f'org.zt.profile={profile}',
            '-s', '2G',
            name,
            quiet=True,
        )
        return True

    def remove_volume(self, name):
        # Apple Container microVM teardown can briefly hold the ext4 volume lock
        # right after `container rm -f`; retry once after a short pause if still present.
        for attempt in range(2):
            if self.run_cli('volume', 'rm', name, quiet=True, check=False).returncode == 0:
                return True
            if attempt == 0 and self.volume_exists(name):
                time.sleep(0.5)
                continue
            return False
        return False

    def inspect(self, name):
        proc = self.run_cli('inspect', name, quiet=True, check=False)
        try:
            return json.loads(proc.stdout)[0] if proc.returncode == 0 else None
        except (ValueError, IndexError):
            return None

    def containers_on(self, port):
        try:
            records = json.loads(self.run_cli('ls', '-a', '--format', 'json', quiet=True).stdout)
            return sorted(
                str(record['configuration']['id'])
                for record in records
                if record.get('status', {}).get('state') == 'running'
                and any(
                    published.get('hostPort') == port
                    for published in record['configuration'].get('publishedPorts', [])
                )
            )
        except (ValueError, KeyError, TypeError):
            return []

    def managed_images(self, profile=None):
        try:
            proc = self.run_cli(
                'image', 'ls', '--format', 'json',
                quiet=True, check=False, timeout=15, retry=False,
            )
            if proc.returncode != 0:
                return []
            records = json.loads(proc.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
            return []
        if not isinstance(records, list):
            return []
        found = set()
        for record in records:
            name = str(record.get('configuration', {}).get('name', ''))
            if not name:
                continue
            labels = {}
            for variant in record.get('variants') or ():
                cfg = (variant.get('config') or {}).get('config') or {}
                labels.update(cfg.get('Labels') or {})
            if (labels.get('org.zt.managed') == 'true' or _MANAGED_TAG_RE.fullmatch(name)) \
                    and _matches_profile(name, labels, profile):
                found.add(name)
        return sorted(found)


class DaemonTraits(NamedTuple):
    is_podman: bool = False
    is_rootless: bool = False
    has_selinux: bool = False
    has_apparmor: bool = False
    is_desktop_vm: bool = False


class DockerEngine(Engine):
    cli = 'docker'
    display_name = ENGINE_NAMES['docker']
    start_hint = 'start the daemon (Docker Desktop, or `podman machine start`)'
    pass_hostname = True
    default_caps = 'least'

    @functools.cached_property
    def _daemon_traits(self):
        """Query engine once to detect Podman, rootless mode, SELinux/AppArmor, and VM desktops."""
        is_podman = False
        is_rootless = False
        has_selinux = False
        has_apparmor = False
        is_desktop_vm = False
        info_proc = self.run_cli('info', '--format', '{{json .}}', quiet=True, check=False)
        try:
            info = json.loads(info_proc.stdout) if info_proc.returncode == 0 else {}
        except ValueError:
            info = {}

        if isinstance(info, dict):
            sec_opts = info.get('SecurityOptions') or []
            if any('rootless' in str(opt).lower() for opt in sec_opts):
                is_rootless = True
            if any('selinux' in str(opt).lower() for opt in sec_opts):
                has_selinux = True
            if any('apparmor' in str(opt).lower() for opt in sec_opts):
                has_apparmor = True
            host_info = info.get('Host') if isinstance(info.get('Host'), dict) else {}
            host_sec = host_info.get('Security') if isinstance(host_info.get('Security'), dict) else {}
            if host_sec.get('Rootless'):
                is_rootless = True
            if host_sec.get('SELinuxEnabled'):
                has_selinux = True
            if host_sec.get('AppArmorEnabled'):
                has_apparmor = True
            os_name = str(info.get('OperatingSystem', '')).lower()
            node_name = str(info.get('Name', '')).lower()
            kernel_ver = str(info.get('KernelVersion', '')).lower()
            if (
                any(tok in os_name for tok in ('docker desktop', 'orbstack', 'rancher desktop'))
                or node_name == 'orbstack'
                or node_name.startswith(('colima', 'lima-'))
                or 'orbstack' in kernel_ver
            ):
                is_desktop_vm = True
            if (
                any(k in host_info for k in ('BuildahVersion', 'Conmon', 'Slirp4netns'))
                or 'podman' in str(info.get('ServerVersion', '')).lower()
                or 'podman' in str((info.get('Platform') or {}).get('Name', '')).lower()
            ):
                is_podman = True

        if not is_podman:
            ver_proc = self.run_cli('version', '--format', '{{json .Server}}', quiet=True, check=False)
            try:
                server = json.loads(ver_proc.stdout) if ver_proc.returncode == 0 else {}
                if isinstance(server, dict):
                    components = server.get('Components') or []
                    is_podman = any('podman' in str(c.get('Name', '')).lower() for c in components)
                    if not is_podman:
                        is_podman = 'podman' in str((server.get('Platform') or {}).get('Name', '')).lower()
            except (ValueError, AttributeError):
                pass
            if is_podman and not info:
                is_rootless = True

        return DaemonTraits(
            is_podman=is_podman,
            is_rootless=is_rootless,
            has_selinux=has_selinux,
            has_apparmor=has_apparmor,
            is_desktop_vm=is_desktop_vm,
        )

    @functools.cached_property
    def _buildx_driver(self):
        """Return active `docker buildx` driver name (e.g. 'docker', 'docker-container'), or ''."""
        try:
            proc = self.run_cli('buildx', 'inspect', quiet=True, check=False, timeout=10, retry=False)
        except (OSError, subprocess.TimeoutExpired):
            return ''
        if proc.returncode != 0:
            return ''
        for line in proc.stdout.splitlines():
            if line.startswith('Driver:'):
                return line.split(':', 1)[1].strip()
        return ''

    @functools.cached_property
    def _buildx_version(self):
        """Return `(major, minor)` parsed from `docker buildx version`, or None."""
        try:
            proc = self.run_cli('buildx', 'version', quiet=True, check=False, timeout=10, retry=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            return None
        match = _BUILDX_VER_RE.search(proc.stdout or '')
        if not match:
            return None
        major, minor = int(match.group(1)), int(match.group(2))
        return (major, minor) if (major or minor) else None

    @property
    def supports_multi_output_build(self):
        # Multiple --output flags (e.g. --load + --output type=oci) require Buildx >= 0.13.
        ver = self._buildx_version
        return True if ver is None else ver >= (0, 13)

    @property
    def needs_external_build_load(self):
        # Non-'docker' buildx drivers (e.g. 'docker-container', 'remote') build in an
        # isolated BuildKit daemon that neither loads results into the local image store
        # nor sees local images for `FROM ${BASE_IMAGE}`.
        return bool(self._buildx_driver and self._buildx_driver != 'docker')

    @property
    def is_podman(self):
        return self._daemon_traits.is_podman

    @property
    def is_rootless(self):
        return self._daemon_traits.is_rootless

    @property
    def has_selinux(self):
        return self._daemon_traits.has_selinux

    @property
    def has_apparmor(self):
        return self._daemon_traits.has_apparmor

    @property
    def is_desktop_vm(self):
        return self._daemon_traits.is_desktop_vm

    @property
    def is_rootless_podman(self):
        return self.is_podman and self.is_rootless

    @property
    def is_linux_rootful(self):
        return sys.platform.startswith('linux') and not self.is_rootless and not self.is_desktop_vm

    def net_mode_for(self, accept='local'):
        # Containers publish :6901 strictly on loopback in all accept modes (the
        # host bridge fronts both lan and all), so Docker stays in strictest gateway
        # mode even for accept all. Podman (rootless & rootful machine/gvproxy)
        # uses routed forwarding and keeps subnet mode (dropping peer containers &
        # VPN tunnels).
        return 'subnet' if self.is_podman else 'gateway'

    def is_running(self):
        try:
            return (
                self.run_cli(
                    'info', '--format', '{{.ServerVersion}}',
                    quiet=True, check=False, timeout=5, retry=False,
                ).returncode
                == 0
            )
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _cap_flags(self, caps_override=None):
        caps = self.resolved_caps(caps_override)
        if caps == 'least':
            return [
                '--cap-drop', 'ALL',
                *(arg for cap in DOCKER_LEAST_CAPS for arg in ('--cap-add', cap)),
            ]
        return [arg for cap in CAPABILITIES[caps] for arg in ('--cap-add', cap)]

    def container_flags(self, caps_override=None, profile=None, arch=None, mac_address=None):
        adds = self._cap_flags(caps_override)
        memory = '3g' if _is_cross_arch(arch) else '2g'
        sysctls = list(_DOCKER_STATIC_SYSCTLS)
        if self.is_rootless and not self.is_podman:
            # Rootless Docker may inherit MNT_LOCK_READONLY on /proc/sys, so pass
            # per-netns conf fallbacks via --sysctl (eth0 already exists, so default.*
            # only applies to subsequently created VPN interfaces like utun7).
            sysctls.append('net.ipv4.conf.all.rp_filter=2')
            if profile == 'atrust':
                sysctls.append('net.ipv4.conf.default.route_localnet=1')
        base = [
            '--cpus', '2', '--memory', memory,
            '--pids-limit', '1024',
            '--shm-size', '256m',
            '--ulimit', _nofile_ulimit(self.is_rootless),
            '--ulimit', 'core=0:0',
            '--user', 'root',
            '--tmpfs', '/run:rw,nosuid,nodev,size=64m',
            '--tmpfs', '/run/lock:rw,noexec,nosuid,nodev,size=16m',
            '--cgroupns=private',
            *(arg for kv in sysctls for arg in ('--sysctl', kv)),
        ]
        if mac_address and not self.is_rootless_podman:
            # Pin deterministic MAC directly on default bridge (avoids creating a
            # custom network & Docker 127.0.0.11 DNS); skip on rootless Podman pasta.
            base += ['--mac-address', mac_address]
        if self.is_rootless_podman or self.has_selinux:
            # systemd requires label=disable when SELinux or rootless Podman confinement is active.
            base += ['--security-opt', 'label=disable']
        if self.has_apparmor and not self.is_rootless_podman:
            # Docker's default AppArmor profile denies mount(2) even with CAP_SYS_ADMIN,
            # blocking systemd, zt-init bind mounts, and netns verification.
            base += ['--security-opt', 'apparmor=unconfined']
        if self.is_rootless_podman:
            # Rootless Podman cannot pass --device /dev/net/tun or confine CAPS;
            # boot --privileged inside the user namespace without contradictory --cap-add.
            return tuple([*base, '--privileged'])
        return tuple([*base, *adds, '--device', '/dev/net/tun:/dev/net/tun:rw'])

    def ensure_volume(self, name, profile):
        if self.volume_exists(name):
            return False
        self.run_cli(
            'volume', 'create',
            '--label', 'org.zt.managed=true',
            '--label', f'org.zt.profile={profile}',
            name,
            quiet=True,
        )
        return True

    def remove_volume(self, name):
        return self.run_cli('volume', 'rm', '-f', name, quiet=True, check=False).returncode == 0

    def inspect(self, name):
        proc = self.run_cli('inspect', name, quiet=True, check=False)
        try:
            record = json.loads(proc.stdout)[0] if proc.returncode == 0 else None
        except (ValueError, IndexError):
            return None
        return docker_record(record) if record is not None else None

    def containers_on(self, port):
        ids_proc = self.run_cli('ps', '-q', quiet=True, check=False)
        if ids_proc.returncode != 0:
            return []
        ids = [line.strip() for line in ids_proc.stdout.splitlines() if line.strip()]
        if not ids:
            return []
        insp = self.run_cli('inspect', *ids, quiet=True, check=False)
        if insp.returncode != 0:
            return []
        try:
            records = json.loads(insp.stdout)
        except ValueError:
            return []
        holders = []
        for record in records:
            ports = (record.get('NetworkSettings') or {}).get('Ports') or {}
            bindings = (record.get('HostConfig') or {}).get('PortBindings') or {}
            found = False
            for proto_key, entries in (*ports.items(), *bindings.items()):
                if not str(proto_key).endswith('/tcp'):
                    continue
                for entry in (entries or ()):
                    if str(entry.get('HostPort', '')) == str(port):
                        found = True
                        break
                if found:
                    break
            if found:
                holders.append((record.get('Name') or record.get('Id', '')).lstrip('/'))
        return sorted(set(holders))

    def managed_images(self, profile=None):
        found = set()
        filter_args = ['--filter', 'label=org.zt.managed=true']
        if profile is not None:
            filter_args += ['--filter', f'label=org.zt.profile={profile}']
        try:
            labeled = self.run_cli(
                'image', 'ls', *filter_args,
                '--format', '{{.Repository}}:{{.Tag}}',
                quiet=True, check=False, timeout=15, retry=False,
            )
            if labeled.returncode == 0:
                for line in labeled.stdout.splitlines():
                    ref = line.strip()
                    if ref and '<none>' not in ref:
                        found.add(ref)
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            proc = self.run_cli(
                'image', 'ls', '--format', 'json',
                quiet=True, check=False, timeout=15, retry=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                raw = proc.stdout.strip()
                if raw.startswith('['):
                    parsed = json.loads(raw)
                    records = parsed if isinstance(parsed, list) else []
                else:
                    records = json_lines(raw)
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    refs = []
                    if record.get('Repository') and record.get('Tag'):
                        refs.append(f"{record['Repository']}:{record['Tag']}")
                    for name in record.get('Names') or ():
                        if isinstance(name, str):
                            refs.append(name)
                    for ref in refs:
                        if _MANAGED_TAG_RE.fullmatch(ref) and _matches_profile(ref, {}, profile):
                            found.add(ref)
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError, AttributeError):
            pass
        return sorted(found)


def _engine_by_name(name):
    return DockerEngine() if name == 'docker' else AppleContainerEngine()


def _reusable_image_score(eng):
    """Count current (client_images, base_image) already built in `eng` for the active arch."""
    from zt.build import current_ref

    try:
        arch = host_arch()
    except ValueError:
        return 0, 0
    have = set(eng.managed_images())
    client_refs = {current_ref(profile, arch) for profile in CLIENTS}
    base_ref = current_ref('base', arch)
    return len(have & client_refs), 1 if base_ref in have else 0


def resolve_engine(choice=None):
    """Select an Engine instance and human-readable provenance.

    In `auto` mode (no ZT_ENGINE override and no saved choice), selection uses no
    OS special-casing:
      1. Installed engines on PATH (`container`, `docker`);
      2. Among installed engines, prefer one whose daemon is currently running;
      3. If multiple daemons are running, prefer the one with more reusable
         current images (client images first, then base image);
      4. Final tie-break prefers `container` (Apple Container) over `docker`.
    """
    if choice is not None:
        return _engine_by_name(choice), 'explicit'

    pinned, reason = configured_engine()
    if pinned is not None:
        return _engine_by_name(pinned), reason

    candidates = [_engine_by_name(name) for name in ENGINES]
    installed = [eng for eng in candidates if eng.is_installed()]
    if not installed:
        return DockerEngine(), 'auto: none installed'
    if len(installed) == 1:
        return installed[0], 'auto'

    running = [eng for eng in installed if eng.is_running()]
    if len(running) == 1:
        return running[0], 'auto: only running engine'
    if not running:
        return installed[0], 'auto: preferred, none running'

    scores = {eng.cli: _reusable_image_score(eng) for eng in running}
    if len(set(scores.values())) > 1:
        winner = max(running, key=lambda eng: scores[eng.cli])
        clients_hit, base_hit = scores[winner.cli]
        if clients_hit:
            noun = 'client image' if clients_hit == 1 else 'client images'
            detail = f'reusing {clients_hit} current {noun}' + (' + base' if base_hit else '')
        elif base_hit:
            detail = 'reusing current base image'
        else:
            detail = 'reusing current images'
        return winner, f'auto: {detail}'

    # Tied on running state & reusable current images: prefer `container` (ENGINES[0]).
    return running[0], 'auto: preferred'


def make_engine(choice=None):
    """Instantiate the selected Engine implementation."""
    eng, reason = resolve_engine(choice)
    eng._choice_reason = reason
    return eng
