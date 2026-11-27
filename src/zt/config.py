"""Output helpers, cross-platform paths, settings persistence, accept mode, and container env."""
import hashlib
import ipaddress
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from zt.spec import ACCEPT_MODES, ENGINES, SETTINGS, host_arch

_LAN_NETWORKS = (
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('100.64.0.0/10'),  # CGNAT / Tailscale
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('fc00::/7'),       # IPv6 ULA
    ipaddress.ip_network('fe80::/10'),      # IPv6 link-local
)

# Standard CLDR Windows timezone IDs -> IANA zone names (used on Windows hosts).
_WINDOWS_TZ_MAP = {
    'Dateline Standard Time': 'Etc/GMT+12',
    'UTC-11': 'Etc/GMT+11',
    'Aleutian Standard Time': 'America/Adak',
    'Hawaiian Standard Time': 'Pacific/Honolulu',
    'Alaskan Standard Time': 'America/Anchorage',
    'Pacific Standard Time': 'America/Los_Angeles',
    'Pacific Standard Time (Mexico)': 'America/Tijuana',
    'US Mountain Standard Time': 'America/Phoenix',
    'Mountain Standard Time': 'America/Denver',
    'Central America Standard Time': 'America/Guatemala',
    'Central Standard Time': 'America/Chicago',
    'Central Standard Time (Mexico)': 'America/Mexico_City',
    'Canada Central Standard Time': 'America/Regina',
    'SA Pacific Standard Time': 'America/Bogota',
    'Eastern Standard Time': 'America/New_York',
    'US Eastern Standard Time': 'America/Indianapolis',
    'Venezuela Standard Time': 'America/Caracas',
    'Atlantic Standard Time': 'America/Halifax',
    'SA Western Standard Time': 'America/La_Paz',
    'Pacific SA Standard Time': 'America/Santiago',
    'Newfoundland Standard Time': 'America/St_Johns',
    'E. South America Standard Time': 'America/Sao_Paulo',
    'Argentina Standard Time': 'America/Buenos_Aires',
    'Greenland Standard Time': 'America/Godthab',
    'Azores Standard Time': 'Atlantic/Azores',
    'Cape Verde Standard Time': 'Atlantic/Cape_Verde',
    'UTC': 'Etc/UTC',
    'GMT Standard Time': 'Europe/London',
    'Greenwich Standard Time': 'Atlantic/Reykjavik',
    'W. Europe Standard Time': 'Europe/Berlin',
    'Central Europe Standard Time': 'Europe/Budapest',
    'Romance Standard Time': 'Europe/Paris',
    'Central European Standard Time': 'Europe/Warsaw',
    'W. Central Africa Standard Time': 'Africa/Lagos',
    'GTB Standard Time': 'Europe/Bucharest',
    'Middle East Standard Time': 'Asia/Beirut',
    'Egypt Standard Time': 'Africa/Cairo',
    'E. Europe Standard Time': 'Europe/Chisinau',
    'South Africa Standard Time': 'Africa/Johannesburg',
    'FLE Standard Time': 'Europe/Kiev',
    'Israel Standard Time': 'Asia/Jerusalem',
    'Kaliningrad Standard Time': 'Europe/Kaliningrad',
    'Arab Standard Time': 'Asia/Riyadh',
    'Turkey Standard Time': 'Europe/Istanbul',
    'Arabic Standard Time': 'Asia/Baghdad',
    'Russian Standard Time': 'Europe/Moscow',
    'E. Africa Standard Time': 'Africa/Nairobi',
    'Iran Standard Time': 'Asia/Tehran',
    'Arabian Standard Time': 'Asia/Dubai',
    'Azerbaijan Standard Time': 'Asia/Baku',
    'Georgian Standard Time': 'Asia/Tbilisi',
    'Caucasus Standard Time': 'Asia/Yerevan',
    'Afghanistan Standard Time': 'Asia/Kabul',
    'West Asia Standard Time': 'Asia/Tashkent',
    'Ekaterinburg Standard Time': 'Asia/Yekaterinburg',
    'Pakistan Standard Time': 'Asia/Karachi',
    'India Standard Time': 'Asia/Kolkata',
    'Sri Lanka Standard Time': 'Asia/Colombo',
    'Nepal Standard Time': 'Asia/Katmandu',
    'Central Asia Standard Time': 'Asia/Almaty',
    'Bangladesh Standard Time': 'Asia/Dhaka',
    'Myanmar Standard Time': 'Asia/Rangoon',
    'SE Asia Standard Time': 'Asia/Bangkok',
    'N. Central Asia Standard Time': 'Asia/Novosibirsk',
    'China Standard Time': 'Asia/Shanghai',
    'North Asia Standard Time': 'Asia/Krasnoyarsk',
    'Singapore Standard Time': 'Asia/Singapore',
    'W. Australia Standard Time': 'Australia/Perth',
    'Taipei Standard Time': 'Asia/Taipei',
    'Ulaanbaatar Standard Time': 'Asia/Ulaanbaatar',
    'Tokyo Standard Time': 'Asia/Tokyo',
    'Korea Standard Time': 'Asia/Seoul',
    'Yakutsk Standard Time': 'Asia/Yakutsk',
    'Cen. Australia Standard Time': 'Australia/Adelaide',
    'AUS Central Standard Time': 'Australia/Darwin',
    'E. Australia Standard Time': 'Australia/Brisbane',
    'AUS Eastern Standard Time': 'Australia/Sydney',
    'West Pacific Standard Time': 'Pacific/Port_Moresby',
    'Tasmania Standard Time': 'Australia/Hobart',
    'Vladivostok Standard Time': 'Asia/Vladivostok',
    'Central Pacific Standard Time': 'Pacific/Guadalcanal',
    'New Zealand Standard Time': 'Pacific/Auckland',
    'Fiji Standard Time': 'Pacific/Fiji',
    'Tonga Standard Time': 'Pacific/Tongatapu',
}

_told_about = set()


def say(*parts):
    print(*parts, flush=True)


def warn(*parts):
    print(*parts, file=sys.stderr, flush=True)


def die(message, code=1):
    warn(f'zt: {message}')
    sys.exit(code)


def target_arch():
    """Validated target container arch ('arm64' or 'amd64')."""
    try:
        return host_arch()
    except ValueError as err:
        die(str(err))


def _is_windows():
    return os.name == 'nt'


def _user_dir(variable, tail):
    return Path(os.environ[variable]) if os.environ.get(variable) else Path.home() / tail


def config_file():
    override = os.environ.get('ZT_CONFIG')
    if override:
        return Path(override)
    if _is_windows():
        base = Path(os.environ.get('APPDATA') or (Path.home() / 'AppData' / 'Roaming'))
        return base / 'zt' / 'config'
    return _user_dir('XDG_CONFIG_HOME', '.config') / 'zt' / 'config'


def cache_dir():
    override = os.environ.get('ZT_CACHE')
    if override:
        return Path(override)
    if _is_windows():
        base = Path(os.environ.get('LOCALAPPDATA') or (Path.home() / 'AppData' / 'Local'))
        return base / 'zt' / 'cache'
    return _user_dir('XDG_CACHE_HOME', '.cache') / 'zt'


def state_dir():
    override = os.environ.get('ZT_STATE')
    if override:
        return Path(override)
    if _is_windows():
        base = Path(os.environ.get('LOCALAPPDATA') or (Path.home() / 'AppData' / 'Local'))
        return base / 'zt' / 'state'
    return _user_dir('XDG_STATE_HOME', '.local/state') / 'zt'


def engine_file():
    return state_dir() / 'engine'


def save_engine(choice):
    """Atomically persist the selected engine ('container' or 'docker') in engine_file()."""
    if choice not in ENGINES:
        die(f'engine must be one of: {", ".join(ENGINES)}')
    return _write_config_lines(engine_file(), [choice])


def clear_engine():
    """Remove saved engine preference so `auto` selection applies."""
    path = engine_file()
    existed = path.exists()
    path.unlink(missing_ok=True)
    return path, existed


def configured_engine():
    """Return (engine_name, provenance) when explicitly pinned via ZT_ENGINE or saved file.

    Returns (None, 'auto') when engine selection is in automatic mode.
    """
    override = os.environ.get('ZT_ENGINE')
    if override:
        if override not in ENGINES:
            die(f'ZT_ENGINE is {override!r}; it must be one of: {", ".join(ENGINES)}')
        return override, 'from ZT_ENGINE'

    path = engine_file()
    try:
        saved = path.read_text(encoding='utf-8').strip()
    except OSError:
        saved = ''
    if saved in ENGINES:
        return saved, f'saved in {path}'
    if saved:
        warn(f'zt: ignoring unknown engine {saved!r} in {path}')
    return None, 'auto'


def parse_config(text):
    """KEY=VALUE lines; blank lines and # comments are ignored."""
    settings = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '"\'':
            value = value[1:-1]
        settings[key] = value
    return settings


def setting(key):
    """Value of a setting: the ZT_<KEY> environment variable, else the config file."""
    env_key = 'ZT_' + key
    if env_key in os.environ:
        return os.environ[env_key]
    path = str(config_file())
    try:
        settings = parse_config(Path(path).read_text(encoding='utf-8'))
    except OSError:
        return ''
    unknown = sorted(set(settings) - set(SETTINGS))
    if unknown and path not in _told_about:
        _told_about.add(path)
        warn(f'zt: ignoring unknown settings in {path}: {", ".join(unknown)}')
    return settings.get(key, '')


def _write_config_lines(path, lines):
    """Atomically write `lines` to `path` with 0600 permissions on POSIX."""
    payload = ''.join(f'{line}\n' for line in lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='.config-', dir=path.parent)
    tmp = Path(tmp_name)
    fd_owned = True
    try:
        if os.name != 'nt':
            os.fchmod(fd, 0o600)
        fd_owned = False
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        if fd_owned:
            os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    return path


def write_setting(key, value):
    """Atomically update KEY=VALUE in config_file() with 0600 permissions on POSIX."""
    path = config_file()
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except OSError:
        lines = []
    kept = [line for line in lines if line.split('=', 1)[0].strip() != key]
    return _write_config_lines(path, [*kept, f'{key}={value}'])


def delete_setting(key):
    """Atomically remove KEY from config_file(); returns (path, removed_bool)."""
    path = config_file()
    try:
        lines = path.read_text(encoding='utf-8').splitlines()
    except OSError:
        return path, False
    kept = [line for line in lines if line.split('=', 1)[0].strip() != key]
    if len(kept) == len(lines):
        return path, False
    _write_config_lines(path, kept)
    return path, True


def accept_mode():
    """Return 'local' (default), 'lan', or 'all'."""
    mode = setting('ACCEPT') or 'local'
    if mode not in ACCEPT_MODES:
        die(f'ACCEPT is {mode!r}; it must be one of: {", ".join(ACCEPT_MODES)}')
    return mode


def bind_address(mode=None):
    """Host bind address for VNC and SOCKS5 ports."""
    return '127.0.0.1' if (mode or accept_mode()) == 'local' else '0.0.0.0'


def is_lan_ip(host):
    """True if `host` is a loopback, RFC 1918, link-local, CGNAT/Tailscale, or IPv6 ULA address."""
    try:
        ip = ipaddress.ip_address(str(host).split('%', 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip in net for net in _LAN_NETWORKS)


def password_valid(password):
    return (
        6 <= len(password) <= 8
        and password.strip() == password
        and '\n' not in password
        and '\r' not in password
        and bool(password)
        and password[0] not in '#"\''
        and parse_config(f'VNC_PW={password}\n').get('VNC_PW') == password
    )


def auth_password(mode=None):
    """Return active password whenever set (required in `all`, optional in `local`/`lan`).

    Fails closed if `mode == 'all'` has no password, or if a non-empty password
    in any mode has an invalid format.
    """
    mode = mode or accept_mode()
    password = setting('VNC_PW')
    if not password:
        if mode == 'all':
            die(
                'accept mode is "all" and requires a 6 to 8 character password; '
                'run "zt password" first'
            )
        return ''
    if not password_valid(password):
        die(
            'VNC_PW must be 6 to 8 characters without leading/trailing spaces, '
            'newlines, or leading #, ", \'; run "zt password" to fix it'
        )
    return password


def auth_fingerprint(mode=None, password=None):
    """Short non-reversible digest of active password (empty when no password is set)."""
    pw = auth_password(mode) if password is None else password
    if not pw:
        return ''
    return hashlib.sha256(pw.encode('utf-8')).hexdigest()[:12]


def zone_from_realpath(path):
    """The IANA zone name a resolved /etc/localtime points at, or None."""
    for marker in ('/zoneinfo/', '/timezone/'):
        at = path.rfind(marker)
        if at >= 0:
            return path[at + len(marker):]
    return None


def windows_timezone_to_iana(win_tz):
    """Map a Windows timezone ID (from `tzutil /g`) to its IANA zone name."""
    name = (win_tz or '').strip()
    if name.endswith('_dstoff'):
        name = name[:-7]
    return _WINDOWS_TZ_MAP.get(name)


def host_timezone():
    if sys.platform == 'win32':
        try:
            proc = subprocess.run(
                ['tzutil', '/g'], capture_output=True, text=True, check=False, timeout=5,
            )
            if proc.returncode == 0:
                return windows_timezone_to_iana(proc.stdout)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return None
    zone = zone_from_realpath(os.path.realpath('/etc/localtime'))
    if zone and Path('/usr/share/zoneinfo', zone).is_file():
        return zone
    return None


def container_env(profile, net_mode='gateway', mode=None):
    """Environment of a container of this client."""
    mode = mode or accept_mode()
    password = auth_password(mode)
    env = {'ZT_NET_MODE': net_mode, 'ZT_AUTH': '1' if password else '0'}
    if password:
        env['VNC_PW'] = password
    zone = host_timezone()
    if zone:
        env['TZ'] = zone
    bypass = setting('TRUSTAGENT_BYPASS_ROUTES')
    if profile == 'trustagent' and bypass:
        env['BYPASS_ROUTES'] = bypass
    return env
