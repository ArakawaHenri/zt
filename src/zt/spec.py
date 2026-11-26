"""Declarative multi-arch specification of official blobs, clients, overlays, and policies."""
import os
import platform

SUPPORTED_ARCHES = ('arm64', 'amd64')
_ARCH_ALIASES = {
    'arm64': 'arm64',
    'aarch64': 'arm64',
    'x86_64': 'amd64',
    'amd64': 'amd64',
}

_KASMVNC_VER = '1.5.2'
_TRUSTAGENT = '3.5.1.1003.62'
_ATRUST = '2.5.16.20'

# Official KasmVNC GitHub releases (Ubuntu 24.04 Noble)
_KASMVNC_URLS = {
    'arm64': (
        f'https://github.com/kasmtech/KasmVNC/releases/download/v{_KASMVNC_VER}/'
        f'kasmvncserver_ubuntu_noble_{_KASMVNC_VER}_arm64.deb',
        '4d680f3d1eb77fb155ae67af7f9fa25d7fbd38a7f69ae146784c7f738e2eed1a',
    ),
    'amd64': (
        f'https://github.com/kasmtech/KasmVNC/releases/download/v{_KASMVNC_VER}/'
        f'kasmvncserver_ubuntu_noble_{_KASMVNC_VER}_amd64.deb',
        '89a5d1fbe9e032b122202be158a2b25f15c97e0a5b8dcf92a5e6835c7b7b2acd',
    ),
}

# Official Sangfor CDNs, official Electron GitHub releases, official Ubuntu archives.
_ATRUST_URLS = {
    'arm64': (
        f'https://atrustcdn.sangfor.com/standard/linux/{_ATRUST}/uos/arm64/aTrustInstaller_arm64.deb',
        'c8c0c0add77c21abb72ae912b1ac01c2cad6cf0fc439a4b64545100153b0cf31',
    ),
    'amd64': (
        f'https://atrustcdn.sangfor.com/standard/linux/{_ATRUST}/uos/amd64/aTrustInstaller_amd64.deb',
        'fea38f63297e2c9bf853f33c566130a2f62f406926f60cf4e87f6d24a8e397d9',
    ),
}

_EASYCONNECT_URLS = {
    'arm64': (
        'https://download.sangfor.com.cn/download/product/sslvpn/SSLVPN'
        '%E4%BF%A1%E5%88%9B%E5%AE%A2%E6%88%B7%E7%AB%AF/'
        '%E7%BB%9F%E4%BF%A1UOS%20%E6%B5%B7%E6%80%9D%E9%BA%92%E9%BA%9F990%20SSL%20VPN'
        '%E5%AE%A2%E6%88%B7%E7%AB%AF.zip',
        '25ed93659d331af943a49e21428af675a33caead06ffce8bd1efaad3b163f893',
    ),
    'amd64': (
        'https://download.sangfor.com.cn/download/product/sslvpn/pkg/linux_767/'
        'EasyConnect_x64_7_6_7_3.deb',
        'ae623c6dc0354ff87afefbb770de5013bfd943051c9a653b93db708253b2f0d3',
    ),
}

_ELECTRON_URLS = {
    'arm64': (
        'https://github.com/electron/electron/releases/download/v1.8.8/'
        'electron-v1.8.8-linux-arm64.zip',
        '41f1cb5c145dd046219f4ead36227dc8e94b2f05df8befbf8a582863db3841e9',
    ),
    'amd64': (
        'https://github.com/electron/electron/releases/download/v1.8.8/'
        'electron-v1.8.8-linux-x64.zip',
        '9600368683ea61ca8e9a476064f128ff319ce4b86378381f94e3888689f2f4d1',
    ),
}

_LIBSSL11_URLS = {
    'arm64': (
        'https://ports.ubuntu.com/ubuntu-ports/pool/main/o/openssl/'
        'libssl1.1_1.1.1f-1ubuntu2.24_arm64.deb',
        'dded4572af8b0a9e0310909f211a519cc6409fda31ea81132a77e268b0ec0f2f',
    ),
    'amd64': (
        'https://security.ubuntu.com/ubuntu/pool/main/o/openssl/'
        'libssl1.1_1.1.1f-1ubuntu2.24_amd64.deb',
        '7cf39d70a639017d1dd7c8d36daa2258063608688e449fddf40ffdd46f992a78',
    ),
}

_LIBEVENT21_AMD64 = (
    'https://security.ubuntu.com/ubuntu/pool/main/libe/libevent/'
    'libevent-2.1-6_2.1.8-stable-4build1_amd64.deb',
    '76bc94b3bb4356673c61dd2a4a7b06f40de21dab051aa4b31282aa9d7798b383',
)

# Qianxin does not publish an anonymous public CDN for TrustAgent; keep the
# existing SHA256-pinned mirror URLs for both arm64 and amd64.
_TRUSTAGENT_URLS = {
    'arm64': (
        'https://media.githubusercontent.com/media/yusiwen/qianxin-clients/refs/heads/master/'
        f'trustagent/TrustAgent_standard_aarch64_{_TRUSTAGENT}_linux.deb',
        'c5ff0a18b6cf1825b867ba498973e7c04a3dca48b120331fb728f0a7530c5be0',
    ),
    'amd64': (
        'https://media.githubusercontent.com/media/yusiwen/qianxin-clients/refs/heads/master/'
        f'trustagent/TrustAgent_standard_amd64_{_TRUSTAGENT}_linux.deb',
        '77a8747e95bfa8fe74475bab68f07d6cbabe53c78ba8ebb02d1e2011447eebc0',
    ),
}

BASE = {
    'version': f'{_KASMVNC_VER}-systemd',
    'overlays': ('base',),
    'dockerfile': 'Dockerfile',
    'args': {'arm64': {}, 'amd64': {}},
    'blobs': {
        arch: (('kasmvncserver.deb', *_KASMVNC_URLS[arch]),)
        for arch in SUPPORTED_ARCHES
    },
}

CLIENTS = {
    'trustagent': {
        'version': _TRUSTAGENT,
        'overlays': ('common', 'trustagent'),
        'dockerfile': 'Dockerfile',
        'args': {'arm64': {}, 'amd64': {}},
        'blobs': {
            'arm64': (
                ('trustagent.deb', *_TRUSTAGENT_URLS['arm64']),
                ('libssl11.deb', *_LIBSSL11_URLS['arm64']),
            ),
            'amd64': (
                ('trustagent.deb', *_TRUSTAGENT_URLS['amd64']),
                ('libssl11.deb', *_LIBSSL11_URLS['amd64']),
                ('libevent21.deb', *_LIBEVENT21_AMD64),
            ),
        },
        'vendor': '/opt/apps/com.qianxin.trustagent/files',
        'launch': '/opt/apps/com.qianxin.trustagent/files/bin/gui_start.sh',
        'ui': 'TrustAgent',
        'units': (
            'trustdservice.service', 'trustservice.service', 'trustservicemgr.service',
            'trustnet.service', 'zt-net.service', 'zt-socks.service',
        ),
        'nnp_units': (
            'kasmvnc.service', 'zt-socks.service',
            'trustdservice.service', 'trustservice.service',
            'trustservicemgr.service', 'trustnet.service',
        ),
        'libs': ('bin/libQTrustWebView.so', 'lib/libQt5WebEngineCore.so.5', 'lib/QtWebEngineProcess'),
        'quiet': ('Driver not loaded',),
        'root_runs': (),
        'desktop_writes': ('/var/log/TrustAgent',),
        'setuid': (),
    },
    'atrust': {
        'version': _ATRUST,
        'overlays': ('common', 'sangfor/common', 'sangfor/atrust'),
        'dockerfile': 'Dockerfile',
        'args': {'arm64': {}, 'amd64': {}},
        'blobs': {
            arch: (('atrust.deb', *_ATRUST_URLS[arch]),)
            for arch in SUPPORTED_ARCHES
        },
        'vendor': '/usr/share/sangfor',
        'launch': None,
        'ui': 'aTrustTray',
        'units': ('zt-net.service', 'zt-sangfor.service', 'zt-socks.service'),
        'nnp_units': (
            'kasmvnc.service', 'zt-socks.service', 'zt-sangfor.service',
            'aTrustDaemon.service', 'eaio_service.service',
        ),
        'quiet': ('error while loading shared libraries',),
        'libs': ('aTrust/resources/bin/aTrustXtunnel-64',),
        'root_runs': ('aTrust/resources/bin/aTrustAgent',),
        'desktop_writes': ('/usr/share/sangfor/.aTrust',),
        'setuid': (),
    },
    'easyconnect': {
        'version': '7.6.7',
        'overlays': ('common', 'sangfor/common', 'sangfor/easyconnect'),
        'dockerfile': 'Dockerfile',
        'args': {
            'arm64': {'VPN_DEB_PATH': '02-升级包及安装文件/EasyConnect_UOS_arm64-20220302.deb'},
            'amd64': {'VPN_DEB_PATH': ''},
        },
        'blobs': {
            arch: (
                ('easyconnect.pkg', *_EASYCONNECT_URLS[arch]),
                ('electron.zip', *_ELECTRON_URLS[arch]),
            )
            for arch in SUPPORTED_ARCHES
        },
        'vendor': '/usr/share/sangfor',
        'launch': None,
        'ui': 'EasyConnect',
        'units': ('zt-net.service', 'zt-sangfor.service', 'zt-socks.service'),
        'nnp_units': (
            'kasmvnc.service', 'zt-socks.service', 'zt-sangfor.service',
            'EasyMonitor.service',
        ),
        'quiet': ('error while loading shared libraries',),
        'libs': (
            'EasyConnect/resources/bin/svpnservice',
            'EasyConnect/resources/bin/CSClient',
            'EasyConnect/resources/bin/ECAgent',
        ),
        'root_runs': (
            'EasyConnect/resources/bin/ECAgent',
            'EasyConnect/resources/bin/svpnservice',
            'EasyConnect/resources/bin/CSClient',
        ),
        'desktop_writes': (
            '/usr/share/sangfor/EasyConnect/resources/conf',
            '/usr/share/sangfor/EasyConnect/resources/logs',
        ),
        'setuid': (
            '6750 root /usr/share/sangfor/EasyConnect/resources/bin/CSClient',
            '6750 root /usr/share/sangfor/EasyConnect/resources/bin/ECAgent',
            '6750 root /usr/share/sangfor/EasyConnect/resources/bin/svpnservice',
        ),
    },
}

SETTINGS = ('VNC_PW', 'ACCEPT', 'TRUSTAGENT_BYPASS_ROUTES', 'CAPS')
ACCEPT_MODES = ('local', 'lan', 'all')
AUTH_USER = 'kasm_user'
ENGINES = ('container', 'docker')
ENGINE_NAMES = {'container': 'Apple Container', 'docker': 'Docker'}
STAND_IN = 16999
STATE_MOUNT = '/var/lib/zt-state'

# Canonical executable overlay paths (used to normalize POSIX modes on Windows NTFS).
EXECUTABLE_OVERLAYS = frozenset((
    'base/rootfs/usr/local/bin/zt-kasmvnc.sh',
    'common/rootfs/usr/local/bin/zt-init',
    'common/rootfs/usr/local/bin/zt-net-setup.sh',
    'sangfor/common/rootfs/usr/bin/xdg-open',
    'sangfor/atrust/rootfs/usr/bin/loginctl',
    'sangfor/atrust/rootfs/usr/sbin/sysctl-hook',
    'sangfor/atrust/rootfs/usr/local/bin/zt-sangfor-session.sh',
    'sangfor/easyconnect/rootfs/usr/local/bin/zt-conf.sh',
    'sangfor/easyconnect/rootfs/usr/local/bin/zt-sangfor-session.sh',
    'sangfor/easyconnect/rootfs/usr/share/sangfor/EasyConnect/resources/shell/open_browser.sh',
    'trustagent/rootfs/usr/bin/nmcli',
    'trustagent/rootfs/usr/local/bin/zt-trustagent-routes.sh',
    'trustagent/rootfs/usr/local/bin/zt-vnic-add.sh',
    'trustagent/rootfs/usr/local/bin/zt-vnic-remove.sh',
))

# Stock setuid/setgid executables on official ubuntu:24.04 + base packages
# (note: sudo is intentionally not installed).
_SYSTEM_SETUID_COMMON = (
    '4755 root /usr/bin/chfn',
    '4755 root /usr/bin/chsh',
    '4755 root /usr/bin/gpasswd',
    '4755 root /usr/bin/mount',
    '4755 root /usr/bin/newgrp',
    '4755 root /usr/bin/passwd',
    '4755 root /usr/bin/su',
    '4755 root /usr/bin/umount',
    '4754 root /usr/lib/dbus-1.0/dbus-daemon-launch-helper',
    '2755 root /usr/sbin/pam_extrausers_chkpwd',
    '2755 root /usr/sbin/unix_chkpwd',
    '2755 root /usr/bin/expiry',
    '2755 root /usr/bin/chage',
)

_LIB_TRIPLET = {
    'arm64': 'aarch64-linux-gnu',
    'amd64': 'x86_64-linux-gnu',
}

CAPABILITIES = {
    'all': ('ALL',),
    'least': ('NET_ADMIN', 'SYS_ADMIN'),
}

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


def normalize_arch(raw):
    key = (raw or '').strip().lower()
    return _ARCH_ALIASES.get(key)


def host_arch():
    """Return active target container arch ('arm64' or 'amd64').

    Honors ZT_ARCH if set, otherwise auto-detects from the host CPU.
    """
    override = os.environ.get('ZT_ARCH')
    if override:
        arch = normalize_arch(override)
        if not arch:
            raise ValueError(
                f'ZT_ARCH is {override!r}; it must be one of: {", ".join(SUPPORTED_ARCHES)}'
            )
        return arch
    detected = normalize_arch(platform.machine())
    if not detected:
        raise ValueError(
            f'unsupported host architecture {platform.machine()!r}; '
            f'supported: {", ".join(SUPPORTED_ARCHES)}'
        )
    return detected


def platform_for(arch=None):
    return f'linux/{arch or host_arch()}'


def system_setuid(arch=None):
    target = arch or host_arch()
    triplet = _LIB_TRIPLET[target]
    return (*_SYSTEM_SETUID_COMMON, f'2755 root /usr/lib/{triplet}/utempter/utempter')


def blobs_for(spec, arch=None):
    target = arch or host_arch()
    return spec['blobs'][target]


def all_blob_shas(spec):
    return {sha for arch_blobs in spec['blobs'].values() for _, _, sha in arch_blobs}


def spec_args_for(spec, arch=None):
    target = arch or host_arch()
    return dict(spec['args'][target])


def desktop_port(profile):
    return 16901 + 10 * list(CLIENTS).index(profile)


def socks_port(profile):
    return desktop_port(profile) + 1


def desktop_backend_port(profile):
    """Internal loopback port used by containers in `accept lan` mode behind the LAN guard."""
    return desktop_port(profile) + 5


def desktop_url(profile, bind_host='127.0.0.1'):
    return f'https://{bind_host}:{desktop_port(profile)}/'


def container_name(profile):
    return f'zt-{profile}'


def state_volume_name(profile):
    return f'zt-state-{profile}'


def spec_of(name):
    return BASE if name == 'base' else CLIENTS[name]


def resolve_targets(target):
    return list(CLIENTS) if target == 'all' else [target]


def image_ref(name, digest, arch=None):
    """Every image, including base, is content-addressed by version, arch, and digest."""
    target = arch or host_arch()
    version = BASE['version'] if name == 'base' else CLIENTS[name]['version']
    return f'localhost/zt-{name}:{version}-{target}-{digest}'
