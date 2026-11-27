"""Unit and contract tests for zt (runs on macOS, Linux, Windows with python3 -W error)."""
import argparse
import asyncio
import contextlib
import hashlib
import http.server
import io
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from zt import VERSION, bridge, build, cli, config, engine, resources, spec, verify  # noqa: E402
from zt.guest import mux as guest_mux  # noqa: E402

if os.name != 'nt':
    from zt.guest import check as guest_check  # noqa: E402
else:
    guest_check = None

EXECUTABLE = tuple(sorted(spec.EXECUTABLE_OVERLAYS))
UNITS = (
    'base/rootfs/etc/systemd/system/kasmvnc.service',
    'common/rootfs/etc/systemd/system/zt-net.service',
    'common/rootfs/etc/systemd/system/zt-socks.service',
    'sangfor/common/rootfs/etc/systemd/system/zt-sangfor.service',
    'sangfor/atrust/rootfs/etc/systemd/system/aTrustDaemon.service.d/zt.conf',
    'sangfor/atrust/rootfs/etc/systemd/system/eaio_service.service.d/zt.conf',
    'sangfor/easyconnect/rootfs/etc/systemd/system/EasyMonitor.service.d/zt.conf',
    'trustagent/rootfs/etc/systemd/system/trustdservice.service',
    'trustagent/rootfs/etc/systemd/system/trustservice.service',
    'trustagent/rootfs/etc/systemd/system/trustservicemgr.service',
    'trustagent/rootfs/etc/systemd/system/trustnet.service',
    'trustagent/rootfs/etc/systemd/system/udev-vnic-add@.service',
    'trustagent/rootfs/etc/systemd/system/udev-vnic-remove@.service',
)
SHARED = (
    'rootfs/usr/local/bin/zt-init',
    'rootfs/usr/local/bin/zt-net-setup.sh',
    'rootfs/etc/systemd/system/zt-net.service',
    'rootfs/etc/systemd/system/zt-socks.service',
)
HOME_IS_THE_USERS = 'chown -R kasm-user:kasm-user /home/kasm-user'


def overlay_text(rel_path):
    return resources.overlay_files()[rel_path][0].decode('utf-8')


class NamesAndMultiArch(unittest.TestCase):
    def test_ports_and_volume_names_follow_layout(self):
        self.assertEqual([spec.desktop_port(p) for p in spec.CLIENTS], [16901, 16911, 16921])
        self.assertEqual([spec.CLIENTS[p]['port'] for p in spec.CLIENTS], [16901, 16911, 16921])
        self.assertEqual([spec.socks_port(p) for p in spec.CLIENTS], [16902, 16912, 16922])
        self.assertEqual([spec.desktop_backend_port(p) for p in spec.CLIENTS], [16906, 16916, 16926])
        self.assertEqual(
            [spec.state_volume_name(p) for p in spec.CLIENTS],
            ['zt-state-trustagent', 'zt-state-atrust', 'zt-state-easyconnect'],
        )
        self.assertEqual(spec.desktop_url('easyconnect'), 'https://127.0.0.1:16921/')
        self.assertEqual(spec.desktop_url('easyconnect', '0.0.0.0'), 'https://0.0.0.0:16921/')

    def test_all_covers_every_client_in_order(self):
        self.assertEqual(spec.resolve_targets('all'), ['trustagent', 'atrust', 'easyconnect'])
        self.assertEqual(spec.resolve_targets('atrust'), ['atrust'])

    def test_every_image_is_arch_and_content_addressed(self):
        self.assertEqual(
            spec.image_ref('base', 'deadbeef1234', 'arm64'),
            f"localhost/zt-base:{spec.BASE['version']}-arm64-deadbeef1234",
        )
        self.assertEqual(
            spec.image_ref('atrust', 'deadbeef1234', 'amd64'),
            f"localhost/zt-atrust:{spec.CLIENTS['atrust']['version']}-amd64-deadbeef1234",
        )
        self.assertNotEqual(build.current_ref('base', 'arm64'), build.current_ref('base', 'amd64'))
        self.assertNotEqual(build.current_ref('atrust', 'arm64'), build.current_ref('atrust', 'amd64'))

    def test_host_arch_detection_and_override(self):
        with mock.patch.dict(os.environ, {'ZT_ARCH': 'amd64'}):
            self.assertEqual(spec.host_arch(), 'amd64')
            self.assertEqual(spec.platform_for(), 'linux/amd64')
        with mock.patch.dict(os.environ, {'ZT_ARCH': 'aarch64'}):
            self.assertEqual(spec.host_arch(), 'arm64')
        with mock.patch.dict(os.environ, {'ZT_ARCH': 'riscv64'}), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            config.target_arch()
        self.assertIn("ZT_ARCH is 'riscv64'", err.getvalue())

        env_no_arch = {k: v for k, v in os.environ.items() if k != 'ZT_ARCH'}
        with mock.patch.dict(os.environ, env_no_arch, clear=True), \
                mock.patch.object(spec.platform, 'machine', return_value='x86_64'):
            self.assertEqual(spec.host_arch(), 'amd64')
        with mock.patch.dict(os.environ, env_no_arch, clear=True), \
                mock.patch.object(spec.platform, 'machine', return_value='AMD64'):
            self.assertEqual(spec.host_arch(), 'amd64')
        with mock.patch.dict(os.environ, env_no_arch, clear=True), \
                mock.patch.object(spec.platform, 'machine', return_value='arm64'):
            self.assertEqual(spec.host_arch(), 'arm64')

    def test_system_setuid_matches_arch_triplet(self):
        self.assertIn('2755 root /usr/lib/aarch64-linux-gnu/utempter/utempter', spec.system_setuid('arm64'))
        self.assertIn('2755 root /usr/lib/x86_64-linux-gnu/utempter/utempter', spec.system_setuid('amd64'))


class SettingsAndCrossPlatform(unittest.TestCase):
    def test_config_lines(self):
        self.assertEqual(
            config.parse_config(
                '# a comment\n\nVNC_PW = "s3cret"\nACCEPT=all\n'
                'TRUSTAGENT_BYPASS_ROUTES=10.0.0.0/8,192.168.0.0/16\n'
            ),
            {
                'VNC_PW': 's3cret',
                'ACCEPT': 'all',
                'TRUSTAGENT_BYPASS_ROUTES': '10.0.0.0/8,192.168.0.0/16',
            },
        )

    def test_default_accept_is_local_and_requires_no_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_patch = {k: v for k, v in os.environ.items() if not k.startswith('ZT_')}
            env_patch['ZT_CONFIG'] = str(Path(tmp) / 'config')
            with mock.patch.dict(os.environ, env_patch, clear=True), \
                    mock.patch.object(config, 'host_timezone', return_value='Asia/Shanghai'):
                self.assertEqual(config.accept_mode(), 'local')
                self.assertEqual(config.bind_address(), '127.0.0.1')
                self.assertEqual(config.auth_password(), '')
                self.assertEqual(
                    config.container_env('atrust'),
                    {'ZT_NET_MODE': 'gateway', 'ZT_AUTH': '0', 'TZ': 'Asia/Shanghai'},
                )

    def test_accept_all_requires_valid_password(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            cfg = str(Path(tmp) / 'config')
            for rejected in ('', '12345', '123456789', '#abcde', 'abc\ndef', 'abc\rdef', ' abcdef'):
                with mock.patch.dict(
                    os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'all', 'ZT_VNC_PW': rejected}
                ), self.assertRaises(SystemExit):
                    config.container_env('atrust')

            with mock.patch.dict(
                os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'all', 'ZT_VNC_PW': 's3cret'}
            ), mock.patch.object(config, 'host_timezone', return_value='Europe/Paris'):
                self.assertEqual(config.bind_address(), '0.0.0.0')
                self.assertEqual(
                    config.container_env('atrust', net_mode='subnet'),
                    {
                        'ZT_NET_MODE': 'subnet',
                        'ZT_AUTH': '1',
                        'VNC_PW': 's3cret',
                        'TZ': 'Europe/Paris',
                    },
                )

    def test_accept_lan_is_passwordless_and_classifies_lan_ips(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = str(Path(tmp) / 'config')
            env_patch = {k: v for k, v in os.environ.items() if not k.startswith('ZT_')}
            env_patch.update({'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'lan'})
            with mock.patch.dict(os.environ, env_patch, clear=True), \
                    mock.patch.object(config, 'host_timezone', return_value='Asia/Shanghai'):
                self.assertEqual(config.accept_mode(), 'lan')
                self.assertEqual(config.bind_address(), '0.0.0.0')
                self.assertEqual(config.auth_password(), '')
                self.assertEqual(config.auth_fingerprint(), '')
                self.assertEqual(
                    config.container_env('atrust'),
                    {'ZT_NET_MODE': 'gateway', 'ZT_AUTH': '0', 'TZ': 'Asia/Shanghai'},
                )
        for allowed in (
            '127.0.0.1', '10.0.0.5', '172.16.1.2', '172.31.255.1',
            '192.168.1.20', '169.254.1.1', '100.64.0.1', '100.127.255.254',
            '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1%en0', '::ffff:192.168.1.5',
        ):
            self.assertTrue(config.is_lan_ip(allowed), allowed)
        for rejected in (
            '8.8.8.8', '1.1.1.1', '172.32.0.1', '100.128.0.1',
            '2001:4860:4860::8888', '::ffff:8.8.8.8', 'not-an-ip', '',
        ):
            self.assertFalse(config.is_lan_ip(rejected), rejected)

    def test_windows_paths_timezone_and_engine_defaults(self):
        self.assertEqual(config.windows_timezone_to_iana('China Standard Time'), 'Asia/Shanghai')
        self.assertEqual(config.windows_timezone_to_iana('Pacific Standard Time_dstoff'), 'America/Los_Angeles')
        self.assertEqual(config.windows_timezone_to_iana('UTC'), 'Etc/UTC')
        self.assertIsNone(config.windows_timezone_to_iana('Nonexistent Zone'))

        with mock.patch.object(config, '_is_windows', return_value=True), \
                mock.patch.dict(
                    os.environ,
                    {'APPDATA': '/fake/roaming', 'LOCALAPPDATA': '/fake/local'},
                    clear=True,
                ):
            self.assertEqual(config.config_file(), Path('/fake/roaming/zt/config'))
            self.assertEqual(config.cache_dir(), Path('/fake/local/zt/cache'))
            self.assertEqual(config.state_dir(), Path('/fake/local/zt/state'))
            self.assertEqual(config.resolve_engine_choice()[0], 'docker')

    def test_bypass_routes_go_to_trustagent_only(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ,
            {
                'ZT_CONFIG': str(Path(tmp) / 'config'),
                'ZT_ACCEPT': 'local',
                'ZT_TRUSTAGENT_BYPASS_ROUTES': '10.0.0.0/8',
            },
        ):
            self.assertEqual(config.container_env('trustagent')['BYPASS_ROUTES'], '10.0.0.0/8')
            self.assertNotIn('BYPASS_ROUTES', config.container_env('atrust'))

    def test_unknown_setting_warned_once(self):
        config._told_about.clear()
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_CONFIG': str(Path(tmp) / 'config')}), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            Path(tmp, 'config').write_text('ACCEPT=local\nTZ=UTC\n', encoding='utf-8')
            self.assertEqual(config.setting('ACCEPT'), 'local')
            self.assertEqual(config.setting('ACCEPT'), 'local')
            self.assertEqual(errors.getvalue().count('ignoring unknown settings'), 1)
            self.assertIn('TZ', errors.getvalue())

    def test_invalid_zt_engine_fails_fast(self):
        with mock.patch.dict(os.environ, {'ZT_ENGINE': 'podman'}), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            config.resolve_engine_choice()
        self.assertIn("ZT_ENGINE is 'podman'", err.getvalue())

    def test_write_setting_is_atomic_with_strict_permissions_and_leaves_no_temp_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'config'
            with mock.patch.dict(os.environ, {'ZT_CONFIG': str(cfg)}):
                config.write_setting('ACCEPT', 'local')
                config.write_setting('VNC_PW', 's3cret')
                config.write_setting('ACCEPT', 'all')
            self.assertEqual(os.listdir(tmp), ['config'])
            parsed = config.parse_config(cfg.read_text(encoding='utf-8'))
            self.assertEqual(parsed, {'VNC_PW': 's3cret', 'ACCEPT': 'all'})
            if os.name != 'nt':
                self.assertEqual(cfg.stat().st_mode & 0o777, 0o600)


class OverlayAndBuildDAG(unittest.TestCase):
    def test_scripts_executable_and_units_not(self):
        files = resources.overlay_files()
        for script in EXECUTABLE:
            self.assertTrue(files[script][1] & 0o111, script)
        for unit in UNITS:
            self.assertFalse(files[unit][1] & 0o111, unit)

        # Ensure Makefile SHELL_SCRIPTS stays in sync with install.sh + every EXECUTABLE_OVERLAYS entry.
        makefile = (ROOT / 'Makefile').read_text(encoding='utf-8')
        self.assertIn('install.sh', makefile)
        for rel in spec.EXECUTABLE_OVERLAYS:
            self.assertIn(f'overlay/{rel}', makefile, f'missing from Makefile SHELL_SCRIPTS: overlay/{rel}')

    def test_sangfor_clients_have_isolated_leaf_layers(self):
        atrust = build.overlay_for(spec.CLIENTS['atrust'])
        ec = build.overlay_for(spec.CLIENTS['easyconnect'])
        self.assertIn('rootfs/etc/systemd/system/aTrustDaemon.service.d/zt.conf', atrust)
        self.assertNotIn('rootfs/etc/systemd/system/EasyMonitor.service.d/zt.conf', atrust)
        self.assertNotIn('rootfs/usr/local/bin/zt-conf.sh', atrust)
        self.assertIn('rootfs/etc/systemd/system/EasyMonitor.service.d/zt.conf', ec)
        self.assertIn('rootfs/usr/local/bin/zt-conf.sh', ec)
        self.assertNotIn('rootfs/etc/systemd/system/aTrustDaemon.service.d/zt.conf', ec)
        for name in (*SHARED, 'rootfs/etc/systemd/system/zt-sangfor.service',
                     'rootfs/usr/local/bin/zt-sangfor-session.sh',
                     'rootfs/etc/zt/state-paths.conf', 'Dockerfile'):
            self.assertIn(name, atrust)
            self.assertIn(name, ec)

    def test_every_client_ships_valid_persistent_state_manifest(self):
        for profile, item in spec.CLIENTS.items():
            files = build.overlay_for(item)
            self.assertIn('rootfs/etc/zt/state-paths.conf', files, profile)
            raw = files['rootfs/etc/zt/state-paths.conf'][0].decode('utf-8')
            slots = set()
            entries = 0
            for line in raw.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                self.assertEqual(len(parts), 4, (profile, line))
                slot, target, owner, mode = parts
                self.assertNotIn(slot, slots, (profile, slot))
                slots.add(slot)
                self.assertTrue(target.startswith('/'), (profile, target))
                self.assertIn(':', owner, (profile, owner))
                self.assertRegex(mode, r'^[0-7]{4}$', (profile, mode))
                entries += 1
            self.assertGreaterEqual(entries, 4, profile)

    def test_editing_easyconnect_does_not_invalidate_atrust_hash(self):
        atrust_before = build.content_hash(spec.CLIENTS['atrust'], 'arm64')
        ec_before = build.content_hash(spec.CLIENTS['easyconnect'], 'arm64')
        orig = resources.overlay_files

        def touched():
            files = orig()
            data, mode = files['sangfor/easyconnect/Dockerfile']
            return {**files, 'sangfor/easyconnect/Dockerfile': (data + b'\n# change\n', mode)}

        with mock.patch.object(build, 'overlay_files', touched):
            self.assertEqual(build.content_hash(spec.CLIENTS['atrust'], 'arm64'), atrust_before)
            self.assertNotEqual(build.content_hash(spec.CLIENTS['easyconnect'], 'arm64'), ec_before)

    def test_changing_base_version_changes_both_base_ref_and_client_ref(self):
        base_before = build.current_ref('base', 'amd64')
        atrust_before = build.current_ref('atrust', 'amd64')
        with mock.patch.dict(spec.BASE, {'version': '1.5.3-systemd'}):
            self.assertNotEqual(build.current_ref('base', 'amd64'), base_before)
            self.assertNotEqual(build.current_ref('atrust', 'amd64'), atrust_before)
            self.assertEqual(
                build.build_args(spec.CLIENTS['atrust'], 'amd64')['BASE_IMAGE'],
                build.current_ref('base', 'amd64'),
            )

    def test_no_orphan_overlay_files(self):
        prefixes = tuple(
            layer + '/'
            for item in (spec.BASE, *spec.CLIENTS.values())
            for layer in item['overlays']
        )
        for name in resources.overlay_files():
            self.assertTrue(name.startswith(prefixes), name)

    def test_official_multiarch_blob_sources_and_sha256_pins(self):
        for arch in spec.SUPPORTED_ARCHES:
            for name, item in (('base', spec.BASE), *spec.CLIENTS.items()):
                blobs = spec.blobs_for(item, arch)
                self.assertTrue(blobs, (name, arch))
                for fname, url, sha in blobs:
                    self.assertEqual(len(sha), 64, (name, arch, fname))
                    int(sha, 16)
                    self.assertTrue(url.startswith('https://'), url)
            self.assertIn('github.com/kasmtech/KasmVNC/releases', spec.blobs_for(spec.BASE, arch)[0][1])
            self.assertIn('atrustcdn.sangfor.com/', spec.blobs_for(spec.CLIENTS['atrust'], arch)[0][1])
            ec_urls = dict((f, u) for f, u, _ in spec.blobs_for(spec.CLIENTS['easyconnect'], arch))
            self.assertIn('download.sangfor.com.cn/', ec_urls['easyconnect.pkg'])
            self.assertIn('github.com/electron/electron/releases', ec_urls['electron.zip'])
        self.assertTrue(
            urllib.parse.unquote(
                dict((f, u) for f, u, _ in spec.blobs_for(spec.CLIENTS['easyconnect'], 'arm64'))['easyconnect.pkg']
            ).endswith('/统信UOS 海思麒麟990 SSL VPN客户端.zip')
        )
        self.assertTrue(
            dict((f, u) for f, u, _ in spec.blobs_for(spec.CLIENTS['easyconnect'], 'amd64'))['easyconnect.pkg']
            .endswith('/EasyConnect_x64_7_6_7_3.deb')
        )
        self.assertFalse(hasattr(spec, 'UPSTREAM'))

    def test_fetch_blob_retries_verifies_sha256_and_hardlinks_in_build_context(self):
        payload = b'verified-vendor-payload' * 128
        good_sha = hashlib.sha256(payload).hexdigest()
        bad_sha = '0' * 64

        class FakeResp(io.BytesIO):
            headers = {'Content-Length': str(len(payload))}

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.close()

        calls = 0

        def flaky_urlopen(req, timeout=300):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise urllib.error.URLError('transient reset')
            return FakeResp(payload)

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_CACHE': tmp}), \
                mock.patch.object(build.time, 'sleep'), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.object(build.urllib.request, 'urlopen', side_effect=flaky_urlopen):
                cached = build.fetch_blob('pkg.deb', 'https://example.invalid/pkg.deb', good_sha)
            self.assertEqual(calls, 2)
            self.assertEqual(cached.read_bytes(), payload)

            # Second call hits SHA256 cache without network
            with mock.patch.object(build.urllib.request, 'urlopen', side_effect=AssertionError('should use cache')):
                self.assertEqual(build.fetch_blob('pkg.deb', 'https://example.invalid/pkg.deb', good_sha), cached)

            # Hardlink deduplication shares the same inode without copying bytes
            linked = Path(tmp) / 'linked.deb'
            build._link_or_copy(cached, linked)
            self.assertEqual(linked.read_bytes(), payload)
            self.assertEqual(os.stat(cached).st_ino, os.stat(linked).st_ino)

            # Tampered download is rejected and never left in cache
            with mock.patch.object(build.urllib.request, 'urlopen', side_effect=lambda *a, **kw: FakeResp(b'tampered')), \
                    self.assertRaises(SystemExit):
                build.fetch_blob('pkg.deb', 'https://example.invalid/pkg.deb', bad_sha, retries=2)
            self.assertFalse((Path(tmp) / 'blobs' / bad_sha).exists())


class SecurityContracts(unittest.TestCase):
    def test_home_owned_by_kasm_user_and_kasmvnc_supports_zt_auth_toggle(self):
        for name, item in (('base', spec.BASE), *spec.CLIENTS.items()):
            dockerfile = build.overlay_for(item)['Dockerfile'][0].decode('utf-8')
            self.assertIn(HOME_IS_THE_USERS, dockerfile, name)
            self.assertIn('chmod -R o-w /home/kasm-user', dockerfile, name)
        kasm_unit = overlay_text('base/rootfs/etc/systemd/system/kasmvnc.service')
        self.assertIn('NoNewPrivileges=true', kasm_unit)
        self.assertIn('Requires=zt-net.service', kasm_unit)
        self.assertIn('PassEnvironment=ZT_AUTH VNC_PW TZ', kasm_unit)
        kasm_launch = overlay_text('base/rootfs/usr/local/bin/zt-kasmvnc.sh')
        self.assertIn('if [ "$auth" = 0 ]; then', kasm_launch)
        self.assertIn('-disableBasicAuth', kasm_launch)
        self.assertIn('kasmvncpasswd -u kasm_user -wo', kasm_launch)

    def test_zt_init_persists_machine_id_tls_and_state_mounts(self):
        init_sh = overlay_text('common/rootfs/usr/local/bin/zt-init')
        self.assertIn('STATE_ROOT=/var/lib/zt-state', init_sh)
        self.assertIn('mountpoint -q "$STATE_ROOT"', init_sh)
        self.assertIn('/etc/machine-id', init_sh)
        self.assertIn('/etc/zt/state-paths.conf', init_sh)
        self.assertIn('mount --bind "$src" "$target"', init_sh)
        self.assertIn('/etc/zt/openbox', init_sh)
        self.assertIn('openssl req -x509', init_sh)

        # Wiring test: KasmVNC's configured TLS cert & key MUST match the exact paths
        # restored by zt-init, and zt-kasmvnc.sh must not generate an unpersisted self.pem.
        kasm_yaml = overlay_text('base/rootfs/etc/kasmvnc/kasmvnc.yaml')
        kasm_sh = overlay_text('base/rootfs/usr/local/bin/zt-kasmvnc.sh')
        cert_init = next(
            line.split('=', 1)[1].strip()
            for line in init_sh.splitlines()
            if line.strip().startswith('CERT=')
        )
        key_init = next(
            line.split('=', 1)[1].strip()
            for line in init_sh.splitlines()
            if line.strip().startswith('KEY=')
        )
        cert_yaml = next(
            line.split(':', 1)[1].strip()
            for line in kasm_yaml.splitlines()
            if line.strip().startswith('pem_certificate:')
        )
        key_yaml = next(
            line.split(':', 1)[1].strip()
            for line in kasm_yaml.splitlines()
            if line.strip().startswith('pem_key:')
        )
        self.assertEqual(cert_yaml, cert_init)
        self.assertEqual(key_yaml, key_init)
        self.assertNotIn('self.pem', kasm_yaml)
        self.assertNotIn('self.pem', kasm_sh)

    def test_zt_sangfor_service_has_nnp_and_drops_privs_for_conf_and_x11(self):
        unit = overlay_text('sangfor/common/rootfs/etc/systemd/system/zt-sangfor.service')
        self.assertIn('NoNewPrivileges=true', unit)
        self.assertNotIn('XAUTHORITY=', unit)
        self.assertEqual(unit.count('setpriv --reuid kasm-user --regid kasm-user --init-groups --no-new-privs'), 3)
        conf = overlay_text('sangfor/easyconnect/rootfs/usr/local/bin/zt-conf.sh')
        self.assertNotIn('chown', conf)
        self.assertIn('cp -rP', conf)

    def test_all_trustagent_vendor_units_have_nnp(self):
        for unit in ('trustdservice', 'trustservice', 'trustservicemgr', 'trustnet',
                     'udev-vnic-add@', 'udev-vnic-remove@'):
            content = overlay_text(f'trustagent/rootfs/etc/systemd/system/{unit}.service')
            self.assertIn('NoNewPrivileges=true', content, unit)

    def test_network_policy_uses_dedicated_chain_and_filters_udp(self):
        unit = overlay_text('common/rootfs/etc/systemd/system/zt-net.service')
        self.assertIn('PassEnvironment=ZT_NET_MODE', unit)
        script = overlay_text('common/rootfs/usr/local/bin/zt-net-setup.sh')
        self.assertIn('ZT-INPUT', script)
        self.assertIn('-I INPUT 1 -j ZT-INPUT', script)
        self.assertIn('zt: host only udp', script)
        self.assertIn('zt: tunnel udp', script)


class TheZipapp(unittest.TestCase):
    @unittest.skipUnless((ROOT / 'zt').exists(), 'run make first')
    def test_single_file_zipapp_runs_and_embeds_exact_overlay(self):
        archive_path = ROOT / 'zt'
        self.assertTrue(zipfile.is_zipfile(archive_path))
        proc = subprocess.run([sys.executable, str(archive_path), '--version'], capture_output=True, text=True, check=True)
        self.assertEqual(proc.stdout.strip(), f'zt {VERSION}')
        with zipfile.ZipFile(archive_path, 'r') as zf:
            embedded = {
                info.filename[len('overlay/'):]: (zf.read(info.filename), (info.external_attr >> 16) & 0o777)
                for info in zf.infolist()
                if info.filename.startswith('overlay/') and not info.is_dir()
            }
            self.assertEqual(embedded, resources.overlay_files())
            for name in ('check', 'probe', 'mux'):
                self.assertEqual(zf.read(f'zt/guest/{name}.py').decode('utf-8'), resources.guest_script(name))


@unittest.skipIf(os.name == 'nt', 'guest/check.py targets Linux containers only')
class GuestVerifier(unittest.TestCase):
    def test_checks_tuple_matches_between_host_spec_and_guest_harness(self):
        self.assertEqual(spec.CHECKS, guest_check.CHECKS)

    def test_elf_machine_reads_uint16_le_and_be(self):
        with tempfile.TemporaryDirectory() as tmp:
            arm64 = Path(tmp) / 'arm64'
            x86_64 = Path(tmp) / 'x86_64'
            be_mips = Path(tmp) / 'mipsbe'
            plain = Path(tmp) / 'text'
            arm64.write_bytes(b'\x7fELF\x02\x01' + b'\x00' * 12 + struct.pack('<H', 183))
            x86_64.write_bytes(b'\x7fELF\x02\x01' + b'\x00' * 12 + struct.pack('<H', 62))
            be_mips.write_bytes(b'\x7fELF\x02\x02' + b'\x00' * 12 + struct.pack('>H', 8))
            plain.write_text('#!/bin/sh\n', encoding='utf-8')
            self.assertEqual(guest_check.elf_machine(arm64), 183)
            self.assertEqual(guest_check.elf_machine(x86_64), 62)
            self.assertEqual(guest_check.elf_machine(be_mips), 8)
            self.assertIsNone(guest_check.elf_machine(plain))

    def test_check_ownership_catches_stray_files_with_empty_and_multi_excludes(self):
        uid = os.getuid()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conf = root / 'usr/share/sangfor/conf'
            logs = root / 'usr/share/sangfor/logs'
            stray = root / 'etc/evil.txt'
            conf.mkdir(parents=True)
            logs.mkdir(parents=True)
            stray.parent.mkdir(parents=True)
            (conf / 'a').write_text('ok', encoding='utf-8')
            (logs / 'l1').write_text('ok', encoding='utf-8')
            (logs / 'l2').write_text('ok', encoding='utf-8')
            stray.write_text('bad', encoding='utf-8')

            ok, detail = guest_check.check_ownership(root=str(root), uid=uid, desktop_writes=(), extra_excludes=())
            self.assertFalse(ok)
            self.assertIn('evil.txt', detail)

            ok, detail = guest_check.check_ownership(
                root=str(root), uid=uid, desktop_writes=(str(conf), str(logs)), extra_excludes=(),
            )
            self.assertFalse(ok)
            self.assertIn('evil.txt', detail)
            self.assertNotIn('/logs/', detail)

            stray.unlink()
            ok, detail = guest_check.check_ownership(
                root=str(root), uid=uid,
                desktop_writes=(str(conf), str(logs)),
                extra_excludes=(str(root / 'etc'), str(root / 'usr')),
            )
            self.assertTrue(ok, detail)

    def test_check_path_chain_catches_symlink_into_writable_target_and_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            safe_dir = root / 'usr/bin'
            evil_dir = root / 'tmp_writable'
            safe_dir.mkdir(parents=True)
            evil_dir.mkdir(mode=0o777)
            evil_dir.chmod(0o777)
            target = evil_dir / 'pwn'
            target.write_text('x', encoding='utf-8')
            target.chmod(0o777)
            link = safe_dir / 'tool'
            link.symlink_to(target)

            missing_issues = guest_check.check_path_chain(str(safe_dir / 'missing'), root=str(root))
            self.assertTrue(any('missing' in msg for msg in missing_issues), missing_issues)

            opt_issues = guest_check.check_path_chain(
                str(evil_dir / 'not-installed'), root=str(root), must_exist=False,
            )
            self.assertTrue(any('tmp_writable' in msg for msg in opt_issues), opt_issues)

            masked = safe_dir / 'masked.service'
            masked.symlink_to('/dev/null')
            masked_issues = guest_check.check_path_chain(str(masked), root=str(root))
            self.assertFalse(any('/dev/null' in msg for msg in masked_issues), masked_issues)

            link_issues = guest_check.check_path_chain(str(link), root=str(root))
            self.assertTrue(any('tmp_writable' in msg for msg in link_issues), link_issues)

    def test_parse_systemd_exec_paths_includes_explicit_user_root_and_dropins(self):
        sample = (
            'ActiveState=active\n'
            'User=root\n'
            'FragmentPath=/etc/systemd/system/zt-sangfor.service\n'
            'DropInPaths=/etc/systemd/system/zt-sangfor.service.d/zt.conf\n'
            'ExecStartPre={ path=/usr/bin/setpriv ; argv[]=/usr/bin/setpriv ... }\n'
            'ExecStart={ path=/usr/local/bin/zt-sangfor-session.sh ; argv[]=... }\n'
            '\n'
            'ActiveState=inactive\n'
            'User=\n'
            'FragmentPath=/usr/lib/systemd/system/rc-local.service\n'
            'ExecStart={ path=/etc/rc.local ; argv[]=/etc/rc.local start }\n'
            '\n'
            'ActiveState=active\n'
            'User=nobody\n'
            'FragmentPath=/etc/systemd/system/zt-socks.service\n'
            'ExecStart={ path=/usr/bin/microsocks ; argv[]=... }\n'
        )
        units, active_execs, optional_execs = guest_check.parse_systemd_exec_paths(sample)
        self.assertIn('/etc/systemd/system/zt-sangfor.service', units)
        self.assertIn('/etc/systemd/system/zt-sangfor.service.d/zt.conf', units)
        self.assertIn('/usr/local/bin/zt-sangfor-session.sh', active_execs)
        self.assertIn('/etc/rc.local', optional_execs)
        self.assertNotIn('/usr/bin/microsocks', active_execs)

    def test_parse_report_strict_json_validation(self):
        complete_map = {c: {'ok': True, 'detail': ''} for c in spec.CHECKS}
        good = json.dumps({'version': 1, 'complete': True, 'checks': complete_map}) + '\n'
        self.assertEqual(verify.parse_report(good), [(c, 'ok', '') for c in spec.CHECKS])

        missing = dict(complete_map)
        del missing['ownership']
        findings = verify.parse_report(json.dumps({'version': 1, 'complete': True, 'checks': missing}))
        self.assertEqual(findings[-1][:2], ('inside', 'fail'))
        self.assertIn('ownership', findings[-1][2])


class MultiplexedBridge(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'guest/mux.py stdio pipes run inside Linux containers')
    def test_host_and_guest_mux_handle_concurrent_streams_and_rfc1929_auth(self):
        async def scenario():
            backend_hits = 0

            async def fake_microsocks(reader, writer):
                nonlocal backend_hits
                backend_hits += 1
                try:
                    greet = await reader.readexactly(3)
                    if greet != b'\x05\x01\x00':
                        return
                    writer.write(b'\x05\x00')
                    await writer.drain()
                    while data := await reader.read(4096):
                        writer.write(b'ok:' + data)
                        await writer.drain()
                except asyncio.IncompleteReadError:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()

            backend = await asyncio.start_server(fake_microsocks, '127.0.0.1', 0)
            backend_port = backend.sockets[0].getsockname()[1]

            class LocalMuxTunnel(bridge.HostMuxTunnel):
                def __init__(self, auth=None):
                    super().__init__(engine.AppleContainerEngine(), 'zt-test', auth=auth)
                    self.spawns = 0

                async def _spawn_process(self):
                    self.spawns += 1
                    return await asyncio.create_subprocess_exec(
                        sys.executable, '-c', resources.guest_script('mux'),
                        '127.0.0.1', str(backend_port),
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

            tunnel = LocalMuxTunnel(auth=('kasm_user', 's3cret'))
            frontend = await asyncio.start_server(tunnel.handle_client, '127.0.0.1', 0)
            frontend_port = frontend.sockets[0].getsockname()[1]

            try:
                # 1. No-auth greeting rejected without touching backend
                r, w = await asyncio.open_connection('127.0.0.1', frontend_port)
                w.write(b'\x05\x01\x00')
                await w.drain()
                self.assertEqual(await r.readexactly(2), b'\x05\xff')
                w.close()
                await w.wait_closed()
                self.assertEqual(backend_hits, 0)

                # 2. Wrong password rejected without touching backend
                r, w = await asyncio.open_connection('127.0.0.1', frontend_port)
                w.write(b'\x05\x01\x02')
                await w.drain()
                self.assertEqual(await r.readexactly(2), b'\x05\x02')
                w.write(b'\x01\x09kasm_user\x06wrong1')
                await w.drain()
                self.assertEqual(await r.readexactly(2), b'\x01\x01')
                w.close()
                await w.wait_closed()
                self.assertEqual(backend_hits, 0)

                # 3. 10 concurrent authenticated streams share 1 mux process
                async def authed_client(idx):
                    cr, cw = await asyncio.open_connection('127.0.0.1', frontend_port)
                    cw.write(b'\x05\x01\x02')
                    await cw.drain()
                    assert await cr.readexactly(2) == b'\x05\x02'
                    cw.write(b'\x01\x09kasm_user\x06s3cret')
                    await cw.drain()
                    assert await cr.readexactly(2) == b'\x01\x00'
                    payload = f'req-{idx}'.encode() * 20
                    cw.write(payload)
                    cw.write_eof()
                    await cw.drain()
                    reply = await cr.read()
                    cw.close()
                    await cw.wait_closed()
                    return reply, b'ok:' + payload

                results = await asyncio.gather(*(authed_client(i) for i in range(10)))
                for got, want in results:
                    self.assertEqual(got, want)
                self.assertEqual(tunnel.spawns, 1)
                self.assertEqual(backend_hits, 10)

                loop = asyncio.get_running_loop()
                self.assertFalse(await loop.run_in_executor(None, bridge.socks_ready, frontend_port, None))
                self.assertTrue(
                    await loop.run_in_executor(
                        None, bridge.socks_ready, frontend_port, ('kasm_user', 's3cret'),
                    )
                )
            finally:
                frontend.close()
                await frontend.wait_closed()
                await tunnel.close()
                backend.close()
                await backend.wait_closed()

        asyncio.run(scenario())

    def test_lan_guard_peer_filter_and_tcp_splice(self):
        class FakeWriter:
            def __init__(self, ip):
                self._ip = ip

            def get_extra_info(self, key):
                return (self._ip, 54321) if key == 'peername' else None

        self.assertTrue(bridge._peer_allowed(FakeWriter('192.168.1.5'), lan_only=True))
        self.assertTrue(bridge._peer_allowed(FakeWriter('100.64.1.2'), lan_only=True))
        self.assertFalse(bridge._peer_allowed(FakeWriter('8.8.8.8'), lan_only=True))
        self.assertTrue(bridge._peer_allowed(FakeWriter('8.8.8.8'), lan_only=False))

        async def splice_scenario():
            backend_hits = 0

            async def echo_backend(reader, writer):
                nonlocal backend_hits
                backend_hits += 1
                data = await reader.read(4096)
                writer.write(b'HTTPS:' + data)
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            backend = await asyncio.start_server(echo_backend, '127.0.0.1', 0)
            bport = backend.sockets[0].getsockname()[1]

            async def guard(reader, writer):
                if not bridge._peer_allowed(writer, lan_only=True):
                    writer.close()
                    await writer.wait_closed()
                    return
                await bridge._splice_tcp(reader, writer, '127.0.0.1', bport)

            frontend = await asyncio.start_server(guard, '127.0.0.1', 0)
            fport = frontend.sockets[0].getsockname()[1]
            try:
                r, w = await asyncio.open_connection('127.0.0.1', fport)
                w.write(b'hello-vnc')
                await w.drain()
                self.assertEqual(await r.read(), b'HTTPS:hello-vnc')
                w.close()
                await w.wait_closed()
                self.assertEqual(backend_hits, 1)

                with mock.patch.object(bridge, 'is_lan_ip', return_value=False):
                    r, w = await asyncio.open_connection('127.0.0.1', fport)
                    try:
                        w.write(b'blocked')
                        await w.drain()
                        self.assertEqual(await r.read(), b'')
                    except ConnectionError:
                        pass
                    finally:
                        w.close()
                        with contextlib.suppress(ConnectionError, OSError):
                            await w.wait_closed()
                self.assertEqual(backend_hits, 1)
            finally:
                frontend.close()
                await frontend.wait_closed()
                backend.close()
                await backend.wait_closed()

        asyncio.run(splice_scenario())

    def test_socks5_rfc1929_credential_reader_cross_platform(self):
        async def scenario():
            results = []

            async def handler(reader, writer):
                creds = await bridge._read_socks5_credentials(reader, writer)
                results.append(creds)
                if creds is not None:
                    writer.write(b'\x01\x00')
                    await writer.drain()
                writer.close()
                await writer.wait_closed()

            srv = await asyncio.start_server(handler, '127.0.0.1', 0)
            port = srv.sockets[0].getsockname()[1]
            try:
                # No-auth greeting rejected with 0x05 0xff
                r, w = await asyncio.open_connection('127.0.0.1', port)
                w.write(b'\x05\x01\x00')
                await w.drain()
                self.assertEqual(await r.readexactly(2), b'\x05\xff')
                w.close()
                await w.wait_closed()

                # Valid RFC 1929 username/password read cleanly
                r, w = await asyncio.open_connection('127.0.0.1', port)
                w.write(b'\x05\x01\x02')
                await w.drain()
                self.assertEqual(await r.readexactly(2), b'\x05\x02')
                w.write(b'\x01\x09kasm_user\x06s3cret')
                await w.drain()
                self.assertEqual(await r.readexactly(2), b'\x01\x00')
                w.close()
                await w.wait_closed()
            finally:
                srv.close()
                await srv.wait_closed()
            self.assertEqual(results, [None, (b'kasm_user', b's3cret')])

        asyncio.run(scenario())

    def test_socks_addr_codec_and_host_udp_protocol_security_filters(self):
        # Address codec: IPv4, IPv6, IPv4-mapped IPv6, domain, malformed inputs.
        v4 = guest_mux.encode_socks_addr('10.20.30.40', 5353)
        self.assertEqual(guest_mux.parse_socks_addr(v4 + b'hi'), (1, '10.20.30.40', 5353, 7))
        v4_mapped = guest_mux.encode_socks_addr('::ffff:192.168.1.9', 443)
        self.assertEqual(guest_mux.parse_socks_addr(v4_mapped), (1, '192.168.1.9', 443, 7))
        v6 = guest_mux.encode_socks_addr('fd00::1%eth0', 53)
        self.assertEqual(guest_mux.parse_socks_addr(v6 + b'x'), (4, 'fd00::1', 53, 19))
        dom = b'\x03\x0blocalhost.x\x00\x35payload'
        self.assertEqual(guest_mux.parse_socks_addr(dom), (3, 'localhost.x', 53, 15))
        for bad in (b'', b'\x01\x01\x02', b'\x03\x00\x00\x35', b'\x03\x03a\x00b\x00\x35',
                    b'\x03\x03a b\x00\x35', b'\x09\x00\x00\x00\x00\x00'):
            self.assertIsNone(guest_mux.parse_socks_addr(bad), bad)

        # Host UDP protocol security filters (cross-platform, incl. Windows).
        async def proto_checks():
            q = asyncio.Queue(maxsize=2)
            seen_client = []
            proto = bridge._HostUDPProtocol('192.168.1.50', 44444, q, seen_client.append)
            good_body = guest_mux.encode_socks_addr('10.0.0.53', 53) + b'dns-q'

            # Spoofed peer IP rejected
            proto.datagram_received(b'\x00\x00\x00' + good_body, ('192.168.1.99', 44444))
            # Wrong source port rejected when pinned
            proto.datagram_received(b'\x00\x00\x00' + good_body, ('192.168.1.50', 55555))
            # Non-zero FRAG rejected (RFC 1928 §7)
            proto.datagram_received(b'\x00\x00\x01' + good_body, ('192.168.1.50', 44444))
            # Non-zero RSV rejected
            proto.datagram_received(b'\x00\x01\x00' + good_body, ('192.168.1.50', 44444))
            # Zero dst port rejected
            bad_port = guest_mux.encode_socks_addr('10.0.0.53', 0) + b'x'
            proto.datagram_received(b'\x00\x00\x00' + bad_port, ('192.168.1.50', 44444))
            self.assertTrue(q.empty())
            self.assertEqual(seen_client, [])

            # Valid packets queued; drop-on-full never raises when overflowing
            proto.datagram_received(b'\x00\x00\x00' + good_body, ('::ffff:192.168.1.50', 44444))
            proto.datagram_received(b'\x00\x00\x00' + good_body, ('192.168.1.50', 44444))
            proto.datagram_received(b'\x00\x00\x00' + good_body, ('192.168.1.50', 44444))
            self.assertEqual(q.qsize(), 2)
            self.assertEqual(q.get_nowait(), good_body)
            # Transient Winsock / ICMP reset never propagates
            proto.error_received(ConnectionResetError('WSAECONNRESET'))

            # Guest UDP protocol drops unsolicited replies from uncontacted peers
            guest_in = asyncio.Queue(maxsize=4)
            allowed = {('10.0.0.53', 53)}
            gproto = guest_mux._GuestUDPProtocol(
                guest_in, lambda host, port: (guest_mux.normalize_ip(host), port) in allowed,
            )
            gproto.datagram_received(b'unsolicited', ('10.0.0.99', 53))
            gproto.datagram_received(b'wrong-port', ('10.0.0.53', 5353))
            self.assertTrue(guest_in.empty())
            gproto.datagram_received(b'legit-reply', ('10.0.0.53', 53))
            self.assertEqual(guest_in.qsize(), 1)
            encoded = guest_in.get_nowait()
            atyp, rhost, rport, off = guest_mux.parse_socks_addr(encoded)
            self.assertEqual((atyp, rhost, rport, encoded[off:]), (1, '10.0.0.53', 53, b'legit-reply'))

            # StreamState: non-blocking push_data, window replenishment, and overflow -> RST
            st = guest_mux.StreamState(initial_window=8)
            self.assertEqual(await st.acquire_send(5), 5)
            self.assertEqual(await st.acquire_send(10), 3)
            # Send window now 0; add_window wakes waiting acquire_send
            waiter = asyncio.create_task(st.acquire_send(10))
            await asyncio.sleep(0)
            self.assertFalse(waiter.done())
            st.add_window(6)
            self.assertEqual(await waiter, 6)
            # Push data then EOF in FIFO order
            self.assertTrue(st.push_data(b'abc'))
            st.push_eof()
            self.assertEqual(await st.recv(), (guest_mux.DATA, b'abc'))
            self.assertEqual(await st.recv(), (guest_mux.EOF, b''))
            # Overflow > MAX_STREAM_BUFFER returns False and transitions to RST immediately
            st2 = guest_mux.StreamState()
            chunk = b'x' * (1024 * 1024)
            for _ in range(5):
                self.assertTrue(st2.push_data(chunk))
            self.assertFalse(st2.push_data(b'overflow'))
            self.assertEqual(await st2.recv(), (guest_mux.RST, b''))
            self.assertEqual(await st2.acquire_send(10), 0)

        asyncio.run(proto_checks())

    @unittest.skipIf(os.name == 'nt', 'guest/mux.py stdio pipes run inside Linux containers')
    def test_stalled_tcp_client_never_blocks_new_handshakes_tcp_or_udp_and_resumes_cleanly(self):
        async def scenario():
            big_size = 16 * 1024 * 1024  # 16 MiB (4x the 4 MiB per-stream window)
            block = bytes(range(256)) * 256  # 64 KiB deterministic block
            want_sha = hashlib.sha256()
            for _ in range(big_size // len(block)):
                want_sha.update(block)
            want_digest = want_sha.hexdigest()

            async def fake_microsocks(reader, writer):
                try:
                    greet = await reader.readexactly(3)
                    if greet != b'\x05\x01\x00':
                        return
                    writer.write(b'\x05\x00')
                    await writer.drain()
                    cmd = await reader.readexactly(3)
                    if cmd == b'BIG':
                        for _ in range(big_size // len(block)):
                            writer.write(block)
                            await writer.drain()
                    elif cmd == b'SML':
                        writer.write(b'small-ok')
                        await writer.drain()
                except (asyncio.IncompleteReadError, ConnectionError, OSError):
                    pass
                finally:
                    writer.close()
                    with contextlib.suppress(ConnectionError, OSError):
                        await writer.wait_closed()

            backend = await asyncio.start_server(fake_microsocks, '127.0.0.1', 0)
            backend_port = backend.sockets[0].getsockname()[1]

            class EchoUDP(asyncio.DatagramProtocol):
                def connection_made(self, transport):
                    self.transport = transport

                def datagram_received(self, data, addr):
                    self.transport.sendto(b'udp:' + data, addr)

            loop = asyncio.get_running_loop()
            echo_transport, _ = await loop.create_datagram_endpoint(EchoUDP, local_addr=('127.0.0.1', 0))
            echo_port = echo_transport.get_extra_info('sockname')[1]

            class LocalMuxTunnel(bridge.HostMuxTunnel):
                async def _spawn_process(self):
                    return await asyncio.create_subprocess_exec(
                        sys.executable, '-c', resources.guest_script('mux'),
                        '127.0.0.1', str(backend_port),
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

            tunnel = LocalMuxTunnel(engine.AppleContainerEngine(), 'zt-hol', auth=None)
            srv = await asyncio.start_server(tunnel.handle_client, '127.0.0.1', 0)
            port = srv.sockets[0].getsockname()[1]
            try:
                # 1. Client A triggers a 16 MiB download and STOPS reading (TCP zero window).
                ra, wa = await asyncio.open_connection('127.0.0.1', port)
                wa.write(b'\x05\x01\x00')
                await wa.drain()
                self.assertEqual(await ra.readexactly(2), b'\x05\x00')
                wa.write(b'BIG')
                await wa.drain()
                # Give server time to fill stream A's entire 4 MiB credit window and pause.
                await asyncio.sleep(0.5)

                # 2. While A is stalled, Client B MUST complete handshake + TCP transfer fast!
                rb, wb = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), timeout=2.0)
                wb.write(b'\x05\x01\x00')
                await wb.drain()
                self.assertEqual(await asyncio.wait_for(rb.readexactly(2), timeout=2.0), b'\x05\x00')
                wb.write(b'SML')
                await wb.drain()
                self.assertEqual(await asyncio.wait_for(rb.readexactly(8), timeout=2.0), b'small-ok')
                wb.close()
                await wb.wait_closed()

                # 3. Client C MUST also complete UDP ASSOCIATE + roundtrip while A is stalled!
                rc, wc = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', port), timeout=2.0)
                wc.write(b'\x05\x01\x00')
                await wc.drain()
                self.assertEqual(await asyncio.wait_for(rc.readexactly(2), timeout=2.0), b'\x05\x00')
                wc.write(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
                await wc.drain()
                rep = await asyncio.wait_for(rc.readexactly(10), timeout=2.0)
                self.assertEqual(rep[:4], b'\x05\x00\x00\x01')
                bnd_port = (rep[8] << 8) | rep[9]
                us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                us.bind(('127.0.0.1', 0))
                us.setblocking(False)
                try:
                    pkt = b'\x00\x00\x00' + guest_mux.encode_socks_addr('127.0.0.1', echo_port) + b'fast'
                    us.sendto(pkt, ('127.0.0.1', bnd_port))
                    ans = await asyncio.wait_for(loop.sock_recv(us, 4096), timeout=2.0)
                    _, _, _, off = guest_mux.parse_socks_addr(ans, 3)
                    self.assertEqual(ans[off:], b'udp:fast')
                finally:
                    us.close()
                wc.close()
                await wc.wait_closed()

                # 4. Now Client A resumes reading and receives ALL 16 MiB intact via WINDOW_UPDATE!
                got_sha = hashlib.sha256()
                got_len = 0
                while got_len < big_size:
                    chunk = await asyncio.wait_for(ra.read(65536), timeout=5.0)
                    if not chunk:
                        break
                    got_sha.update(chunk)
                    got_len += len(chunk)
                self.assertEqual(got_len, big_size)
                self.assertEqual(got_sha.hexdigest(), want_digest)
                wa.close()
                await wa.wait_closed()
            finally:
                srv.close()
                await srv.wait_closed()
                await tunnel.close()
                echo_transport.close()
                backend.close()
                await backend.wait_closed()
                await asyncio.sleep(0)

        asyncio.run(scenario())

    @unittest.skipIf(os.name == 'nt', 'guest/mux.py stdio pipes run inside Linux containers')
    def test_udp_associate_end_to_end_ipv4_domain_auth_pinning_isolation_and_teardown(self):
        async def scenario():
            async def fake_microsocks(reader, writer):
                try:
                    greet = await reader.readexactly(3)
                    if greet != b'\x05\x01\x00':
                        return
                    writer.write(b'\x05\x00')
                    await writer.drain()
                    while data := await reader.read(4096):
                        writer.write(b'tcp:' + data)
                        await writer.drain()
                except asyncio.IncompleteReadError:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()

            backend = await asyncio.start_server(fake_microsocks, '127.0.0.1', 0)
            backend_port = backend.sockets[0].getsockname()[1]

            # Real IPv4 UDP echo server
            udp_hits = []

            class EchoUDP(asyncio.DatagramProtocol):
                def connection_made(self, transport):
                    self.transport = transport

                def datagram_received(self, data, addr):
                    udp_hits.append(data)
                    self.transport.sendto(b'echo:' + data, addr)

            loop = asyncio.get_running_loop()
            echo_transport, _ = await loop.create_datagram_endpoint(
                EchoUDP, local_addr=('127.0.0.1', 0),
            )
            echo_port = echo_transport.get_extra_info('sockname')[1]

            # Optional IPv6 UDP echo server (if host enables ::1)
            echo6_transport = None
            echo6_port = None
            try:
                echo6_transport, _ = await loop.create_datagram_endpoint(
                    EchoUDP, local_addr=('::1', 0),
                )
                echo6_port = echo6_transport.get_extra_info('sockname')[1]
            except OSError:
                echo6_transport = None

            class LocalMuxTunnel(bridge.HostMuxTunnel):
                def __init__(self, auth=None):
                    super().__init__(engine.AppleContainerEngine(), 'zt-test', auth=auth)
                    self.spawns = 0

                async def _spawn_process(self):
                    self.spawns += 1
                    return await asyncio.create_subprocess_exec(
                        sys.executable, '-c', resources.guest_script('mux'),
                        '127.0.0.1', str(backend_port),
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

            async def open_udp_assoc(port, auth=None, req_host='0.0.0.0', req_port=0):
                cr, cw = await asyncio.open_connection('127.0.0.1', port)
                if auth is None:
                    cw.write(b'\x05\x01\x00')
                    await cw.drain()
                    assert await cr.readexactly(2) == b'\x05\x00'
                else:
                    u, p = auth[0].encode(), auth[1].encode()
                    cw.write(b'\x05\x01\x02')
                    await cw.drain()
                    assert await cr.readexactly(2) == b'\x05\x02'
                    cw.write(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
                    await cw.drain()
                    assert await cr.readexactly(2) == b'\x01\x00'
                # Send UDP ASSOCIATE in split chunks to test partial-read reassembly too.
                cw.write(b'\x05\x03')
                await cw.drain()
                cw.write(b'\x00' + guest_mux.encode_socks_addr(req_host, req_port))
                await cw.drain()
                hdr = await cr.readexactly(4)
                assert hdr[:2] == b'\x05\x00', hdr
                atyp = hdr[3]
                if atyp == 1:
                    raw = await cr.readexactly(6)
                    bnd_ip = socket.inet_ntop(socket.AF_INET, raw[:4])
                    bnd_port = (raw[4] << 8) | raw[5]
                else:
                    raw = await cr.readexactly(18)
                    bnd_ip = socket.inet_ntop(socket.AF_INET6, raw[:16])
                    bnd_port = (raw[16] << 8) | raw[17]
                return cr, cw, bnd_ip, bnd_port

            def make_udp_client(bind_port=0):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('127.0.0.1', bind_port))
                sock.setblocking(False)
                return sock

            async def udp_roundtrip(sock, relay, dst_body, timeout=3.0):
                sock.sendto(b'\x00\x00\x00' + dst_body, relay)
                return await asyncio.wait_for(loop.sock_recv(sock, 4096), timeout=timeout)

            # Bind on 0.0.0.0 (like `accept lan`/`all`) to verify BND.ADDR is never 0.0.0.0!
            tunnel_noauth = LocalMuxTunnel(auth=None)
            srv_noauth = await asyncio.start_server(tunnel_noauth.handle_client, '0.0.0.0', 0)
            noauth_port = srv_noauth.sockets[0].getsockname()[1]

            tunnel_auth = LocalMuxTunnel(auth=('kasm_user', 's3cret'))
            srv_auth = await asyncio.start_server(tunnel_auth.handle_client, '127.0.0.1', 0)
            auth_port = srv_auth.sockets[0].getsockname()[1]

            try:
                # 1. No-auth UDP ASSOCIATE: BND.ADDR must be 127.0.0.1 (never 0.0.0.0)
                cr, cw, bnd_ip, bnd_port = await open_udp_assoc(noauth_port)
                self.assertEqual(bnd_ip, '127.0.0.1')
                self.assertGreater(bnd_port, 0)
                self.assertEqual(len(tunnel_noauth._udp_handlers), 1)

                client_sock = make_udp_client()
                try:
                    # IPv4 target roundtrip
                    body_v4 = guest_mux.encode_socks_addr('127.0.0.1', echo_port) + b'hello-v4'
                    reply = await udp_roundtrip(client_sock, (bnd_ip, bnd_port), body_v4)
                    self.assertEqual(reply[:3], b'\x00\x00\x00')
                    atyp, rhost, rport, off = guest_mux.parse_socks_addr(reply, 3)
                    self.assertEqual((atyp, rhost, rport, reply[off:]), (1, '127.0.0.1', echo_port, b'echo:hello-v4'))

                    # ATYP=0x03 domain ('localhost') resolution inside guest mux
                    dom_body = b'\x03\x09localhost' + struct.pack('!H', echo_port) + b'hello-dns'
                    reply = await udp_roundtrip(client_sock, (bnd_ip, bnd_port), dom_body)
                    _, _, rport, off = guest_mux.parse_socks_addr(reply, 3)
                    self.assertEqual((rport, reply[off:]), (echo_port, b'echo:hello-dns'))

                    # IPv6 target cross-family over IPv4 client relay (if host has ::1)
                    if echo6_port is not None:
                        body_v6 = guest_mux.encode_socks_addr('::1', echo6_port) + b'hello-v6'
                        reply6 = await udp_roundtrip(client_sock, (bnd_ip, bnd_port), body_v6)
                        atyp6, rhost6, rport6, off6 = guest_mux.parse_socks_addr(reply6, 3)
                        self.assertEqual((atyp6, rhost6, rport6, reply6[off6:]), (4, '::1', echo6_port, b'echo:hello-v6'))

                    # FRAG != 0 must be dropped silently
                    before = len(udp_hits)
                    client_sock.sendto(b'\x00\x00\x02' + body_v4, (bnd_ip, bnd_port))
                    await asyncio.sleep(0.15)
                    self.assertEqual(len(udp_hits), before)

                    # Burst of 350 UDP datagrams must NOT stall concurrent TCP streams on the same mux!
                    for idx in range(350):
                        client_sock.sendto(
                            b'\x00\x00\x00' + guest_mux.encode_socks_addr('127.0.0.1', echo_port) + f'b{idx}'.encode(),
                            (bnd_ip, bnd_port),
                        )
                    tr, tw = await asyncio.open_connection('127.0.0.1', noauth_port)
                    tw.write(b'\x05\x01\x00')
                    await tw.drain()
                    self.assertEqual(await tr.readexactly(2), b'\x05\x00')
                    tw.write(b'tcp-under-udp-burst')
                    tw.write_eof()
                    await tw.drain()
                    self.assertEqual(await asyncio.wait_for(tr.read(), timeout=3.0), b'tcp:tcp-under-udp-burst')
                    tw.close()
                    await tw.wait_closed()
                    self.assertEqual(tunnel_noauth.spawns, 1)
                finally:
                    client_sock.close()

                # Closing TCP control tears down host & guest UDP association immediately
                cw.close()
                await cw.wait_closed()
                for _ in range(30):
                    if not tunnel_noauth._udp_handlers:
                        break
                    await asyncio.sleep(0.05)
                self.assertEqual(len(tunnel_noauth._udp_handlers), 0)

                # 2. Explicit source-port pinning + authenticated (`accept all`) UDP ASSOCIATE
                pinned = make_udp_client()
                other = make_udp_client()
                try:
                    pinned_port = pinned.getsockname()[1]
                    ar, aw, abnd_ip, abnd_port = await open_udp_assoc(
                        auth_port, auth=('kasm_user', 's3cret'), req_host='127.0.0.1', req_port=pinned_port,
                    )
                    # Packet from unpinned local port must be dropped
                    before = len(udp_hits)
                    other.sendto(
                        b'\x00\x00\x00' + guest_mux.encode_socks_addr('127.0.0.1', echo_port) + b'wrong-port',
                        (abnd_ip, abnd_port),
                    )
                    await asyncio.sleep(0.15)
                    self.assertEqual(len(udp_hits), before)

                    # Packet from pinned port succeeds
                    body_ok = guest_mux.encode_socks_addr('127.0.0.1', echo_port) + b'authed-udp'
                    reply = await udp_roundtrip(pinned, (abnd_ip, abnd_port), body_ok)
                    _, _, _, off = guest_mux.parse_socks_addr(reply, 3)
                    self.assertEqual(reply[off:], b'echo:authed-udp')

                    # 3. Unsupported ATYP returns REP=0x08
                    ur, uw = await asyncio.open_connection('127.0.0.1', noauth_port)
                    uw.write(b'\x05\x01\x00')
                    await uw.drain()
                    self.assertEqual(await ur.readexactly(2), b'\x05\x00')
                    uw.write(b'\x05\x03\x00\x09\x00\x00')
                    await uw.drain()
                    rep8 = await ur.readexactly(10)
                    self.assertEqual(rep8[:3], b'\x05\x08\x00')
                    uw.close()
                    await uw.wait_closed()

                    # 4. MAX_UDP_ASSOCS cap returns REP=0x01
                    with mock.patch.object(bridge, 'MAX_UDP_ASSOCS', 1):
                        lr, lw = await asyncio.open_connection('127.0.0.1', auth_port)
                        lw.write(b'\x05\x01\x02')
                        await lw.drain()
                        self.assertEqual(await lr.readexactly(2), b'\x05\x02')
                        lw.write(b'\x01\x09kasm_user\x06s3cret')
                        await lw.drain()
                        self.assertEqual(await lr.readexactly(2), b'\x01\x00')
                        lw.write(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
                        await lw.drain()
                        rep1 = await lr.readexactly(10)
                        self.assertEqual(rep1[:3], b'\x05\x01\x00')
                        lw.close()
                        await lw.wait_closed()

                    # 5. Closing mux tunnel immediately wakes up & closes active UDP control TCP
                    #    and MUST NOT re-spawn a new mux process during UDP_CLOSE teardown!
                    spawns_before = tunnel_auth.spawns
                    await tunnel_auth.close()
                    self.assertEqual(await asyncio.wait_for(ar.read(), timeout=3.0), b'')
                    aw.close()
                    await aw.wait_closed()
                    self.assertEqual(tunnel_auth.spawns, spawns_before)
                finally:
                    pinned.close()
                    other.close()
            finally:
                srv_noauth.close()
                await srv_noauth.wait_closed()
                srv_auth.close()
                await srv_auth.wait_closed()
                await tunnel_noauth.close()
                await tunnel_auth.close()
                echo_transport.close()
                if echo6_transport is not None:
                    echo6_transport.close()
                backend.close()
                await backend.wait_closed()
                await asyncio.sleep(0)

        asyncio.run(scenario())

    def test_detached_popen_kwargs_adapts_for_windows(self):
        with mock.patch.object(bridge.os, 'name', 'nt'):
            kwargs = bridge._detached_popen_kwargs()
            self.assertIn('creationflags', kwargs)
            self.assertNotIn('start_new_session', kwargs)
            detached = getattr(subprocess, 'DETACHED_PROCESS', 0)
            if detached:
                self.assertFalse(kwargs['creationflags'] & detached)
        with mock.patch.object(bridge.os, 'name', 'posix'):
            self.assertEqual(bridge._detached_popen_kwargs(), {'start_new_session': True})

    def test_cross_engine_bridge_is_detected_and_never_reused(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_STATE': tmp, 'ZT_ACCEPT': 'local'}):
            bridge._write_pidfile('atrust', 4242, 'container', 'local', '')
            with mock.patch.object(bridge, '_pid_is_bridge', return_value=True):
                self.assertEqual(bridge.bridge_pid('atrust', engine_cli='container'), 4242)
                self.assertIsNone(bridge.bridge_pid('atrust', engine_cli='docker'))
                problem = bridge.bridge_start(engine.DockerEngine(), 'atrust', mode='local')
                self.assertIn('Apple Container (pid 4242)', problem)
                self.assertIn('not Docker', problem)

    def test_legacy_v1_bridge_pidfile_triggers_seamless_restart(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_STATE': tmp, 'ZT_ACCEPT': 'local'}):
            # Simulate a running v1.0.0 bridge pidfile (no `proto` field).
            bridge.bridge_pidfile('atrust').write_text(
                json.dumps({
                    'pid': 4242, 'engine': 'container', 'profile': 'atrust',
                    'accept': 'local', 'auth_hash': '',
                }) + '\n',
                encoding='utf-8',
            )
            with mock.patch.object(bridge, '_pid_is_bridge', return_value=True):
                rec = bridge.bridge_record('atrust')
                self.assertEqual(rec, (4242, 'container', 'local', '', 1))
                self.assertNotEqual(rec[4], bridge.BRIDGE_PROTO)

            # `bridge_start` must stop the stale v1 bridge instead of reusing it.
            eng = engine.AppleContainerEngine()
            with mock.patch.object(bridge, '_pid_is_bridge', return_value=True), \
                    mock.patch.object(bridge, 'bridge_stop') as bstop, \
                    mock.patch.object(bridge, 'socks_any_listener', return_value=True), \
                    mock.patch.object(eng, 'port_holders', return_value='test'):
                bridge.bridge_start(eng, 'atrust', mode='local')
                bstop.assert_called_once_with('atrust', engine_cli='container')

    def test_run_bridge_cleans_pidfile_safely_even_if_removed_externally(self):
        def fake_asyncio_run(coro):
            coro.close()
            bridge.bridge_pidfile('atrust').unlink(missing_ok=True)

        eng = mock.Mock(cli='container', display_name='Apple Container')
        eng.container_state.return_value = 'running'
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_STATE': tmp, 'ZT_ACCEPT': 'local'}), \
                mock.patch.object(bridge, 'bridge_record', return_value=(None, None, None, None, None)), \
                mock.patch.object(bridge.asyncio, 'run', side_effect=fake_asyncio_run):
            bridge.run_bridge(eng, 'atrust')
            self.assertEqual(os.listdir(tmp), [])


class Engines(unittest.TestCase):
    REFUSED = 'Error: unknown: "POSIXErrorCode(rawValue: 61): Connection refused"'

    @staticmethod
    def answer(stdout='', code=0, stderr=''):
        return subprocess.CompletedProcess(['engine'], code, stdout, stderr)

    def test_passed_through_streams_stderr_portably_without_select(self):
        proc = engine.passed_through(
            sys.executable, ['-c', 'import sys; sys.stderr.write("hello-stderr\\n")'], timeout=10,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn('hello-stderr', proc.stderr)

    def test_retry_only_on_engine_refusal_and_error_uses_engine_cli_name(self):
        eng = engine.DockerEngine()
        with mock.patch.object(engine.subprocess, 'run', return_value=self.answer('', 1, self.REFUSED)), \
                mock.patch.object(engine.time, 'sleep'), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            eng.run_cli('ps', quiet=True)
        self.assertIn('zt: "docker ps" failed:', err.getvalue())

    def test_docker_net_mode_switches_to_subnet_for_accept_all_and_rootless_podman(self):
        # Hostname containing 'podman' must NOT false-positive as Podman on regular Docker!
        docker = engine.DockerEngine()
        docker_info = json.dumps({
            'Name': 'podman-workstation',
            'ServerVersion': '27.0.3',
            'SecurityOptions': ['name=seccomp'],
        })
        with mock.patch.object(docker, 'run_cli', return_value=self.answer(docker_info)):
            self.assertFalse(docker.is_podman)
            self.assertIsInstance(docker._daemon_traits, engine.DaemonTraits)
            self.assertEqual(docker.net_mode_for('local'), 'gateway')
            self.assertEqual(docker.net_mode_for('lan'), 'gateway')
            self.assertEqual(docker.net_mode_for('all'), 'subnet')

        podman_rl = engine.DockerEngine()
        rl_info = json.dumps({
            'Host': {'BuildahVersion': '1.35.0', 'Security': {'Rootless': True}},
            'SecurityOptions': ['name=rootless'],
        })
        with mock.patch.object(podman_rl, 'run_cli', return_value=self.answer(rl_info)):
            flags = podman_rl.container_flags('all')
            self.assertTrue(podman_rl.is_rootless_podman)
            self.assertEqual(podman_rl.net_mode_for('local'), 'subnet')
            self.assertIn('--privileged', flags)
            self.assertNotIn('--cap-add', flags)

    def test_docker_defaults_to_hardened_least_caps_and_conditional_selinux(self):
        env_clean = {k: v for k, v in os.environ.items() if k != 'ZT_CAPS'}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {**env_clean, 'ZT_CONFIG': str(Path(tmp) / 'config')}, clear=True):
            # Non-SELinux Docker (Ubuntu AppArmor / Docker Desktop)
            docker = engine.DockerEngine()
            docker_info = json.dumps({'SecurityOptions': ['name=apparmor', 'name=seccomp,profile=builtin']})
            with mock.patch.object(docker, 'run_cli', return_value=self.answer(docker_info)):
                self.assertEqual(docker.resolved_caps(), 'least')
                flags = docker.container_flags()
            self.assertIn('--cap-drop', flags)
            self.assertEqual(flags[flags.index('--cap-drop') + 1], 'ALL')
            for cap in spec.DOCKER_LEAST_CAPS:
                self.assertIn(cap, flags)
            for forbidden in ('SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE', 'SYS_BOOT', 'SYS_TIME',
                              'DAC_READ_SEARCH', 'BPF', 'PERFMON', 'MAC_ADMIN', 'SYSLOG', 'MKNOD', 'SETFCAP'):
                self.assertNotIn(forbidden, flags)
            self.assertIn('--device', flags)
            self.assertIn('/dev/net/tun:/dev/net/tun:rw', flags)
            self.assertNotIn('/dev/net/tun', flags)
            self.assertIn('--pids-limit', flags)
            self.assertIn('1024', flags)
            self.assertIn('/run:rw,nosuid,nodev,size=64m', flags)
            self.assertIn('/run/lock:rw,noexec,nosuid,nodev,size=16m', flags)
            self.assertNotIn('label=disable', flags)

            # SELinux Docker adds label=disable only when SELinux is active
            selinux_docker = engine.DockerEngine()
            se_info = json.dumps({'SecurityOptions': ['name=selinux', 'name=seccomp']})
            with mock.patch.object(selinux_docker, 'run_cli', return_value=self.answer(se_info)):
                se_flags = selinux_docker.container_flags()
                self.assertTrue(selinux_docker.has_selinux)
            self.assertIn('--security-opt', se_flags)
            self.assertIn('label=disable', se_flags)

            # Explicit CAPS=all still works as opt-in escape hatch without --cap-drop
            all_flags = docker.container_flags('all')
            self.assertNotIn('--cap-drop', all_flags)
            self.assertIn('--cap-add', all_flags)
            self.assertIn('ALL', all_flags)

            # Linux Docker Desktop (VM) is not mislabeled as shared-kernel rootful
            dd_docker = engine.DockerEngine()
            dd_info = json.dumps({'OperatingSystem': 'Docker Desktop', 'SecurityOptions': ['name=seccomp']})
            with mock.patch.object(dd_docker, 'run_cli', return_value=self.answer(dd_info)), \
                    mock.patch.object(engine.sys, 'platform', 'linux'):
                self.assertTrue(dd_docker.is_desktop_vm)
                self.assertFalse(dd_docker.is_linux_rootful)

            # Apple Container keeps microVM default CAPS=all and supports CAPS=least
            apple = engine.AppleContainerEngine()
            self.assertEqual(apple.resolved_caps(), 'all')
            self.assertIn('ALL', apple.container_flags())
            self.assertNotIn('--cap-drop', apple.container_flags('least'))
            self.assertIn('NET_ADMIN', apple.container_flags('least'))
            self.assertIn('SYS_ADMIN', apple.container_flags('least'))

    def test_run_container_binds_host_volume_arch_and_keeps_vnc_pw_out_of_argv(self):
        eng = engine.DockerEngine()
        eng.__dict__['_daemon_traits'] = engine.DaemonTraits()
        captured = {}

        def fake_cli(*args, quiet=False, check=True, timeout=None, env=None):
            captured['args'] = args
            captured['env'] = env
            return self.answer()

        with mock.patch.object(eng, 'run_cli', side_effect=fake_cli), \
                mock.patch.dict(os.environ, {'ZT_CAPS': 'least'}):
            eng.run_container(
                'zt-atrust', 'localhost/zt-atrust:1',
                {'VNC_PW': 's3cret', 'ZT_AUTH': '1'}, 16911, {'zt.profile': 'atrust'},
                bind_host='0.0.0.0', arch='amd64', volume='zt-state-atrust',
            )
        self.assertIn('linux/amd64', captured['args'])
        self.assertIn('--hostname', captured['args'])
        self.assertIn('zt-state-atrust:/var/lib/zt-state', captured['args'])
        self.assertIn('0.0.0.0:16911:6901', captured['args'])
        self.assertNotIn('VNC_PW=s3cret', captured['args'])
        self.assertIn('VNC_PW', captured['args'])
        self.assertEqual(captured['env']['VNC_PW'], 's3cret')

    def test_ensure_volume_creates_labeled_volume_when_missing(self):
        apple = engine.AppleContainerEngine()
        calls = []

        def fake_cli(*args, quiet=False, check=True, timeout=None, env=None):
            calls.append(args)
            if args[:2] == ('volume', 'inspect'):
                return self.answer('', 1)
            return self.answer('', 0)

        with mock.patch.object(apple, 'run_cli', side_effect=fake_cli):
            self.assertTrue(apple.ensure_volume('zt-state-atrust', 'atrust'))
        self.assertIn(
            ('volume', 'create', '--label', 'org.zt.managed=true',
             '--label', 'org.zt.profile=atrust', '-s', '2G', 'zt-state-atrust'),
            calls,
        )

    def test_managed_images_filters_by_profile_across_legacy_and_multiarch_tags(self):
        eng = engine.AppleContainerEngine()
        listing = json.dumps([
            {'configuration': {'name': 'localhost/zt-atrust:2.5.16.20-amd64-0123456789ab'}, 'variants': []},
            {'configuration': {'name': 'localhost/zt-atrust:2.5.16.20-fedcba987654'}, 'variants': []},
            {
                'configuration': {'name': 'localhost/zt-base:1.5.2-systemd-arm64-abcdef012345'},
                'variants': [{'config': {'config': {'Labels': {'org.zt.managed': 'true', 'org.zt.profile': 'base'}}}}],
            },
            {'configuration': {'name': 'docker.io/library/ubuntu:24.04'}, 'variants': []},
        ])
        with mock.patch.object(eng, 'run_cli', return_value=self.answer(listing)):
            self.assertEqual(len(eng.managed_images('atrust')), 2)
            self.assertEqual(eng.managed_images('base'), ['localhost/zt-base:1.5.2-systemd-arm64-abcdef012345'])
            self.assertEqual(len(eng.managed_images()), 3)

    def test_host_listener_supports_ss_and_windows_netstat(self):
        ss_out = subprocess.CompletedProcess(
            [], 0, 'LISTEN 0 128 127.0.0.1:16912 0.0.0.0:* users:(("python3",pid=999,fd=5))\n'
        )
        with mock.patch.object(engine.os, 'name', 'posix'), \
                mock.patch.object(engine.shutil, 'which', side_effect=lambda c: '/usr/bin/ss' if c == 'ss' else None), \
                mock.patch.object(engine.os.path, 'exists', return_value=False), \
                mock.patch.object(engine.subprocess, 'run', return_value=ss_out):
            self.assertEqual(engine._host_listener(16912), 'held by python3 (pid 999)')

        netstat_sample = (
            '  Proto  Local Address          Foreign Address        State           PID\n'
            '  TCP    127.0.0.1:16912        0.0.0.0:0              LISTENING       4321\n'
        )
        self.assertEqual(engine._parse_windows_netstat(netstat_sample, 16912), '4321')
        self.assertIsNone(engine._parse_windows_netstat(netstat_sample, 16911))


class EncapsulatedCLI(unittest.TestCase):
    def test_public_cli_exposes_only_the_seven_commands(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as ex:
            cli.main(['--help'])
        self.assertEqual(ex.exception.code, 0)
        help_text = out.getvalue()
        for expected in ('up', 'down', 'status', 'doctor', 'purge', 'accept', 'password'):
            self.assertRegex(help_text, rf'\b{expected}\b')
        for hidden in ('build', 'verify', 'prune', 'socks', 'logs', 'exec', 'shot', 'init', 'use', 'bridge'):
            self.assertNotRegex(help_text, rf'^\s+{hidden}\b', f'{hidden} must not be exposed')

    def test_password_command_saves_silently_and_accept_all_enforces_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'config'
            base_env = {k: v for k, v in os.environ.items() if not k.startswith('ZT_')}
            base_env['ZT_CONFIG'] = str(cfg)
            with mock.patch.dict(os.environ, base_env, clear=True):
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['accept', 'lan'])
                self.assertEqual(config.accept_mode(), 'lan')
                self.assertIn('LAN only', out.getvalue())

                with mock.patch.object(cli.sys.stdin, 'isatty', return_value=False), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    cli.main(['accept', 'all'])
                self.assertIn('zt password', err.getvalue())

                with mock.patch.object(cli.getpass, 'getpass', side_effect=['s3cret', 's3cret']), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['password'])
                self.assertNotIn('s3cret', out.getvalue())
                self.assertEqual(config.setting('VNC_PW'), 's3cret')
                if os.name != 'nt':
                    self.assertEqual(cfg.stat().st_mode & 0o777, 0o600)

                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['accept', 'all'])
                self.assertEqual(config.accept_mode(), 'all')
                self.assertIn('0.0.0.0', out.getvalue())

                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['accept', 'local'])
                self.assertEqual(config.accept_mode(), 'local')
                self.assertIn('127.0.0.1', out.getvalue())

    def test_ensure_image_promotes_only_after_verify_and_stays_fail_closed_on_retry(self):
        ref = build.current_ref('atrust', 'arm64')
        staging = f'{ref}-unverified'
        tags = set()
        cli_calls = []

        eng = mock.Mock(cli='container', display_name='Apple Container')
        eng.image_exists.side_effect = lambda name: name in tags

        def fake_run_cli(*args, **kwargs):
            cli_calls.append(args)
            if args[:2] == ('image', 'tag'):
                tags.add(args[3])
            elif args[:2] == ('image', 'rm'):
                tags.discard(args[2])
            return mock.Mock(returncode=0)

        eng.run_cli.side_effect = fake_run_cli

        def fake_build(_eng, _profile, force=False, arch=None, tag=None):
            tags.add(tag or ref)
            return tag or ref

        # 1. Failed verify MUST NOT promote `ref` and MUST remove `staging`,
        #    so a retry still sees `ref` absent and cannot bypass verification!
        with mock.patch.object(cli, 'build', side_effect=fake_build) as mbuild, \
                mock.patch.object(cli, 'verify', return_value=['tunnel: failed']) as mverify, \
                contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit):
            cli.ensure_image(eng, 'atrust', 'local', 'arm64')
        self.assertNotIn(ref, tags)
        self.assertNotIn(staging, tags)
        mbuild.assert_called_once_with(eng, 'atrust', force=True, arch='arm64', tag=staging)
        mverify.assert_called_once_with(eng, 'atrust', mode='local', arch='arm64', ref=staging)
        self.assertFalse(any(c[:2] == ('image', 'tag') for c in cli_calls))

        # 2. Retry runs verify again; only on pass does it promote `staging` -> `ref` and clean up `staging`.
        with mock.patch.object(cli, 'build', side_effect=fake_build), \
                mock.patch.object(cli, 'verify', return_value=[]) as mverify:
            got = cli.ensure_image(eng, 'atrust', 'local', 'arm64')
        self.assertEqual(got, ref)
        mverify.assert_called_once_with(eng, 'atrust', mode='local', arch='arm64', ref=staging)
        self.assertIn(ref, tags)
        self.assertNotIn(staging, tags)
        self.assertIn(('image', 'tag', staging, ref), cli_calls)

    def test_ensure_container_attaches_persistent_volume_and_binds_loopback_in_lan_mode(self):
        eng = mock.Mock(cli='container', display_name='Apple Container')
        eng.inspect.return_value = None
        eng.port_holders.return_value = None
        eng.container_state.return_value = 'running'
        eng.fingerprint.return_value = 'abc123'
        with contextlib.redirect_stdout(io.StringIO()):
            problem = cli.ensure_container(eng, 'atrust', {'ZT_AUTH': '0'}, mode='lan', arch='amd64')
        self.assertIsNone(problem)
        eng.ensure_volume.assert_called_once_with('zt-state-atrust', 'atrust')
        eng.run_container.assert_called_once()
        args = eng.run_container.call_args
        self.assertEqual(args.args[3], spec.desktop_backend_port('atrust'))
        self.assertEqual(args.kwargs['bind_host'], '127.0.0.1')
        self.assertEqual(args.kwargs['arch'], 'amd64')
        self.assertEqual(args.kwargs['volume'], 'zt-state-atrust')

    def test_doctor_does_not_require_password_in_local_or_lan_mode_but_enforces_in_all_mode(self):
        eng = mock.Mock(cli='container', display_name='Apple Container')
        eng.is_installed.return_value = False
        with tempfile.TemporaryDirectory() as tmp:
            cfg = str(Path(tmp) / 'config')
            for mode in ('local', 'lan'):
                with mock.patch.object(cli, 'make_engine', return_value=eng), \
                        mock.patch.dict(os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': mode, 'ZT_VNC_PW': ''}), \
                        contextlib.redirect_stdout(io.StringIO()) as out, \
                        self.assertRaises(SystemExit):
                    cli.cmd_doctor(argparse.Namespace())
                self.assertIn(f'OK   password              not required (accept {mode})', out.getvalue())
                self.assertIn('OK   target platform', out.getvalue())

            with mock.patch.object(cli, 'make_engine', return_value=eng), \
                    mock.patch.dict(os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'all', 'ZT_VNC_PW': 'too-long-12345'}), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit):
                cli.cmd_doctor(argparse.Namespace())
            self.assertIn('FAIL password              must be 6 to 8 characters (got 14)', out.getvalue())

    def test_linux_rootful_docker_warns_on_caps_all_and_reports_capabilities_in_doctor(self):
        docker = engine.DockerEngine()
        docker.__dict__['_daemon_traits'] = engine.DaemonTraits()
        with tempfile.TemporaryDirectory() as tmp:
            cfg = str(Path(tmp) / 'config')
            env_base = {k: v for k, v in os.environ.items() if not k.startswith('ZT_')}
            env_base.update({'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'local', 'ZT_CAPS': 'all'})
            with mock.patch.dict(os.environ, env_base, clear=True), \
                    mock.patch.object(engine.sys, 'platform', 'linux'), \
                    mock.patch.object(cli, 'make_engine', return_value=docker), \
                    mock.patch.object(docker, 'require'), \
                    mock.patch.object(cli, 'ensure_image'), \
                    mock.patch.object(cli, 'ensure_container', return_value=None), \
                    mock.patch.object(cli, 'bridge_start', return_value=None), \
                    mock.patch.object(cli, 'cmd_status'), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()) as err:
                cli.cmd_up(argparse.Namespace(target='atrust'))
            self.assertIn('CAPS=all grants full capabilities on a shared Linux kernel', err.getvalue())

            env_base.pop('ZT_CAPS')
            with mock.patch.dict(os.environ, env_base, clear=True), \
                    mock.patch.object(engine.sys, 'platform', 'linux'), \
                    mock.patch.object(cli, 'make_engine', return_value=docker), \
                    mock.patch.object(docker, 'is_installed', return_value=True), \
                    mock.patch.object(docker, 'is_running', return_value=True), \
                    mock.patch.object(docker, 'image_exists', return_value=True), \
                    mock.patch.object(docker, 'container_state', return_value=None), \
                    mock.patch.object(cli, 'bridge_record', return_value=(None, None, None, None, None)), \
                    mock.patch.object(cli, 'socks_any_listener', return_value=False), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit):
                cli.cmd_doctor(argparse.Namespace())
            self.assertIn('OK   capabilities          least (shared Linux kernel', out.getvalue())

            # Invalid CAPS reports FAIL cleanly in doctor instead of aborting mid-output
            env_bad = {**env_base, 'ZT_CAPS': 'bogus'}
            with mock.patch.dict(os.environ, env_bad, clear=True), \
                    mock.patch.object(cli, 'make_engine', return_value=docker), \
                    mock.patch.object(docker, 'is_installed', return_value=True), \
                    mock.patch.object(docker, 'is_running', return_value=True), \
                    mock.patch.object(docker, 'image_exists', return_value=True), \
                    mock.patch.object(docker, 'container_state', return_value=None), \
                    mock.patch.object(cli, 'bridge_record', return_value=(None, None, None, None, None)), \
                    mock.patch.object(cli, 'socks_any_listener', return_value=False), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit) as ex:
                cli.cmd_doctor(argparse.Namespace())
            self.assertEqual(ex.exception.code, 1)
            self.assertIn("FAIL capabilities          CAPS is 'bogus'", out.getvalue())

    def test_purge_removes_containers_volumes_images_and_cache(self):
        eng = mock.Mock(cli='container', display_name='Apple Container')
        eng.inspect.return_value = {'status': {'state': 'running'}}
        eng.remove_volume.return_value = True
        eng.managed_images.side_effect = lambda p=None: (
            [f'localhost/zt-{p}:1.0-arm64-abc'] if p else []
        )
        eng.run_cli.return_value = mock.Mock(returncode=0)

        atrust_sha = spec.blobs_for(spec.CLIENTS['atrust'], 'arm64')[0][2]
        base_sha = spec.blobs_for(spec.BASE, 'arm64')[0][2]

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_CACHE': tmp}), \
                mock.patch.object(cli, 'make_engine', return_value=eng), \
                mock.patch.object(cli, 'bridge_stop') as bstop:
            cache = Path(tmp)
            (cache / 'build' / 'atrust-arm64-1234').mkdir(parents=True)
            (cache / 'build' / 'base-arm64-9999').mkdir(parents=True)
            (cache / 'blobs').mkdir(parents=True)
            (cache / 'blobs' / atrust_sha).write_bytes(b'atrust-deb')
            (cache / 'blobs' / base_sha).write_bytes(b'kasm-deb')

            with contextlib.redirect_stdout(io.StringIO()) as out:
                cli.main(['purge', 'atrust'])
            bstop.assert_called_once_with('atrust', engine_cli='container')
            eng.run_cli.assert_any_call('rm', '-f', 'zt-atrust', quiet=True)
            eng.remove_volume.assert_any_call('zt-state-atrust')
            eng.run_cli.assert_any_call('image', 'rm', 'localhost/zt-atrust:1.0-arm64-abc', quiet=True, check=False)
            self.assertFalse((cache / 'build' / 'atrust-arm64-1234').exists())
            self.assertFalse((cache / 'blobs' / atrust_sha).exists())
            self.assertTrue((cache / 'build' / 'base-arm64-9999').exists())
            self.assertTrue((cache / 'blobs' / base_sha).exists())
            self.assertIn('state volume removed', out.getvalue())
            self.assertIn('cached blob removed', out.getvalue())

            with contextlib.redirect_stdout(io.StringIO()) as out:
                cli.main(['purge', 'all'])
            eng.run_cli.assert_any_call('image', 'rm', 'localhost/zt-base:1.0-arm64-abc', quiet=True, check=False)
            self.assertFalse(cache.exists())
            self.assertIn('cache removed', out.getvalue())

    def test_run_main_timeout_quotes_actual_command_name(self):
        with mock.patch.object(cli, 'main', side_effect=subprocess.TimeoutExpired(
            ['docker', 'build', '-f', 'x'], 60
        )), self.assertRaises(SystemExit) as stopped:
            cli.run_main()
        self.assertEqual(str(stopped.exception), 'zt: "docker build" did not finish in 60 seconds')


class FromAnotherContainer(unittest.TestCase):
    NETWORKS = {
        'status': {
            'networks': [{
                'ipv4Address': '192.168.64.5/24',
                'ipv6Address': 'fda0:b0d:9d48:31ac::8a67/64',
            }]
        }
    }
    STOPPED = json.dumps({
        'desktop over IPv4': 'stopped',
        'stand-in over IPv4': 'stopped',
        'stand-in UDP over IPv4': 'stopped',
        'stand-in over IPv6': 'stopped',
        'stand-in UDP over IPv6': 'stopped',
    }).encode()
    THROUGH = json.dumps({
        'desktop over IPv4': 'through',
        'stand-in over IPv4': 'through',
        'stand-in UDP over IPv4': 'through',
        'stand-in over IPv6': 'through',
        'stand-in UDP over IPv6': 'through',
    }).encode()

    def test_two_round_control_uses_platform_and_restores_rule(self):
        eng = engine.AppleContainerEngine()
        cmds = []
        probe_round = 0

        def fake_exec(name, user, command, stdin=None, timeout=120):
            nonlocal probe_round
            cmds.append((name, command))
            if 'probe' in command:
                ans = (self.STOPPED, self.THROUGH)[probe_round]
                probe_round += 1
                return mock.Mock(returncode=0, stdout=ans)
            return mock.Mock(returncode=0, stdout=b'')

        with mock.patch.object(eng, 'inspect', return_value=self.NETWORKS), \
                mock.patch.object(eng, 'run_cli', return_value=mock.Mock(returncode=0)) as rcli, \
                mock.patch.object(eng, 'exec_capture', side_effect=fake_exec):
            problem, measured = verify.host_only_holds(eng, 'zt-verify-atrust', arch='amd64')

        self.assertIsNone(problem)
        self.assertIn('each through with the rule out', measured)
        run_call = [c.args for c in rcli.call_args_list if c.args[0] == 'run'][0]
        self.assertIn('linux/amd64', run_call)
        self.assertEqual(cmds[0][1][-2:], ['setup-ipv6', 'fda0:b0d:9d48:31ac::beef/64'])
        self.assertEqual(cmds[2][1][-3:], ['toggle', 'out', 'gateway'])
        self.assertEqual(cmds[4][1][-3:], ['toggle', 'in', 'gateway'])

    def test_peer_ipv6_respects_prefix_length_and_avoids_collision(self):
        cidr = verify._derive_peer_ipv6('fda0:b0d:9d48:31ac::beef/80')
        self.assertTrue(cidr.endswith('/80'))
        self.assertNotEqual(cidr, 'fda0:b0d:9d48:31ac::beef/80')
        self.assertEqual(
            ipaddress.ip_network(cidr, strict=False),
            ipaddress.ip_network('fda0:b0d:9d48:31ac::beef/80', strict=False),
        )


class Installers(unittest.TestCase):
    def test_installer_scripts_target_zt_repo_and_stable_releases(self):
        for fname in ('install.sh', 'install.ps1'):
            text = (ROOT / fname).read_text(encoding='utf-8')
            self.assertIn('ArakawaHenri/zt', text, fname)
            self.assertIn('/releases/latest', text, fname)
            self.assertIn('SHA256SUMS', text, fname)
            self.assertNotIn('zt-images', text, fname)

    @unittest.skipUnless((ROOT / 'zt').exists(), 'run make first')
    def test_installer_end_to_end_verifies_sha256_and_rejects_tampering(self):
        payload = (ROOT / 'zt').read_bytes()
        good_sha = hashlib.sha256(payload).hexdigest()
        state = {'tamper': False}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                base = f'http://127.0.0.1:{self.server.server_port}'
                if self.path == '/repos/ArakawaHenri/zt/releases/latest':
                    body = json.dumps({
                        'tag_name': f'v{VERSION}',
                        'draft': False,
                        'prerelease': False,
                        'assets': [
                            {'name': 'zt', 'browser_download_url': f'{base}/dl/zt'},
                            {'name': 'zt.pyz', 'browser_download_url': f'{base}/dl/zt.pyz'},
                            {'name': 'SHA256SUMS', 'browser_download_url': f'{base}/dl/SHA256SUMS'},
                        ],
                    }).encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path in ('/dl/zt', '/dl/zt.pyz'):
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif self.path == '/dl/SHA256SUMS':
                    digest = ('0' * 64) if state['tamper'] else good_sha
                    body = f'{digest}  zt\n{digest}  zt.pyz\n'.encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        base_url = f'http://127.0.0.1:{srv.server_port}'
        try:
            with tempfile.TemporaryDirectory() as tmp:
                env = dict(os.environ)
                env.update({
                    'ZT_API_BASE': base_url,
                    'ZT_DOWNLOAD_BASE': base_url,
                    'ZT_INSTALL_DIR': tmp,
                    'ZT_NO_MODIFY_PATH': '1',
                })
                env.pop('ZT_VERSION', None)

                if os.name == 'nt':
                    cmd = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(ROOT / 'install.ps1')]
                    run = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False, timeout=60)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertTrue((Path(tmp) / 'zt.pyz').is_file())
                    self.assertTrue((Path(tmp) / 'zt.cmd').is_file())
                    ver = subprocess.run(
                        ['cmd.exe', '/c', str(Path(tmp) / 'zt.cmd'), '--version'],
                        capture_output=True, text=True, check=True, timeout=30,
                    )
                    self.assertEqual(ver.stdout.strip(), f'zt {VERSION}')
                    bad_arg = subprocess.run(
                        ['cmd.exe', '/c', str(Path(tmp) / 'zt.cmd'), '--no-such-flag'],
                        capture_output=True, text=True, check=False, timeout=30,
                    )
                    self.assertNotEqual(bad_arg.returncode, 0)

                    state['tamper'] = True
                    bad_dir = Path(tmp) / 'bad'
                    env['ZT_INSTALL_DIR'] = str(bad_dir)
                    bad = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False, timeout=60)
                    self.assertNotEqual(bad.returncode, 0)
                    self.assertFalse((bad_dir / 'zt.pyz').exists())
                else:
                    cmd = ['sh', str(ROOT / 'install.sh')]
                    run = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False, timeout=60)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    installed = Path(tmp) / 'zt'
                    self.assertTrue(installed.is_file())
                    self.assertTrue(installed.stat().st_mode & 0o111)
                    ver = subprocess.run([str(installed), '--version'], capture_output=True, text=True, check=True)
                    self.assertEqual(ver.stdout.strip(), f'zt {VERSION}')

                    state['tamper'] = True
                    bad_dir = Path(tmp) / 'bad'
                    env['ZT_INSTALL_DIR'] = str(bad_dir)
                    bad = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False, timeout=60)
                    self.assertNotEqual(bad.returncode, 0)
                    self.assertIn('SHA256 mismatch', bad.stderr)
                    self.assertFalse((bad_dir / 'zt').exists())
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == '__main__':
    unittest.main()
