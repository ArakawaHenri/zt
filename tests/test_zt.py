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
            for rejected in ('', '12345', '123456789', '#abcde'):
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


class OverlayAndBuildDAG(unittest.TestCase):
    def test_scripts_executable_and_units_not(self):
        files = resources.overlay_files()
        for script in EXECUTABLE:
            self.assertTrue(files[script][1] & 0o111, script)
        for unit in UNITS:
            self.assertFalse(files[unit][1] & 0o111, unit)

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

    def test_run_bridge_cleans_pidfile_safely_even_if_removed_externally(self):
        def fake_asyncio_run(coro):
            coro.close()
            bridge.bridge_pidfile('atrust').unlink(missing_ok=True)

        eng = mock.Mock(cli='container', display_name='Apple Container')
        eng.container_state.return_value = 'running'
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_STATE': tmp, 'ZT_ACCEPT': 'local'}), \
                mock.patch.object(bridge, 'bridge_record', return_value=(None, None, None, None)), \
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
        docker = engine.DockerEngine()
        docker_info = json.dumps({'SecurityOptions': ['name=seccomp']})
        with mock.patch.object(docker, 'run_cli', return_value=self.answer(docker_info)):
            self.assertEqual(docker.net_mode_for('local'), 'gateway')
            self.assertEqual(docker.net_mode_for('lan'), 'gateway')
            self.assertEqual(docker.net_mode_for('all'), 'subnet')

        podman_rl = engine.DockerEngine()
        rl_info = json.dumps({'SecurityOptions': ['name=rootless'], 'Name': 'podman'})
        with mock.patch.object(podman_rl, 'run_cli', return_value=self.answer(rl_info)):
            flags = podman_rl.container_flags('all')
            self.assertTrue(podman_rl.is_rootless_podman)
            self.assertEqual(podman_rl.net_mode_for('local'), 'subnet')
            self.assertIn('--privileged', flags)
            self.assertNotIn('--cap-add', flags)

    def test_run_container_binds_host_volume_arch_and_keeps_vnc_pw_out_of_argv(self):
        eng = engine.DockerEngine()
        eng.__dict__['_daemon_traits'] = (False, False)
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
        'stand-in over IPv6': 'stopped',
    }).encode()
    THROUGH = json.dumps({
        'desktop over IPv4': 'through',
        'stand-in over IPv4': 'through',
        'stand-in over IPv6': 'through',
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
