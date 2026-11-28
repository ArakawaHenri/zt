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

from zt import VERSION, bridge, build, cli, config, engine, resources, spec, update, verify  # noqa: E402
from zt.guest import mux as guest_mux  # noqa: E402

if os.name != 'nt':
    from zt.guest import check as guest_check  # noqa: E402
else:
    guest_check = None

EXECUTABLE = tuple(sorted(spec.EXECUTABLE_OVERLAYS))
UNITS = (
    'base/rootfs/etc/systemd/system/kasmvnc.service',
    'common/rootfs/etc/systemd/system/zt-net.service',
    'sangfor/common/rootfs/etc/systemd/system/zt-sangfor-daemon.service',
    'sangfor/common/rootfs/etc/systemd/system/zt-sangfor-ui.service',
    'sangfor/atrust/rootfs/etc/systemd/system/aTrustDaemon.service.d/zt.conf',
    'sangfor/atrust/rootfs/etc/systemd/system/eaio_service.service.d/zt.conf',
    'sangfor/easyconnect/rootfs/etc/systemd/system/EasyMonitor.service.d/zt.conf',
    'trustagent/rootfs/etc/systemd/system/trustdservice.service',
    'trustagent/rootfs/etc/systemd/system/trustservice.service',
    'trustagent/rootfs/etc/systemd/system/trustservicemgr.service',
    'trustagent/rootfs/etc/systemd/system/trustnet.service',
)
SHARED = (
    'rootfs/usr/bin/xdg-open',
    'rootfs/usr/local/bin/zt-identity',
    'rootfs/usr/local/bin/zt-init',
    'rootfs/usr/local/bin/zt-net-setup.sh',
    'rootfs/usr/local/sbin/zt-iptables',
    'rootfs/etc/systemd/system/zt-net.service',
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
        self.assertFalse(config.password_valid('abc\x00def'))
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            cfg = str(Path(tmp) / 'config')
            for rejected in (
                '', '12345', 'a' * 129, '#abcde', 'abc\ndef', 'abc\rdef',
                ' abcdef', 'abc\tdef', '密码123456',
            ):
                with mock.patch.dict(
                    os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'all', 'ZT_VNC_PW': rejected}
                ), self.assertRaises(SystemExit):
                    config.container_env('atrust')

            for valid_pw in ('s3cret', 'long-passphrase-1234', 'x' * 128):
                with mock.patch.dict(
                    os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'all', 'ZT_VNC_PW': valid_pw}
                ), mock.patch.object(config, 'host_timezone', return_value='Europe/Paris'):
                    self.assertEqual(config.bind_address(), '0.0.0.0')
                    self.assertEqual(
                        config.container_env('atrust', net_mode='subnet'),
                        {
                            'ZT_NET_MODE': 'subnet',
                            'ZT_AUTH': '1',
                            'VNC_PW': valid_pw,
                            'TZ': 'Europe/Paris',
                        },
                    )

    def test_accept_lan_is_passwordless_by_default_and_honors_password_when_set(self):
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

            # Orthogonal auth: setting VNC_PW activates auth in local and lan modes too.
            for mode in ('local', 'lan'):
                env_pw = {**env_patch, 'ZT_ACCEPT': mode, 'ZT_VNC_PW': 's3cret'}
                with mock.patch.dict(os.environ, env_pw, clear=True), \
                        mock.patch.object(config, 'host_timezone', return_value='Asia/Shanghai'):
                    self.assertEqual(config.auth_password(), 's3cret')
                    self.assertTrue(config.auth_fingerprint())
                    self.assertEqual(
                        config.container_env('atrust'),
                        {'ZT_NET_MODE': 'gateway', 'ZT_AUTH': '1', 'VNC_PW': 's3cret', 'TZ': 'Asia/Shanghai'},
                    )
                # Non-empty invalid password fails closed even in local/lan mode.
                env_bad = {**env_patch, 'ZT_ACCEPT': mode, 'ZT_VNC_PW': '123'}
                with mock.patch.dict(os.environ, env_bad, clear=True), \
                        contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaises(SystemExit):
                    config.container_env('atrust')
            self.assertFalse(bridge.bridge_matches('local', '', bridge.BRIDGE_PROTO, 'local', 'abc123'))
            self.assertFalse(bridge.bridge_matches('lan', 'abc123', bridge.BRIDGE_PROTO, 'lan', ''))
            self.assertTrue(bridge.bridge_matches('lan', 'abc123', bridge.BRIDGE_PROTO, 'lan', 'abc123'))
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
                mock.patch.object(engine.shutil, 'which', side_effect=lambda c: '/usr/bin/docker' if c == 'docker' else None), \
                mock.patch.dict(
                    os.environ,
                    {'APPDATA': '/fake/roaming', 'LOCALAPPDATA': '/fake/local'},
                    clear=True,
                ):
            self.assertEqual(config.config_file(), Path('/fake/roaming/zt/config'))
            self.assertEqual(config.cache_dir(), Path('/fake/local/zt/cache'))
            self.assertEqual(config.state_dir(), Path('/fake/local/zt/state'))
            self.assertEqual(engine.resolve_engine()[0].cli, 'docker')

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
            config.configured_engine()
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

            st = Path(tmp) / 'state'
            st.mkdir(mode=0o755)
            if os.name != 'nt':
                st.chmod(0o755)
            with mock.patch.dict(os.environ, {'ZT_STATE': str(st)}):
                bridge._write_pidfile('atrust', 12345, 'docker', 'all', 'deadbeef1234')
                pid_path = bridge.bridge_pidfile('atrust')
                self.assertTrue(pid_path.is_file())
                self.assertEqual(os.listdir(st), [pid_path.name])
                if os.name != 'nt':
                    self.assertEqual(st.stat().st_mode & 0o777, 0o700)
                    self.assertEqual(pid_path.stat().st_mode & 0o777, 0o600)


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
        for name in (*SHARED,
                     'rootfs/etc/systemd/system/zt-sangfor-daemon.service',
                     'rootfs/etc/systemd/system/zt-sangfor-ui.service',
                     'rootfs/usr/local/bin/zt-sangfor-daemon.sh',
                     'rootfs/usr/local/bin/zt-sangfor-ui.sh',
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

    @unittest.skipIf(os.name == 'nt', 'POSIX umask/chmod test')
    def test_build_context_normalizes_modes_under_linux_umask_0002(self):
        old_umask = os.umask(0o002)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                dummy_payload = b'deb'
                dummy_sha = hashlib.sha256(dummy_payload).hexdigest()
                dummy_blob = Path(tmp) / 'dummy.deb'
                dummy_blob.write_bytes(dummy_payload)
                with mock.patch.dict(os.environ, {'ZT_CACHE': tmp}), \
                        mock.patch.object(build, 'blobs_for', return_value=(('dummy.deb', 'https://example.invalid/dummy.deb', dummy_sha),)), \
                        mock.patch.object(build, 'fetch_blob', return_value=dummy_blob):
                    ctx, _ = build.build_context('trustagent', 'amd64')
                    for dirpath, dirnames, filenames in os.walk(ctx):
                        self.assertEqual(Path(dirpath).stat().st_mode & 0o777, 0o755, dirpath)
                        for fname in filenames:
                            full = Path(dirpath, fname)
                            self.assertFalse(full.stat().st_mode & 0o022, str(full))

                    # Poison cached context dirs back to 0775 (pre-fix Linux cache) and verify self-healing on pure cache hit.
                    for bad_rel in ('rootfs/usr', 'rootfs/usr/bin', 'rootfs/etc', 'rootfs/etc/systemd/system'):
                        (ctx / bad_rel).chmod(0o775)
                    ctx2, _ = build.build_context('trustagent', 'amd64')
                    self.assertEqual(ctx2, ctx)
                    for bad_rel in ('rootfs/usr', 'rootfs/usr/bin', 'rootfs/etc', 'rootfs/etc/systemd/system'):
                        self.assertEqual((ctx / bad_rel).stat().st_mode & 0o777, 0o755, bad_rel)

                # Checkout mode canonicalizer strips group/world-write bits even under umask 0002.
                gw_script = Path(tmp) / 'script.sh'
                gw_unit = Path(tmp) / 'unit.service'
                gw_script.write_text('#!/bin/sh\n', encoding='utf-8')
                gw_unit.write_text('[Unit]\n', encoding='utf-8')
                gw_script.chmod(0o775)
                gw_unit.chmod(0o664)
                self.assertEqual(resources._checkout_mode('common/rootfs/x', gw_script), 0o755)
                self.assertEqual(resources._checkout_mode('common/rootfs/y', gw_unit), 0o644)
        finally:
            os.umask(old_umask)

    def test_build_context_revalidates_cached_blob_sha256_and_rejects_tampering_or_symlinks(self):
        good_payload = b'good-vendor-deb-bytes'
        good_sha = hashlib.sha256(good_payload).hexdigest()
        fetches = 0

        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            source_blob = cache / 'upstream.deb'
            source_blob.write_bytes(good_payload)

            def fake_fetch(filename, url, expected_sha):
                nonlocal fetches
                fetches += 1
                dest = cache / 'blobs' / expected_sha
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(good_payload)
                return dest

            with mock.patch.dict(os.environ, {'ZT_CACHE': str(cache)}), \
                    mock.patch.object(build, 'blobs_for', return_value=(('vendor.deb', 'https://example.invalid/v.deb', good_sha),)), \
                    mock.patch.object(build, 'fetch_blob', side_effect=fake_fetch):
                ctx, _ = build.build_context('trustagent', 'arm64')
                self.assertEqual(fetches, 1)

                # Second call on clean cache MUST reuse without re-fetching.
                ctx2, _ = build.build_context('trustagent', 'arm64')
                self.assertEqual(ctx2, ctx)
                self.assertEqual(fetches, 1)

                # Tamper cached blob bytes -> must warn, delete poisoned cache, and rebuild cleanly!
                (ctx / 'blobs' / 'vendor.deb').write_bytes(b'tampered!')
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    ctx3, _ = build.build_context('trustagent', 'arm64')
                self.assertEqual(fetches, 2)
                self.assertIn('failed SHA256 verification', err.getvalue())
                self.assertEqual((ctx3 / 'blobs' / 'vendor.deb').read_bytes(), good_payload)

                # Replace cached blob with a symlink (even pointing to valid bytes) -> rejected & rebuilt!
                if os.name != 'nt':
                    (ctx3 / 'blobs' / 'vendor.deb').unlink()
                    (ctx3 / 'blobs' / 'vendor.deb').symlink_to(source_blob)
                    with contextlib.redirect_stderr(io.StringIO()) as err:
                        ctx4, _ = build.build_context('trustagent', 'arm64')
                    self.assertEqual(fetches, 3)
                    self.assertIn('failed SHA256 verification', err.getvalue())
                    self.assertFalse((ctx4 / 'blobs' / 'vendor.deb').is_symlink())

    def test_github_workflows_pin_all_actions_to_commit_shas_and_attest_release(self):
        wf_dir = ROOT / '.github' / 'workflows'
        workflows = sorted(wf_dir.glob('*.y*ml'))
        self.assertTrue(workflows, 'expected at least one GitHub Actions workflow')
        uses_count = 0
        for wf in workflows:
            text = wf.read_text(encoding='utf-8')
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith('- uses:') or stripped.startswith('uses:'):
                    uses_count += 1
                    spec_part = stripped.split('uses:', 1)[1].strip()
                    self.assertRegex(
                        spec_part,
                        r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}(\s+#\s*v\S+)?$',
                        f'{wf.name}:{lineno} action not pinned to 40-char commit SHA: {spec_part!r}',
                    )
        self.assertGreaterEqual(uses_count, 5)
        ci_text = (wf_dir / 'ci.yml').read_text(encoding='utf-8')
        self.assertIn('verify-container:', ci_text)
        self.assertIn('python3 -m zt.verify', ci_text)
        self.assertIn('actions/attest-build-provenance@', ci_text)
        self.assertIn('attestations: write', ci_text)
        self.assertIn('id-token: write', ci_text)

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
        self.assertIn('/var/lib/dbus/machine-id', init_sh)
        self.assertIn('/etc/zt/state-paths.conf', init_sh)
        self.assertIn('mount --bind "$src" "$target"', init_sh)
        self.assertIn('setpriv --reuid kasm-user --regid kasm-user --init-groups --no-new-privs', init_sh)
        self.assertIn('chmod 1777 /usr/share/sangfor/.aTrust', init_sh)
        self.assertIn('mount -o remount,rw /sys/fs/cgroup', init_sh)
        self.assertIn('mount --bind /proc/sys/net/ipv4/conf /proc/sys/net/ipv4/conf', init_sh)
        self.assertNotIn('mount --bind /proc/sys/net /proc/sys/net', init_sh)
        self.assertIn('/usr/local/bin/zt-identity', init_sh)
        self.assertIn('/usr/local/sbin/zt-iptables --init', init_sh)
        self.assertIn('/run/zt/resolv.orig', init_sh)
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
        daemon = overlay_text('sangfor/common/rootfs/etc/systemd/system/zt-sangfor-daemon.service')
        ui = overlay_text('sangfor/common/rootfs/etc/systemd/system/zt-sangfor-ui.service')
        self.assertIn('User=root', daemon)
        self.assertIn('NoNewPrivileges=true', daemon)
        self.assertIn(
            'CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE',
            daemon,
        )
        self.assertNotIn(' ~CAP_', daemon)
        self.assertNotIn('XAUTHORITY=', daemon)
        self.assertNotIn('zt-conf.sh sync', daemon)
        self.assertIn('setpriv --reuid kasm-user --regid kasm-user --init-groups --no-new-privs', daemon)
        self.assertIn('User=kasm-user', ui)
        self.assertIn('Group=kasm-user', ui)
        self.assertIn('NoNewPrivileges=true', ui)
        self.assertIn('OOMScoreAdjust=200', ui)
        self.assertIn('BindsTo=kasmvnc.service', ui)
        self.assertNotIn('XAUTHORITY=', ui)

        conf = overlay_text('sangfor/easyconnect/rootfs/usr/local/bin/zt-conf.sh')
        self.assertNotIn('chown', conf)
        self.assertNotIn('sync)', conf)
        self.assertIn('cp -rP', conf)
        if os.name != 'nt':
            with tempfile.TemporaryDirectory() as tmp:
                res_dir = Path(tmp) / 'resources'
                (res_dir / 'conf_backup').mkdir(parents=True)
                (res_dir / 'conf').mkdir(parents=True)
                (res_dir / 'conf_backup' / 'default.json').write_text('{"k":1}\n', encoding='utf-8')
                (res_dir / 'conf_backup' / 'pkg_version.xml').write_text('<v/>\n', encoding='utf-8')
                (res_dir / 'conf' / 'user.json').write_text('{"user":"keep"}\n', encoding='utf-8')
                (res_dir / 'conf' / 'ECDomainFile').write_text('stale\n', encoding='utf-8')
                patched = conf.replace('res=/usr/share/sangfor/EasyConnect/resources', f'res={res_dir}')
                script_path = Path(tmp) / 'zt-conf.sh'
                script_path.write_text(patched, encoding='utf-8')
                script_path.chmod(0o755)
                run = subprocess.run([str(script_path), 'init'], capture_output=True, text=True, check=False)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual((res_dir / 'conf' / 'default.json').read_text(encoding='utf-8'), '{"k":1}\n')
                self.assertEqual((res_dir / 'conf' / 'user.json').read_text(encoding='utf-8'), '{"user":"keep"}\n')
                self.assertFalse((res_dir / 'conf' / 'ECDomainFile').exists())
                self.assertEqual(os.readlink(res_dir / 'conf' / 'pkg_version.xml'), '/dev/null')
        ec_state = overlay_text('sangfor/easyconnect/rootfs/etc/zt/state-paths.conf')
        self.assertIn('easyconnect-conf /usr/share/sangfor/EasyConnect/resources/conf kasm-user:kasm-user 0755', ec_state)
        at_state = overlay_text('sangfor/atrust/rootfs/etc/zt/state-paths.conf')
        self.assertIn('atrust-sys /usr/share/sangfor/.aTrust root:root 1777', at_state)

        # Retired Wave 2 artifacts must be completely absent from overlays and Dockerfiles.
        all_files = resources.overlay_files()
        for retired in (
            'common/rootfs/etc/systemd/system/zt-socks.service',
            'sangfor/common/rootfs/etc/systemd/system/zt-sangfor.service',
            'sangfor/common/rootfs/usr/bin/xdg-open',
            'sangfor/atrust/rootfs/usr/local/bin/zt-sangfor-session.sh',
            'sangfor/easyconnect/rootfs/usr/local/bin/zt-sangfor-session.sh',
            'trustagent/rootfs/etc/udev/rules.d/99-vnic.rules',
            'trustagent/rootfs/etc/systemd/system/udev-vnic-add@.service',
            'trustagent/rootfs/etc/systemd/system/udev-vnic-remove@.service',
            'trustagent/rootfs/usr/local/bin/zt-vnic-add.sh',
            'trustagent/rootfs/usr/local/bin/zt-vnic-remove.sh',
        ):
            self.assertNotIn(retired, all_files, retired)
        for name, item in (('base', spec.BASE), *spec.CLIENTS.items()):
            df = build.overlay_for(item)['Dockerfile'][0].decode('utf-8')
            self.assertNotIn('microsocks', df, name)
            self.assertNotIn('zt-socks.service', df, name)

        # Safe universal xdg-open + Openbox menu.xml callback trigger contracts.
        xdg_sh = overlay_text('common/rootfs/usr/bin/xdg-open')
        xdg_code = '\n'.join(line for line in xdg_sh.splitlines() if not line.lstrip().startswith('#'))
        self.assertNotIn('xmessage', xdg_code)
        self.assertIn('/run/zt-events', xdg_code)
        self.assertIn('setpriv --reuid kasm-user --regid kasm-user --init-groups --no-new-privs', xdg_code)
        for menu_rel in (
            'base/rootfs/etc/zt/openbox/menu.xml',
            'trustagent/rootfs/etc/zt/openbox/menu.xml',
        ):
            menu_xml = overlay_text(menu_rel)
            self.assertIn('python3 -I', menu_xml, menu_rel)
            self.assertIn('encoding=', menu_xml, menu_rel)
            self.assertNotIn('os.fdopen(fd,"w","utf-8")', menu_xml, menu_rel)

        init_sh = overlay_text('common/rootfs/usr/local/bin/zt-init')
        self.assertIn('/run/zt-events', init_sh)
        self.assertIn('GPUCache', init_sh)

    def test_all_trustagent_vendor_units_have_nnp(self):
        for unit in ('trustdservice', 'trustservice', 'trustservicemgr', 'trustnet'):
            content = overlay_text(f'trustagent/rootfs/etc/systemd/system/{unit}.service')
            self.assertIn('NoNewPrivileges=true', content, unit)
        for rel in (
            'trustagent/rootfs/etc/systemd/system/trustdservice.service',
            'trustagent/rootfs/etc/systemd/system/trustservice.service',
            'trustagent/rootfs/etc/systemd/system/trustservicemgr.service',
            'trustagent/rootfs/etc/systemd/system/trustnet.service',
            'sangfor/common/rootfs/etc/systemd/system/zt-sangfor-daemon.service',
            'sangfor/atrust/rootfs/etc/systemd/system/aTrustDaemon.service.d/zt.conf',
            'sangfor/atrust/rootfs/etc/systemd/system/eaio_service.service.d/zt.conf',
            'sangfor/easyconnect/rootfs/etc/systemd/system/EasyMonitor.service.d/zt.conf',
        ):
            content = overlay_text(rel)
            self.assertIn('Requires=zt-net.service', content, rel)
            self.assertIn(
                'CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_PTRACE',
                content,
                rel,
            )
            self.assertNotIn(' ~CAP_', content, rel)
        for name, item in (('base', spec.BASE), *spec.CLIENTS.items()):
            df = build.overlay_for(item)['Dockerfile'][0].decode('utf-8')
            self.assertNotIn('# syntax=docker/dockerfile:1', df, name)
        limits_conf = overlay_text('base/rootfs/etc/systemd/system.conf.d/99-zt-limits.conf')
        self.assertIn('DefaultLimitNOFILE=1024:65536', limits_conf)
        self.assertIn('DefaultLimitCORE=0', limits_conf)

    def test_network_policy_uses_dedicated_chain_and_filters_udp(self):
        unit = overlay_text('common/rootfs/etc/systemd/system/zt-net.service')
        self.assertIn('PassEnvironment=ZT_NET_MODE', unit)
        script = overlay_text('common/rootfs/usr/local/bin/zt-net-setup.sh')
        for token in (
            'ZT-INPUT', 'ZT-OUTPUT', 'ZT-PREROUTING', 'ZT-POSTROUTING',
            'zt: loopback guard', 'zt: host only udp', 'zt: tunnel udp',
            'zt: kasmvnc out', 'zt: kasmvnc mark',
            '--clamp-mss-to-pmtu', '--set-mss 1340', '--set-mss 1220',
            '/run/zt/wan.env', '--reapply',
        ):
            self.assertIn(token, script, token)
        ipt = overlay_text('common/rootfs/usr/local/sbin/zt-iptables')
        self.assertIn('/usr/local/lib/zt-ipt', ipt)
        self.assertIn('ZT_IPT_INTERNAL', ipt)
        self.assertIn('--reapply', ipt)
        self.assertIn('precedence ::ffff:0:0/96', overlay_text('base/rootfs/etc/gai.conf'))
        hook = overlay_text('sangfor/atrust/rootfs/usr/sbin/sysctl-hook')
        self.assertIn('utun[0-9]*.route_localnet=1', hook)
        ta_routes = overlay_text('trustagent/rootfs/usr/local/bin/zt-trustagent-routes.sh')
        self.assertNotIn('--set-mss', ta_routes)
        self.assertIn('/run/zt/wan.env', ta_routes)

    def test_zt_identity_generates_valid_deterministic_smbios3_and_dmi_id(self):
        identity_script = ROOT / 'overlay/common/rootfs/usr/local/bin/zt-identity'
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2, \
                tempfile.TemporaryDirectory() as tmp3:
            for dest, seed in ((tmp1, 'machine-a'), (tmp2, 'machine-a'), (tmp3, 'machine-b')):
                subprocess.run(
                    [sys.executable, str(identity_script), '--dump-dir', dest, '--seed', seed],
                    check=True, capture_output=True, text=True,
                )
            for bad_seed in ('', 'uninitialized', '  UNINITIALIZED  '):
                bad = subprocess.run(
                    [sys.executable, str(identity_script), '--dump-dir', tmp1, '--seed', bad_seed],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(bad.returncode, 2, bad_seed)

            ep1 = (Path(tmp1) / 'dmi/tables/smbios_entry_point').read_bytes()
            dmi1 = (Path(tmp1) / 'dmi/tables/DMI').read_bytes()
            ep2 = (Path(tmp2) / 'dmi/tables/smbios_entry_point').read_bytes()
            dmi2 = (Path(tmp2) / 'dmi/tables/DMI').read_bytes()
            dmi3 = (Path(tmp3) / 'dmi/tables/DMI').read_bytes()

            self.assertEqual((ep1, dmi1), (ep2, dmi2))
            self.assertNotEqual(dmi1, dmi3)
            self.assertEqual(len(ep1), 24)
            self.assertEqual(ep1[:5], b'_SM3_')
            self.assertEqual(sum(ep1) & 0xFF, 0)
            self.assertEqual((ep1[6], ep1[7], ep1[8], ep1[10]), (24, 3, 0, 1))
            max_size, table_addr = struct.unpack_from('<IQ', ep1, 12)
            self.assertEqual(max_size, len(dmi1))
            self.assertEqual(table_addr, 0)

            # Walk every SMBIOS structure and confirm Type 0, 1, 2, 3, 4 (Processor), 127.
            pos = 0
            found = []
            while pos < len(dmi1):
                stype, slen, _handle = struct.unpack_from('<BBH', dmi1, pos)
                found.append((stype, slen))
                str_end = dmi1.index(b'\x00\x00', pos + slen)
                pos = str_end + 2
            self.assertEqual(pos, len(dmi1))
            self.assertEqual(found, [(0, 18), (1, 27), (2, 15), (3, 21), (4, 48), (127, 4)])

            # Confirm sysfs DMI id files are deterministic, 0444, and match SMBIOS serials.
            serial1 = (Path(tmp1) / 'dmi/id/product_serial').read_text(encoding='ascii').strip()
            serial2 = (Path(tmp2) / 'dmi/id/product_serial').read_text(encoding='ascii').strip()
            serial3 = (Path(tmp3) / 'dmi/id/product_serial').read_text(encoding='ascii').strip()
            uuid1 = (Path(tmp1) / 'dmi/id/product_uuid').read_text(encoding='ascii').strip()
            self.assertEqual(serial1, serial2)
            self.assertNotEqual(serial1, serial3)
            self.assertTrue(serial1.startswith('ZT-'))
            self.assertIn(serial1.encode('ascii'), dmi1)
            self.assertRegex(uuid1, r'^[0-9a-f-]{36}$')
            if os.name != 'nt':
                self.assertEqual((Path(tmp1) / 'dmi/id/product_serial').stat().st_mode & 0o777, 0o444)
                self.assertEqual((Path(tmp1) / 'dmi/tables/DMI').stat().st_mode & 0o777, 0o444)


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
            'FragmentPath=/etc/systemd/system/zt-sangfor-daemon.service\n'
            'DropInPaths=/etc/systemd/system/zt-sangfor-daemon.service.d/zt.conf\n'
            'ExecStartPre={ path=/usr/bin/setpriv ; argv[]=/usr/bin/setpriv ... }\n'
            'ExecStart={ path=/usr/local/bin/zt-sangfor-daemon.sh ; argv[]=... }\n'
            '\n'
            'ActiveState=inactive\n'
            'User=\n'
            'FragmentPath=/usr/lib/systemd/system/rc-local.service\n'
            'ExecStart={ path=/etc/rc.local ; argv[]=/etc/rc.local start }\n'
            '\n'
            'ActiveState=active\n'
            'User=kasm-user\n'
            'FragmentPath=/etc/systemd/system/zt-sangfor-ui.service\n'
            'ExecStart={ path=/usr/local/bin/zt-sangfor-ui.sh ; argv[]=... }\n'
        )
        units, active_execs, optional_execs = guest_check.parse_systemd_exec_paths(sample)
        self.assertIn('/etc/systemd/system/zt-sangfor-daemon.service', units)
        self.assertIn('/etc/systemd/system/zt-sangfor-daemon.service.d/zt.conf', units)
        self.assertIn('/usr/local/bin/zt-sangfor-daemon.sh', active_execs)
        self.assertIn('/etc/rc.local', optional_execs)
        self.assertNotIn('/usr/local/bin/zt-sangfor-ui.sh', active_execs)

    def test_parse_report_strict_json_validation(self):
        complete_map = {c: {'ok': True, 'detail': ''} for c in spec.CHECKS}
        good = json.dumps({'version': 1, 'complete': True, 'checks': complete_map}) + '\n'
        self.assertEqual(verify.parse_report(good), [(c, 'ok', '') for c in spec.CHECKS])

        missing = dict(complete_map)
        del missing['ownership']
        findings = verify.parse_report(json.dumps({'version': 1, 'complete': True, 'checks': missing}))
        self.assertEqual(findings[-1][:2], ('inside', 'fail'))
        self.assertIn('ownership', findings[-1][2])

    def test_check_log_checks_extra_logs_and_device_mid(self):
        payload_box = [
            b'({"jsonrpc":"2.0","method":"get_mid","result":"'
            + b'A' * 64
            + b'","uuid":"11111111-2222-4333-8444-555555555555"});'
        ]

        class MidHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(payload_box[0])

            def log_message(self, *_args):
                pass

        srv = http.server.HTTPServer(('127.0.0.1', 0), MidHandler)
        port = srv.server_address[1]
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{port}/_zerotrust/agent?method=get_mid'
            with tempfile.TemporaryDirectory() as tmp:
                ui_log = Path(tmp) / 'ui.log'
                tds_log = Path(tmp) / 'trustdservice.log'
                ui_log.write_text('started ok\n', encoding='utf-8')
                tds_log.write_text('before encode mid_json:{"data":[{"id":"abc"}]}\n', encoding='utf-8')

                ok, detail = guest_check.check_log(
                    str(ui_log), ('Driver not loaded',),
                    extra_logs=((str(tds_log), ('GetBaseDmiInfo failed', '"uuid":""')),),
                    mid_url=url,
                )
                self.assertTrue(ok, detail)

                payload_box[0] = b'({"jsonrpc":"2.0","method":"get_mid","result":"' + b'A' * 64 + b'","uuid":""});'
                ok, detail = guest_check.check_log(
                    str(ui_log), ('Driver not loaded',),
                    extra_logs=((str(tds_log), ('GetBaseDmiInfo failed', '"uuid":""')),),
                    mid_url=url,
                )
                self.assertFalse(ok)
                self.assertIn('empty device uuid', detail)

                payload_box[0] = (
                    b'({"jsonrpc":"2.0","method":"get_mid","result":"'
                    + b'A' * 64
                    + b'","uuid":"11111111-2222-4333-8444-555555555555"});'
                )
                tds_log.write_text('ERROR|get mid GetBaseDmiInfo failed\n', encoding='utf-8')
                ok, detail = guest_check.check_log(
                    str(ui_log), ('Driver not loaded',),
                    extra_logs=((str(tds_log), ('GetBaseDmiInfo failed', '"uuid":""')),),
                    mid_url=url,
                )
                self.assertFalse(ok)
                self.assertIn('GetBaseDmiInfo failed', detail)
        finally:
            srv.shutdown()
            srv.server_close()

    def test_resolve_proc_exe_handles_qemu_binfmt_and_rosetta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'rootfs'
            guest_bin = root / 'usr/bin/trustdservice'
            guest_bin.parent.mkdir(parents=True)
            guest_bin.write_bytes(b'\x7fELF')

            # Linux QEMU binfmt_misc: /proc/<pid>/exe -> missing host /usr/bin/qemu-x86_64-static
            p_qemu = Path(tmp) / 'proc_qemu'
            p_qemu.mkdir()
            (p_qemu / 'exe').symlink_to('/usr/bin/qemu-x86_64-static')
            (p_qemu / 'cmdline').write_bytes(b'/usr/bin/trustdservice\x00--nofork\x00')
            self.assertEqual(
                guest_check._resolve_proc_exe(str(p_qemu), root=str(root)),
                '/usr/bin/trustdservice',
            )

            # Rosetta on macOS Apple Container: skipped cleanly.
            p_rosetta = Path(tmp) / 'proc_rosetta'
            p_rosetta.mkdir()
            (p_rosetta / 'exe').symlink_to('/run/rosetta/rosetta')
            self.assertIsNone(guest_check._resolve_proc_exe(str(p_rosetta), root=str(root)))

            # Native root binary: returned verbatim.
            p_native = Path(tmp) / 'proc_native'
            p_native.mkdir()
            (p_native / 'exe').symlink_to('/usr/bin/trustdservice')
            self.assertEqual(
                guest_check._resolve_proc_exe(str(p_native), root=str(root)),
                '/usr/bin/trustdservice',
            )

    def test_check_identity_and_limits_parsers(self):
        identity_script = ROOT / 'overlay/common/rootfs/usr/local/bin/zt-identity'
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            mid_file = base / 'machine-id'
            dbus_dir = base / 'dbus'
            dbus_dir.mkdir()
            dbus_mid = dbus_dir / 'machine-id'
            seed = '0123456789abcdef0123456789abcdef'
            mid_file.write_text(seed + '\n', encoding='utf-8')
            dbus_mid.symlink_to(mid_file)
            fw = base / 'firmware'
            subprocess.run(
                [sys.executable, str(identity_script), '--dump-dir', str(fw), '--seed', seed],
                check=True, capture_output=True, text=True,
            )
            ok, detail = guest_check.check_identity(
                machine_id_path=str(mid_file),
                dbus_machine_id_path=str(dbus_mid),
                firmware_dir=str(fw),
                dmi_id_dir=str(fw / 'dmi/id'),
                check_ro=False,
            )
            self.assertTrue(ok, detail)

            mid_file.write_text('uninitialized\n', encoding='utf-8')
            ok, detail = guest_check.check_identity(
                machine_id_path=str(mid_file),
                dbus_machine_id_path=str(dbus_mid),
                firmware_dir=str(fw),
                dmi_id_dir=str(fw / 'dmi/id'),
                check_ro=False,
            )
            self.assertFalse(ok)
            self.assertIn('invalid', detail)

        sample_limits = (
            'Limit                     Soft Limit           Hard Limit           Units\n'
            'Max core file size        0                    0                    bytes\n'
            'Max open files            1024                 65536                files\n'
        )
        parsed = guest_check._parse_proc_limits(sample_limits)
        self.assertEqual(parsed['Max open files'], (1024, 65536))
        self.assertEqual(parsed['Max core file size'], (0, 0))
        self.assertEqual(guest_check._parse_cap_bnd('Uid:\t0\nCapBnd:\t0000000000003c00\n'), 0x3c00)
        self.assertEqual(guest_check._parse_cap_bnd('CapBnd:\t0000000000200000\n') & (1 << 21), 1 << 21)


_TUN_BENCHMARK_NET = ipaddress.ip_network('198.18.0.0/15')


def _find_reachable_non_loopback_ipv4():
    """Return a local non-loopback IPv4 reachable via TCP+UDP from this host, or None."""
    candidates = []
    for probe_dst in (('10.255.255.1', 80), ('192.168.255.1', 80), ('172.16.255.1', 80)):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect(probe_dst)
                cand = probe.getsockname()[0]
            if cand not in candidates:
                candidates.append(cand)
        except OSError:
            continue
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            cand = info[4][0]
            if cand not in candidates:
                candidates.append(cand)
    except OSError:
        pass

    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand)
            if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip in _TUN_BENCHMARK_NET:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.settimeout(0.3)
                srv.bind((cand, 0))
                srv.listen(1)
                port = srv.getsockname()[1]
                accepted = []

                def _accept_one():
                    try:
                        conn, _ = srv.accept()
                        conn.close()
                        accepted.append(True)
                    except OSError:
                        pass

                t = threading.Thread(target=_accept_one, daemon=True)
                t.start()
                with socket.create_connection((cand, port), timeout=0.3):
                    pass
                t.join(timeout=0.5)
                if not accepted:
                    continue
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u1, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u2:
                u1.settimeout(0.3)
                u1.bind((cand, 0))
                u2.sendto(b'p', (cand, u1.getsockname()[1]))
                if u1.recvfrom(16)[0] != b'p':
                    continue
            return cand
        except OSError:
            continue
    return None


def _mux_subprocess_source(allow_loopback_for_sandbox=False):
    src = resources.guest_script('mux')
    if not allow_loopback_for_sandbox:
        return src
    return src.replace(
        'def is_disallowed_target_ip(host):',
        'def is_disallowed_target_ip(host):\n    return False\ndef _orig_is_disallowed_target_ip(host):',
        1,
    )


async def _socks5_connect(proxy_port, dst_host, dst_port, auth=None, domain=False):
    """Open a SOCKS5 CONNECT through proxy_port; return (reader, writer, rep, bnd_ip, bnd_port)."""
    r, w = await asyncio.open_connection('127.0.0.1', proxy_port)
    if auth is None:
        w.write(b'\x05\x01\x00')
        await w.drain()
        assert await r.readexactly(2) == b'\x05\x00'
    else:
        u, p = auth[0].encode('utf-8'), auth[1].encode('utf-8')
        w.write(b'\x05\x01\x02')
        await w.drain()
        assert await r.readexactly(2) == b'\x05\x02'
        w.write(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
        await w.drain()
        assert await r.readexactly(2) == b'\x01\x00'
    if domain:
        raw_dom = dst_host.encode('ascii')
        addr_bytes = bytes([guest_mux.ATYP_DOMAIN, len(raw_dom)]) + raw_dom + struct.pack('!H', dst_port)
    else:
        addr_bytes = guest_mux.encode_socks_addr(dst_host, dst_port)
    w.write(b'\x05\x01\x00' + addr_bytes)
    await w.drain()
    hdr = await r.readexactly(4)
    assert hdr[0] == 0x05 and hdr[2] == 0x00, hdr
    rep, atyp = hdr[1], hdr[3]
    if atyp == 1:
        raw = await r.readexactly(6)
        bnd_ip = socket.inet_ntop(socket.AF_INET, raw[:4])
        bnd_port = (raw[4] << 8) | raw[5]
    elif atyp == 4:
        raw = await r.readexactly(18)
        bnd_ip = socket.inet_ntop(socket.AF_INET6, raw[:16])
        bnd_port = (raw[16] << 8) | raw[17]
    else:
        dlen = (await r.readexactly(1))[0]
        raw = await r.readexactly(dlen + 2)
        bnd_ip = raw[:-2].decode('ascii', errors='replace')
        bnd_port = (raw[-2] << 8) | raw[-1]
    return r, w, rep, bnd_ip, bnd_port


class MultiplexedBridge(unittest.TestCase):
    @unittest.skipIf(os.name == 'nt', 'guest/mux.py stdio pipes run inside Linux containers')
    def test_host_and_guest_mux_handle_concurrent_streams_and_rfc1929_auth(self):
        async def scenario():
            target_ip = _find_reachable_non_loopback_ipv4()
            sandbox_fallback = target_ip is None
            bind_ip = target_ip or '127.0.0.1'
            mux_code = _mux_subprocess_source(allow_loopback_for_sandbox=sandbox_fallback)
            backend_hits = 0

            async def echo_target(reader, writer):
                nonlocal backend_hits
                backend_hits += 1
                try:
                    while data := await reader.read(4096):
                        writer.write(b'ok:' + data)
                        await writer.drain()
                except (ConnectionError, OSError):
                    pass
                finally:
                    writer.close()
                    with contextlib.suppress(ConnectionError, OSError):
                        await writer.wait_closed()

            backend = await asyncio.start_server(echo_target, bind_ip, 0)
            backend_port = backend.sockets[0].getsockname()[1]

            class LocalMuxTunnel(bridge.HostMuxTunnel):
                def __init__(self, auth=None, health_path=None):
                    super().__init__(
                        engine.AppleContainerEngine(), 'zt-test', auth=auth,
                        mux_source=mux_code, profile='trustagent', health_path=health_path,
                    )
                    self.spawns = 0

                async def _spawn_process(self):
                    self.spawns += 1
                    return await asyncio.create_subprocess_exec(
                        sys.executable, '-c', self._mux_source,
                        '--profile', 'trustagent',
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

            with tempfile.TemporaryDirectory() as tmp:
                health_path = Path(tmp) / 'health.json'
                tunnel = LocalMuxTunnel(auth=('kasm_user', 's3cret'), health_path=health_path)
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

                    # 3. 10 concurrent authenticated native SOCKS5 CONNECT streams share 1 GuestMux
                    async def authed_client(idx):
                        cr, cw, rep, _, _ = await _socks5_connect(
                            frontend_port, bind_ip, backend_port, auth=('kasm_user', 's3cret'),
                        )
                        self.assertEqual(rep, 0x00)
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
                    self.assertTrue(health_path.is_file())
                    snap = json.loads(health_path.read_text(encoding='utf-8'))
                    self.assertIn('vpn', snap)
                    self.assertIn('updated_at', snap)

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

    @unittest.skipIf(os.name == 'nt', 'guest/mux.py stdio pipes run inside Linux containers')
    def test_guest_mux_v3_blocks_loopback_ssrf_post_resolve_and_supports_happy_eyeballs(self):
        # 1. Pure IP classification matrix
        for blocked in ('127.0.0.1', '127.255.255.254', '0.0.0.0', '::1', '::', '::ffff:127.0.0.1', '::ffff:0.0.0.0'):
            self.assertTrue(guest_mux.is_disallowed_target_ip(blocked), blocked)
        for allowed in ('10.0.0.1', '172.16.0.2', '192.168.1.10', '8.8.8.8', '2001:db8::1', 'fd00::1'):
            self.assertFalse(guest_mux.is_disallowed_target_ip(allowed), allowed)

        async def scenario():
            # 2. Unmodified GuestMux subprocess MUST reject loopback/unspecified/DNS-rebinding targets (REP=0x02)
            #    and reject disallowed CALLBACK_OPEN ports (REP=0x02), plus MAX_TCP_STREAMS cap.
            class RealUnmodifiedMuxTunnel(bridge.HostMuxTunnel):
                async def _spawn_process(self):
                    return await asyncio.create_subprocess_exec(
                        sys.executable, '-c', resources.guest_script('mux'),
                        '--profile', 'trustagent', '--callback-ports', '39301,6901',
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

            with tempfile.TemporaryDirectory() as tmp:
                tunnel = RealUnmodifiedMuxTunnel(
                    engine.AppleContainerEngine(), 'zt-ssrf', auth=None,
                    profile='trustagent', health_path=Path(tmp) / 'h.json',
                )
                srv = await asyncio.start_server(tunnel.handle_client, '127.0.0.1', 0)
                port = srv.sockets[0].getsockname()[1]
                try:
                    proc = await tunnel.ensure_connected()
                    for dst_host, dst_port, is_dom in (
                        ('127.0.0.1', 6901, False),
                        ('0.0.0.0', 6901, False),
                        ('::1', 6901, False),
                        ('::ffff:127.0.0.1', 6901, False),
                        ('localhost', 6901, True),
                    ):
                        _, w, rep, _, _ = await _socks5_connect(port, dst_host, dst_port, domain=is_dom)
                        w.close()
                        await w.wait_closed()
                        self.assertEqual(rep, guest_mux.REP_NOT_ALLOWED, (dst_host, dst_port, is_dom))

                    # Disallowed CALLBACK_OPEN port (6901 stripped even though passed in CLI, 54631 not for trustagent)
                    for bad_cb in (6901, 54631):
                        sid = tunnel._alloc_id()
                        fut = asyncio.get_running_loop().create_future()
                        tunnel._pending_opens[sid] = fut
                        await tunnel.send_on(proc, sid, guest_mux.CALLBACK_OPEN, guest_mux.PORT_STRUCT.pack(bad_cb))
                        kind, payload = await asyncio.wait_for(fut, timeout=5.0)
                        tunnel._pending_opens.pop(sid, None)
                        self.assertEqual((kind, payload), (guest_mux.OPEN_ERR, bytes([guest_mux.REP_NOT_ALLOWED])))

                    # MAX_TCP_STREAMS cap returns REP_GENERAL_FAILURE immediately
                    tunnel._max_tcp_streams = 0
                    _, w, rep, _, _ = await _socks5_connect(port, '10.0.0.1', 443)
                    w.close()
                    await w.wait_closed()
                    self.assertEqual(rep, guest_mux.REP_GENERAL_FAILURE)
                finally:
                    srv.close()
                    await srv.wait_closed()
                    await tunnel.close()

            # 3. RFC 8305 Happy Eyeballs falls back when first candidate fails/stalls
            mux = guest_mux.GuestMux(profile='trustagent')
            try:
                # Address ordering interleaves IPv4 first then IPv6 for enterprise VPN tunnels
                interleaved = guest_mux._interleave_v4_first([
                    (socket.AF_INET6, '2001:db8::1'),
                    (socket.AF_INET6, '2001:db8::2'),
                    (socket.AF_INET, '198.51.100.1'),
                ])
                self.assertEqual(
                    list(interleaved),
                    [
                        (socket.AF_INET, '198.51.100.1'),
                        (socket.AF_INET6, '2001:db8::1'),
                        (socket.AF_INET6, '2001:db8::2'),
                    ],
                )

                # DNS rebinding check: resolve_and_filter rejects if all resolved IPs are loopback
                with mock.patch.object(
                    guest_mux.socket, 'getaddrinfo',
                    return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))],
                ):
                    status, targets = await mux.resolve_and_filter('rebind.example', 80, socket.SOCK_STREAM)
                self.assertEqual((status, tuple(targets)), ('blocked', ()))

                # Happy Eyeballs opens second candidate when first raises ConnectionRefusedError
                fake_reader, fake_writer = mock.Mock(), mock.Mock()
                calls = []

                async def fake_open(host, port, family=0):
                    calls.append(host)
                    if host == '198.51.100.1':
                        raise ConnectionRefusedError('refused')
                    return fake_reader, fake_writer

                with mock.patch.object(guest_mux.asyncio, 'open_connection', side_effect=fake_open):
                    got = await mux._happy_eyeballs_connect(
                        [(socket.AF_INET, '198.51.100.1'), (socket.AF_INET, '198.51.100.2')],
                        443,
                    )
                self.assertEqual(got, (fake_reader, fake_writer))
                self.assertEqual(calls, ['198.51.100.1', '198.51.100.2'])
            finally:
                mux._dns_executor.shutdown(wait=False)

        asyncio.run(scenario())

        # 4. verify.mux_e2e_holds runs end-to-end against a stand-in TCP echo listener
        target_ip = _find_reachable_non_loopback_ipv4()
        if target_ip:
            srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv_sock.bind((target_ip, 0))
            srv_sock.listen(8)
            standin_port = srv_sock.getsockname()[1]
            stop_evt = threading.Event()

            def serve_echo():
                srv_sock.settimeout(0.2)
                while not stop_evt.is_set():
                    try:
                        conn, _ = srv_sock.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    try:
                        data = conn.recv(64)
                        if data:
                            conn.sendall(b'echo:' + data)
                    finally:
                        conn.close()

            th = threading.Thread(target=serve_echo, daemon=True)
            th.start()
            try:
                fake_eng = mock.Mock(cli='docker')
                fake_eng.inspect.return_value = {
                    'status': {'networks': [{'ipv4Address': f'{target_ip}/24'}]}
                }

                class TestE2ETunnel(bridge.HostMuxTunnel):
                    async def _spawn_process(self):
                        return await asyncio.create_subprocess_exec(
                            sys.executable, '-c', resources.guest_script('mux'),
                            '--profile', 'trustagent', '--callback-ports', '39301',
                            stdin=asyncio.subprocess.PIPE,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )

                with mock.patch.object(verify, 'STAND_IN', standin_port):
                    problem, detail = verify.mux_e2e_holds(
                        fake_eng, 'zt-verify-trustagent', 'trustagent', tunnel_cls=TestE2ETunnel,
                    )
                self.assertIsNone(problem, problem)
                self.assertIn('REP=0x02', detail)
                self.assertIn(f'{target_ip}:{standin_port}', detail)
            finally:
                stop_evt.set()
                srv_sock.close()
                th.join(timeout=2)

    @unittest.skipIf(os.name == 'nt', 'guest/mux.py stdio pipes run inside Linux containers')
    def test_sso_events_callback_dual_allowlist_ttl_and_health_persistence(self):
        async def scenario():
            # Echo server simulating a VPN client's local SSO callback listener on 127.0.0.1.
            async def cb_backend(reader, writer):
                req = await reader.read(1024)
                writer.write(b'CBOK:' + req)
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            cb_srv = await asyncio.start_server(cb_backend, '127.0.0.1', 0)
            cb_port = cb_srv.sockets[0].getsockname()[1]

            # Find a separate free ephemeral port on 127.0.0.1 for the host callback listener
            # (on the same machine host and guest share loopback, so pick a distinct port for host
            # only by binding cb_srv on cb_port and letting HostMuxTunnel test forwarding via
            # direct CALLBACK_OPEN, plus testing host listener lifecycle on another free port).
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(('127.0.0.1', 0))
                host_cb_port = probe.getsockname()[1]

            with tempfile.TemporaryDirectory() as tmp:
                events_file = Path(tmp) / 'latest.json'
                health_path = Path(tmp) / 'health-trustagent.json'
                custom_mux = resources.guest_script('mux').replace(
                    'STATIC_CALLBACK_ALLOWLIST = frozenset((39301, 54631, 54530))',
                    f'STATIC_CALLBACK_ALLOWLIST = frozenset((39301, 54631, 54530, {cb_port}, {host_cb_port}))',
                    1,
                ).replace(
                    "EVENTS_PATH = '/run/zt-events/latest.json'",
                    f'EVENTS_PATH = {str(events_file)!r}',
                    1,
                )

                class CallbackMuxTunnel(bridge.HostMuxTunnel):
                    async def _spawn_process(self):
                        return await asyncio.create_subprocess_exec(
                            sys.executable, '-c', custom_mux,
                            '--profile', 'trustagent', '--callback-ports', f'{cb_port},{host_cb_port}',
                            stdin=asyncio.subprocess.PIPE,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )

                with mock.patch.object(bridge, 'STATIC_CALLBACK_ALLOWLIST', frozenset((39301, 54631, 54530, cb_port, host_cb_port))):
                    tunnel = CallbackMuxTunnel(
                        engine.AppleContainerEngine(), 'zt-cb', auth=None,
                        profile='trustagent',
                        callback_ports=(host_cb_port,),
                        callback_ttl=0.8,
                        health_path=health_path,
                    )
                    try:
                        proc = await tunnel.ensure_connected()

                        # 1. Write OPEN_URL event (as safe xdg-open does) and trigger poll via PING.
                        sso_url = 'https://sso.example.com/auth?code=abc'
                        events_file.write_text(
                            json.dumps({'kind': 'url', 'url': sso_url, 'ts': int(bridge.time.time())}) + '\n',
                            encoding='utf-8',
                        )
                        await tunnel.ping(proc=proc)
                        for _ in range(30):
                            if host_cb_port in tunnel._callback_servers:
                                break
                            await asyncio.sleep(0.05)

                        self.assertIn(host_cb_port, tunnel._callback_servers)
                        # Listener MUST bind strictly on 127.0.0.1
                        bound_addr = tunnel._callback_servers[host_cb_port].sockets[0].getsockname()
                        self.assertEqual(bound_addr[0], '127.0.0.1')
                        # health.json persisted with 0600, sso_url, vpn=sso-pending, callback_ports
                        snap = json.loads(health_path.read_text(encoding='utf-8'))
                        self.assertEqual(snap.get('sso_url'), sso_url)
                        self.assertEqual(snap.get('vpn'), 'sso-pending')
                        self.assertEqual(snap.get('callback_ports'), [host_cb_port])
                        self.assertEqual(health_path.stat().st_mode & 0o777, 0o600)

                        # 2. Direct CALLBACK_OPEN to allowlisted cb_port succeeds & splices data!
                        sid = tunnel._alloc_id()
                        st = guest_mux.StreamState()
                        fut = asyncio.get_running_loop().create_future()
                        tunnel._streams[sid] = st
                        tunnel._pending_opens[sid] = fut
                        await tunnel.send_on(proc, sid, guest_mux.CALLBACK_OPEN, guest_mux.PORT_STRUCT.pack(cb_port))
                        kind, _ = await asyncio.wait_for(fut, timeout=5.0)
                        self.assertEqual(kind, guest_mux.OPEN_OK)
                        await tunnel.send_on(proc, sid, guest_mux.DATA, b'token=xyz')
                        await tunnel.send_on(proc, sid, guest_mux.EOF)
                        got_kind, got_data = await asyncio.wait_for(st.recv(), timeout=5.0)
                        self.assertEqual((got_kind, got_data), (guest_mux.DATA, b'CBOK:token=xyz'))
                        tunnel._streams.pop(sid, None)
                        tunnel._pending_opens.pop(sid, None)

                        # 3. TTL expiry automatically closes the host 127.0.0.1 callback listener!
                        for _ in range(30):
                            if not tunnel._callback_servers:
                                break
                            await asyncio.sleep(0.1)
                        self.assertEqual(tunnel._callback_servers, {})
                    finally:
                        await tunnel.close()
                        cb_srv.close()
                        await cb_srv.wait_closed()

        asyncio.run(scenario())

    def test_accept_all_rate_limiters_and_sleep_wake_heartbeat(self):
        # 1. _ConnRateLimiter: per-real-IP window limit, loopback exempt, bounded LRU
        conn_lim = bridge._ConnRateLimiter(max_hits=3, window=10.0, max_ips=2)
        for _ in range(10):
            self.assertTrue(conn_lim.allow('127.0.0.1', now=100.0))
            self.assertTrue(conn_lim.allow('::1', now=100.0))
        self.assertTrue(conn_lim.allow('203.0.113.5', now=100.0))
        self.assertTrue(conn_lim.allow('203.0.113.5', now=101.0))
        self.assertTrue(conn_lim.allow('203.0.113.5', now=102.0))
        self.assertFalse(conn_lim.allow('203.0.113.5', now=103.0))
        # After window slides past 100.0, allowed again
        self.assertTrue(conn_lim.allow('203.0.113.5', now=110.5))
        # Bounded map size
        conn_lim.allow('203.0.113.6', now=111.0)
        conn_lim.allow('203.0.113.7', now=111.0)
        self.assertLessEqual(len(conn_lim._hits), 2)

        # 2. _AuthFailureLimiter: 5 failed RFC 1929 logins -> 60s block, loopback exempt, success clears
        auth_lim = bridge._AuthFailureLimiter(max_failures=5, window=60.0, block_seconds=60.0)
        for _ in range(10):
            auth_lim.record_failure('127.0.0.1', now=10.0)
        self.assertFalse(auth_lim.is_blocked('127.0.0.1', now=10.0))
        for i in range(4):
            auth_lim.record_failure('198.51.100.9', now=10.0 + i)
            self.assertFalse(auth_lim.is_blocked('198.51.100.9', now=10.0 + i))
        auth_lim.record_failure('198.51.100.9', now=15.0)
        self.assertTrue(auth_lim.is_blocked('198.51.100.9', now=20.0))
        self.assertFalse(auth_lim.is_blocked('198.51.100.9', now=76.0))
        auth_lim.record_failure('198.51.100.9', now=80.0)
        auth_lim.record_success('198.51.100.9')
        self.assertNotIn('198.51.100.9', auth_lim._failures)

        # 3. Sleep-wake detector & heartbeat PING failure triggers clean tunnel reset
        self.assertFalse(bridge._check_sleep_jump(100.0, 1000.0, 101.0, 1001.0))
        self.assertTrue(bridge._check_sleep_jump(100.0, 1000.0, 101.0, 1060.0))

        async def hb_scenario():
            tunnel = bridge.HostMuxTunnel(
                engine.AppleContainerEngine(), 'zt-hb',
                heartbeat_interval=0.05, heartbeat_timeout=0.05,
            )
            fake_proc = mock.Mock(returncode=None, stdin=None)
            fake_proc.wait = mock.AsyncMock(return_value=0)
            tunnel._process = fake_proc
            resets = []

            async def fake_reset(p):
                resets.append(p)
                tunnel._process = None

            with mock.patch.object(bridge, '_check_sleep_jump', return_value=True), \
                    mock.patch.object(tunnel, 'ping', side_effect=asyncio.TimeoutError), \
                    mock.patch.object(tunnel, '_reset_tunnel', side_effect=fake_reset), \
                    mock.patch.object(tunnel, 'ensure_connected', new=mock.AsyncMock()), \
                    contextlib.redirect_stderr(io.StringIO()):
                tunnel.start_heartbeat()
                for _ in range(40):
                    if resets:
                        break
                    await asyncio.sleep(0.02)
                await tunnel.close()
            self.assertEqual(resets, [fake_proc])

        asyncio.run(hb_scenario())

    def test_boot_health_fast_refresh_dual_stack_fallback_and_idle_tunnel_keepalive(self):
        # 1. Fast post-start health refresh converges daemon-down -> connected before 15s cadence
        async def boot_refresh_scenario():
            tunnel = bridge.HostMuxTunnel(
                engine.AppleContainerEngine(), 'zt-boot',
                heartbeat_interval=15.0, heartbeat_timeout=1.0,
                boot_refresh_delays=(0.06, 0.14),
            )
            fake_proc = mock.Mock(returncode=None, stdin=None)
            fake_proc.wait = mock.AsyncMock(return_value=0)
            tunnel._process = fake_proc
            tunnel._epoch = 1
            tunnel._connected_at = bridge.time.monotonic()
            tunnel._last_health = {'vpn': 'daemon-down'}
            ping_calls = []

            async def fake_ping(proc=None, timeout=None):
                ping_calls.append(proc)
                if len(ping_calls) == 1:
                    tunnel._last_health = {'vpn': 'disconnected'}
                else:
                    tunnel._last_health = {'vpn': 'connected', 'iface': 'vnic0'}
                return tunnel._last_health

            with mock.patch.object(tunnel, 'ping', side_effect=fake_ping):
                tunnel.start_heartbeat()
                for _ in range(40):
                    if len(ping_calls) >= 2:
                        break
                    await asyncio.sleep(0.02)
                await tunnel.close()
            self.assertEqual(len(ping_calls), 2)
            self.assertEqual(tunnel._last_health['vpn'], 'connected')

        asyncio.run(boot_refresh_scenario())

        # 2. Dual-stack listener gracefully falls back to IPv4 on IPv6 EAFNOSUPPORT without leaking sockets
        async def dual_stack_fallback():
            real_socket = bridge.socket.socket

            def ipv4_only_socket(family=socket.AF_INET, *args, **kwargs):
                if family == socket.AF_INET6:
                    raise OSError(socket.errno.EAFNOSUPPORT, 'no ipv6')
                return real_socket(family, *args, **kwargs)

            async def noop(_r, _w):
                pass

            with mock.patch.object(bridge.socket, 'socket', side_effect=ipv4_only_socket):
                servers = await bridge._start_dual_stack_servers(noop, '127.0.0.1', 0)
            try:
                self.assertEqual(len(servers), 1)
            finally:
                for srv in servers:
                    srv.close()
                    await srv.wait_closed()

        asyncio.run(dual_stack_fallback())

        # 3. _discover_keepalive_target prioritizes non-loopback resolv.conf DNS -> route gw -> subnet peer
        with tempfile.TemporaryDirectory() as tmp:
            resolv = Path(tmp) / 'resolv.conf'
            route = Path(tmp) / 'route'
            # Skip loopback 127.0.0.1, pick non-loopback corp DNS 10.10.0.53
            resolv.write_text('nameserver 127.0.0.1\nnameserver 10.10.0.53\n', encoding='utf-8')
            self.assertEqual(
                guest_mux._discover_keepalive_target('vnic0', resolv_path=str(resolv), route_path=str(route)),
                (socket.AF_INET, '10.10.0.53', 53),
            )
            # Loopback-only resolv.conf falls back to tunnel gateway in /proc/net/route
            resolv.write_text('nameserver 127.0.0.1\n', encoding='utf-8')
            # 10.8.0.1 in little-endian hex = 0100080A; 10.8.0.0/24 mask = 00FFFFFF
            route.write_text(
                'Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n'
                'vnic0\t0000080A\t0100080A\t0003\t0\t0\t0\t00FFFFFF\n',
                encoding='utf-8',
            )
            self.assertEqual(
                guest_mux._discover_keepalive_target('vnic0', resolv_path=str(resolv), route_path=str(route)),
                (socket.AF_INET, '10.8.0.1', 53),
            )
            self.assertIsNone(guest_mux._discover_keepalive_target('', resolv_path=str(resolv), route_path=str(route)))

        # 4. Passive idle tunnel keepalive: no-op when tunnel down, fires once per idle window when UP, resets on activity
        async def keepalive_scenario():
            probed = []

            async def fake_probe(iface):
                probed.append(iface)
                return True

            mux = guest_mux.GuestMux(
                profile='trustagent', keepalive_idle=0.1, keepalive_probe_fn=fake_probe,
            )
            try:
                # Tunnel down -> silent no-op even after idle window
                with mock.patch.object(guest_mux, '_detect_tunnel_iface', return_value=''):
                    mux._last_tunnel_activity = guest_mux.time.monotonic() - 1.0
                    self.assertFalse(mux._maybe_idle_keepalive())
                    self.assertEqual(probed, [])

                # Tunnel UP + active traffic -> no-op
                with mock.patch.object(guest_mux, '_detect_tunnel_iface', return_value='vnic0'), \
                        mock.patch.object(guest_mux, '_read_iface_tx_bytes', return_value=100):
                    mux.touch_tunnel_activity()
                    self.assertFalse(mux._maybe_idle_keepalive())

                    # Idle >= keepalive_idle -> triggers exactly 1 probe, rate-limited immediately after
                    mux._last_tunnel_activity = guest_mux.time.monotonic() - 0.5
                    self.assertTrue(mux._maybe_idle_keepalive())
                    self.assertFalse(mux._maybe_idle_keepalive())
                    if mux._bg_tasks:
                        await asyncio.gather(*list(mux._bg_tasks), return_exceptions=True)
                    self.assertEqual(probed, ['vnic0'])
                    self.assertEqual(mux._keepalive_probes_sent, 1)
            finally:
                mux._dns_executor.shutdown(wait=False)

        asyncio.run(keepalive_scenario())

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
            target_ip = _find_reachable_non_loopback_ipv4()
            sandbox_fallback = target_ip is None
            bind_ip = target_ip or '127.0.0.1'
            mux_code = _mux_subprocess_source(allow_loopback_for_sandbox=sandbox_fallback)

            big_size = 16 * 1024 * 1024  # 16 MiB (4x the 4 MiB per-stream window)
            block = bytes(range(256)) * 256  # 64 KiB deterministic block
            want_sha = hashlib.sha256()
            for _ in range(big_size // len(block)):
                want_sha.update(block)
            want_digest = want_sha.hexdigest()

            async def target_server(reader, writer):
                try:
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

            backend = await asyncio.start_server(target_server, bind_ip, 0)
            backend_port = backend.sockets[0].getsockname()[1]

            class EchoUDP(asyncio.DatagramProtocol):
                def connection_made(self, transport):
                    self.transport = transport

                def datagram_received(self, data, addr):
                    self.transport.sendto(b'udp:' + data, addr)

            loop = asyncio.get_running_loop()
            echo_transport, _ = await loop.create_datagram_endpoint(EchoUDP, local_addr=(bind_ip, 0))
            echo_port = echo_transport.get_extra_info('sockname')[1]

            class LocalMuxTunnel(bridge.HostMuxTunnel):
                async def _spawn_process(self):
                    return await asyncio.create_subprocess_exec(
                        sys.executable, '-c', mux_code,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )

            tunnel = LocalMuxTunnel(engine.AppleContainerEngine(), 'zt-hol', auth=None)
            srv = await asyncio.start_server(tunnel.handle_client, '127.0.0.1', 0)
            port = srv.sockets[0].getsockname()[1]
            try:
                # 1. Client A triggers a 16 MiB download and STOPS reading (TCP zero window).
                ra, wa, rep_a, _, _ = await _socks5_connect(port, bind_ip, backend_port)
                self.assertEqual(rep_a, 0x00)
                wa.write(b'BIG')
                await wa.drain()
                # Give server time to fill stream A's entire 4 MiB credit window and pause.
                await asyncio.sleep(0.5)

                # 2. While A is stalled, Client B MUST complete handshake + TCP transfer fast!
                rb, wb, rep_b, _, _ = await asyncio.wait_for(
                    _socks5_connect(port, bind_ip, backend_port), timeout=2.0,
                )
                self.assertEqual(rep_b, 0x00)
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
                    pkt = b'\x00\x00\x00' + guest_mux.encode_socks_addr(bind_ip, echo_port) + b'fast'
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
            target_ip = _find_reachable_non_loopback_ipv4()
            sandbox_fallback = target_ip is None
            bind_ip = target_ip or '127.0.0.1'
            mux_code = _mux_subprocess_source(allow_loopback_for_sandbox=sandbox_fallback)

            async def tcp_echo(reader, writer):
                try:
                    while data := await reader.read(4096):
                        writer.write(b'tcp:' + data)
                        await writer.drain()
                except (ConnectionError, OSError):
                    pass
                finally:
                    writer.close()
                    with contextlib.suppress(ConnectionError, OSError):
                        await writer.wait_closed()

            backend = await asyncio.start_server(tcp_echo, bind_ip, 0)
            backend_port = backend.sockets[0].getsockname()[1]

            # Real IPv4 UDP echo server on bind_ip
            udp_hits = []

            class EchoUDP(asyncio.DatagramProtocol):
                def connection_made(self, transport):
                    self.transport = transport

                def datagram_received(self, data, addr):
                    udp_hits.append(data)
                    self.transport.sendto(b'echo:' + data, addr)

            loop = asyncio.get_running_loop()
            echo_transport, _ = await loop.create_datagram_endpoint(
                EchoUDP, local_addr=(bind_ip, 0),
            )
            echo_port = echo_transport.get_extra_info('sockname')[1]

            class LocalMuxTunnel(bridge.HostMuxTunnel):
                def __init__(self, auth=None):
                    super().__init__(engine.AppleContainerEngine(), 'zt-test', auth=auth)
                    self.spawns = 0

                async def _spawn_process(self):
                    self.spawns += 1
                    return await asyncio.create_subprocess_exec(
                        sys.executable, '-c', mux_code,
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
                    body_v4 = guest_mux.encode_socks_addr(bind_ip, echo_port) + b'hello-v4'
                    reply = await udp_roundtrip(client_sock, (bnd_ip, bnd_port), body_v4)
                    self.assertEqual(reply[:3], b'\x00\x00\x00')
                    atyp, rhost, rport, off = guest_mux.parse_socks_addr(reply, 3)
                    self.assertEqual((atyp, rhost, rport, reply[off:]), (1, bind_ip, echo_port, b'echo:hello-v4'))

                    # Loopback UDP target must be dropped by SSRF filter when running unmodified mux
                    if not sandbox_fallback:
                        before = len(udp_hits)
                        lo_body = b'\x03\x09localhost' + struct.pack('!H', echo_port) + b'blocked-lo'
                        client_sock.sendto(b'\x00\x00\x00' + lo_body, (bnd_ip, bnd_port))
                        await asyncio.sleep(0.15)
                        self.assertEqual(len(udp_hits), before)

                    # FRAG != 0 must be dropped silently
                    before = len(udp_hits)
                    client_sock.sendto(b'\x00\x00\x02' + body_v4, (bnd_ip, bnd_port))
                    await asyncio.sleep(0.15)
                    self.assertEqual(len(udp_hits), before)

                    # Burst of 350 UDP datagrams must NOT stall concurrent TCP CONNECT on the same mux!
                    for idx in range(350):
                        client_sock.sendto(
                            b'\x00\x00\x00' + guest_mux.encode_socks_addr(bind_ip, echo_port) + f'b{idx}'.encode(),
                            (bnd_ip, bnd_port),
                        )
                    tr, tw, rep_t, _, _ = await _socks5_connect(noauth_port, bind_ip, backend_port)
                    self.assertEqual(rep_t, 0x00)
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
                        b'\x00\x00\x00' + guest_mux.encode_socks_addr(bind_ip, echo_port) + b'wrong-port',
                        (abnd_ip, abnd_port),
                    )
                    await asyncio.sleep(0.15)
                    self.assertEqual(len(udp_hits), before)

                    # Packet from pinned port succeeds
                    body_ok = guest_mux.encode_socks_addr(bind_ip, echo_port) + b'authed-udp'
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

    @unittest.skipIf(os.name == 'nt', 'POSIX subprocess signal test')
    def test_host_mux_reaps_process_on_protocol_desync_and_send_if_open_handles_broken_pipe(self):
        async def scenario():
            bad_frame = struct.pack('>IBI', 1, guest_mux.DATA, guest_mux.MAX_FRAME + 1)
            code = (
                'import sys, time\n'
                f'sys.stdout.buffer.write({bad_frame!r})\n'
                'sys.stdout.buffer.flush()\n'
                'time.sleep(30)\n'
            )

            spawned = []

            class DesyncTunnel(bridge.HostMuxTunnel):
                async def _spawn_process(self):
                    proc = await asyncio.create_subprocess_exec(
                        sys.executable, '-c', code,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    spawned.append(proc)
                    return proc

            tunnel = DesyncTunnel(mock.Mock(cli='docker'), 'zt-atrust', mux_source='')
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(ConnectionError):
                    await tunnel.ensure_connected()
                await asyncio.wait_for(tunnel._reader_task, timeout=5.0)
                self.assertEqual(len(spawned), 1)
                self.assertIsNotNone(spawned[0].returncode)
                self.assertNotIn(spawned[0], tunnel._active_procs)

                # send_if_open must swallow BrokenPipeError cleanly.
                fake_stdin = mock.Mock()
                fake_stdin.is_closing.return_value = False
                fake_stdin.drain = mock.AsyncMock(side_effect=BrokenPipeError('closed'))
                tunnel._process = mock.Mock(returncode=None, stdin=fake_stdin)
                await tunnel.send_if_open(1, guest_mux.RST)
                tunnel._process = None
                await tunnel.close()

        asyncio.run(scenario())


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

        gordon_err = (
            "ERROR: failed to solve: bad dockerfile\n"
            "\n"
            "What's next:\n"
            '    Debug this build failure with Gordon -> docker ai "help me fix this build failure"\n'
        )
        with mock.patch.object(engine.subprocess, 'run', return_value=self.answer('', 1, gordon_err)), \
                contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit):
            eng.run_cli('build', '-f', 'Dockerfile', '.', quiet=True)
        self.assertIn('zt: "docker build" failed: ERROR: failed to solve: bad dockerfile', err.getvalue())
        self.assertNotIn('Gordon', err.getvalue())

    def test_build_and_stop_use_cross_engine_compatible_flags(self):
        eng = mock.Mock(cli='docker', display_name='Docker')
        eng.image_exists.return_value = False
        eng.container_state.return_value = 'running'
        eng.run_cli.return_value = self.answer()

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(build, 'build_context', return_value=(Path(tmp), 'deadbeef1234')), \
                contextlib.redirect_stdout(io.StringIO()):
            build.build(eng, 'base', force=True, arch='arm64')
        build_args = eng.run_cli.call_args.args
        self.assertEqual(build_args[0], 'build')
        self.assertIn('--label', build_args)
        self.assertNotIn('-l', build_args)

        eng.run_cli.reset_mock()
        with mock.patch.object(cli, 'make_engine', return_value=eng), \
                mock.patch.object(cli, 'bridge_stop'), \
                contextlib.redirect_stdout(io.StringIO()):
            cli.cmd_down(argparse.Namespace(target='atrust'))
        eng.run_cli.assert_called_once_with('stop', '-t', '8', 'zt-atrust', quiet=True)

    def test_docker_container_buildx_driver_uses_load_and_local_oci_base_context(self):
        # Driver detection: 'docker' -> False, 'docker-container' -> True, missing buildx -> False.
        d_native = engine.DockerEngine()
        with mock.patch.object(d_native, 'run_cli', return_value=self.answer('Name: default\nDriver: docker\n')):
            self.assertFalse(d_native.needs_external_build_load)

        d_container = engine.DockerEngine()
        with mock.patch.object(
            d_container, 'run_cli',
            return_value=self.answer('Name: default\nDriver: docker-container\n'),
        ):
            self.assertTrue(d_container.needs_external_build_load)

        d_podman_plain = engine.DockerEngine()
        with mock.patch.object(d_podman_plain, 'run_cli', return_value=self.answer('', 1)):
            self.assertFalse(d_podman_plain.needs_external_build_load)

        # Under docker-container driver, base exports OCI layout + --load and child mounts it via --build-context.
        calls = []

        def fake_cli(*args, quiet=False, check=True, timeout=None, env=None):
            calls.append(args)
            if '--output' in args:
                out_spec = args[args.index('--output') + 1]
                dest = out_spec.split('dest=', 1)[1].split(',tar=', 1)[0].strip('"')
                (Path(dest) / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}\n', encoding='utf-8')
            return self.answer()

        eng = mock.Mock(cli='docker', display_name='Docker', needs_external_build_load=True)
        eng.image_exists.return_value = False
        eng.run_cli.side_effect = fake_cli

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_CACHE': tmp}), \
                mock.patch.object(build, 'build_context', return_value=(Path(tmp), 'deadbeef1234')), \
                contextlib.redirect_stdout(io.StringIO()):
            build.build(eng, 'trustagent', force=True, arch='arm64')

            self.assertEqual(len(calls), 2)
            base_call, child_call = calls
            self.assertIn('--load', base_call)
            self.assertIn('--output', base_call)
            self.assertIn('type=oci,dest=', base_call[base_call.index('--output') + 1])
            self.assertIn('--load', child_call)
            self.assertIn('--build-context', child_call)
            base_ref = build.current_ref('base', 'arm64')
            ctx_arg = child_call[child_call.index('--build-context') + 1]
            self.assertTrue(ctx_arg.startswith(f'{base_ref}=oci-layout://'), ctx_arg)
            oci_path = Path(ctx_arg.split('=oci-layout://', 1)[1])
            self.assertTrue((oci_path / 'oci-layout').is_file())

        # Buildx < 0.13 splits base export (--output) and local load (--load) into two calls.
        calls_old = []

        def fake_cli_old(*args, quiet=False, check=True, timeout=None, env=None):
            calls_old.append(args)
            if '--output' in args:
                out_spec = args[args.index('--output') + 1]
                dest = out_spec.split('dest=', 1)[1].split(',tar=', 1)[0].strip('"')
                (Path(dest) / 'oci-layout').write_text('{"imageLayoutVersion":"1.0.0"}\n', encoding='utf-8')
            return self.answer()

        eng_old = mock.Mock(
            cli='docker', display_name='Docker',
            needs_external_build_load=True, supports_multi_output_build=False,
        )
        eng_old.image_exists.return_value = False
        eng_old.run_cli.side_effect = fake_cli_old
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_CACHE': tmp}), \
                mock.patch.object(build, 'build_context', return_value=(Path(tmp), 'deadbeef1234')), \
                contextlib.redirect_stdout(io.StringIO()):
            build.build(eng_old, 'base', force=True, arch='arm64')
        self.assertEqual(len(calls_old), 2)
        self.assertIn('--output', calls_old[0])
        self.assertNotIn('--load', calls_old[0])
        self.assertIn('--load', calls_old[1])
        self.assertNotIn('--output', calls_old[1])
        self.assertTrue(build._oci_context_ref('localhost/zt-base:1', Path('/tmp/a b')).startswith('"'))

    def test_docker_net_mode_keeps_gateway_in_all_modes_and_subnet_for_podman(self):
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
            self.assertEqual(docker.net_mode_for('all'), 'gateway')

        podman_rl = engine.DockerEngine()
        rl_info = json.dumps({
            'Host': {'BuildahVersion': '1.35.0', 'Security': {'Rootless': True}},
            'SecurityOptions': ['name=rootless'],
        })
        with mock.patch.object(podman_rl, 'run_cli', return_value=self.answer(rl_info)):
            flags = podman_rl.container_flags('all', mac_address='02:7a:74:11:22:33')
            self.assertTrue(podman_rl.is_rootless_podman)
            self.assertEqual(podman_rl.net_mode_for('local'), 'subnet')
            self.assertIn('--privileged', flags)
            self.assertNotIn('--cap-add', flags)
            self.assertNotIn('--mac-address', flags)

        # Rootful Podman (e.g. podman machine / netavark) also uses subnet mode without --privileged.
        podman_rf = engine.DockerEngine()
        rf_info = json.dumps({'ServerVersion': '6.0.2', 'SecurityOptions': ['name=selinux']})
        rf_ver = json.dumps({'Components': [{'Name': 'Podman Engine', 'Version': '6.0.2'}]})
        with mock.patch.object(podman_rf, 'run_cli', side_effect=[self.answer(rf_info), self.answer(rf_ver)]):
            rf_flags = podman_rf.container_flags(mac_address='02:7a:74:aa:bb:cc')
            self.assertTrue(podman_rf.is_podman)
            self.assertFalse(podman_rf.is_rootless_podman)
            self.assertEqual(podman_rf.net_mode_for('local'), 'subnet')
            self.assertNotIn('--privileged', rf_flags)
            self.assertIn('label=disable', rf_flags)
            self.assertIn('--mac-address', rf_flags)
            self.assertIn('02:7a:74:aa:bb:cc', rf_flags)

    def test_docker_defaults_to_hardened_least_caps_and_conditional_selinux(self):
        env_clean = {k: v for k, v in os.environ.items() if k != 'ZT_CAPS'}
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {**env_clean, 'ZT_CONFIG': str(Path(tmp) / 'config')}, clear=True):
            # Non-SELinux, non-AppArmor Docker (Docker Desktop / seccomp-only)
            docker = engine.DockerEngine()
            docker_info = json.dumps({'SecurityOptions': ['name=seccomp,profile=builtin']})
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
            self.assertIn('--ulimit', flags)
            self.assertIn('nofile=1024:65536', flags)
            self.assertIn('core=0:0', flags)
            for sysctl_kv in (
                'net.ipv4.tcp_mtu_probing=1',
                'net.ipv4.tcp_keepalive_time=60',
                'net.ipv4.tcp_keepalive_intvl=15',
                'net.ipv4.tcp_keepalive_probes=4',
                'net.ipv4.tcp_retries2=8',
            ):
                self.assertIn(sysctl_kv, flags)
            self.assertNotIn('net.ipv4.conf.all.rp_filter=2', flags)
            self.assertNotIn('net.ipv4.conf.default.route_localnet=1', flags)

            # Rootless Docker adds rp_filter=2, atrust-only default.route_localnet=1, and clamps NOFILE.
            rl_docker = engine.DockerEngine()
            rl_info = json.dumps({'SecurityOptions': ['name=rootless', 'name=seccomp']})
            fake_res = mock.Mock(RLIMIT_NOFILE=7)
            fake_res.getrlimit.return_value = (1024, 4096)
            with mock.patch.object(rl_docker, 'run_cli', return_value=self.answer(rl_info)), \
                    mock.patch.object(engine.sys, 'platform', 'linux'), \
                    mock.patch.object(engine, 'resource', fake_res):
                rl_atrust = rl_docker.container_flags(profile='atrust')
                rl_ta = rl_docker.container_flags(profile='trustagent')
            self.assertIn('nofile=1024:4096', rl_atrust)
            self.assertIn('net.ipv4.conf.all.rp_filter=2', rl_atrust)
            self.assertIn('net.ipv4.conf.default.route_localnet=1', rl_atrust)
            self.assertNotIn('net.ipv4.conf.default.route_localnet=1', rl_ta)
            self.assertIn('/run:rw,nosuid,nodev,size=64m', flags)
            self.assertIn('/run/lock:rw,noexec,nosuid,nodev,size=16m', flags)
            self.assertNotIn('label=disable', flags)
            self.assertNotIn('apparmor=unconfined', flags)

            # Ubuntu/Debian AppArmor Docker adds apparmor=unconfined (needed for mount(2))
            aa_docker = engine.DockerEngine()
            aa_info = json.dumps({'SecurityOptions': ['name=apparmor', 'name=seccomp,profile=builtin']})
            with mock.patch.object(aa_docker, 'run_cli', return_value=self.answer(aa_info)):
                aa_flags = aa_docker.container_flags()
                self.assertTrue(aa_docker.has_apparmor)
            self.assertIn('--security-opt', aa_flags)
            self.assertIn('apparmor=unconfined', aa_flags)
            self.assertNotIn('label=disable', aa_flags)

            # SELinux Docker adds label=disable only when SELinux is active
            selinux_docker = engine.DockerEngine()
            se_info = json.dumps({'SecurityOptions': ['name=selinux', 'name=seccomp']})
            with mock.patch.object(selinux_docker, 'run_cli', return_value=self.answer(se_info)):
                se_flags = selinux_docker.container_flags()
                self.assertTrue(selinux_docker.has_selinux)
            self.assertIn('--security-opt', se_flags)
            self.assertIn('label=disable', se_flags)
            self.assertNotIn('apparmor=unconfined', se_flags)

            # Explicit CAPS=all still works as opt-in escape hatch without --cap-drop
            all_flags = docker.container_flags('all')
            self.assertNotIn('--cap-drop', all_flags)
            self.assertIn('--cap-add', all_flags)
            self.assertIn('ALL', all_flags)

            # Linux Docker Desktop / OrbStack / Colima / Lima / Rancher Desktop VM detection
            for vm_info in (
                {'OperatingSystem': 'Docker Desktop', 'SecurityOptions': ['name=seccomp']},
                {'OperatingSystem': 'OrbStack', 'SecurityOptions': ['name=seccomp']},
                {'Name': 'colima-default', 'SecurityOptions': ['name=seccomp']},
                {'Name': 'lima-docker', 'SecurityOptions': ['name=seccomp']},
                {'OperatingSystem': 'Rancher Desktop WSL Distro', 'SecurityOptions': ['name=seccomp']},
            ):
                vm_docker = engine.DockerEngine()
                with mock.patch.object(vm_docker, 'run_cli', return_value=self.answer(json.dumps(vm_info))), \
                        mock.patch.object(engine.sys, 'platform', 'linux'):
                    self.assertTrue(vm_docker.is_desktop_vm, vm_info)
                    self.assertFalse(vm_docker.is_linux_rootful, vm_info)

            # 256m shm-size, cross-arch 3g/3G memory bump, and deterministic MAC flags
            self.assertEqual(flags[flags.index('--shm-size') + 1], '256m')
            with mock.patch.object(engine.platform, 'machine', return_value='arm64'):
                native_flags = docker.container_flags(arch='arm64', mac_address='02:7a:74:01:02:03')
                cross_flags = docker.container_flags(arch='amd64', mac_address='02:7a:74:01:02:03')
            self.assertEqual(native_flags[native_flags.index('--memory') + 1], '2g')
            self.assertEqual(cross_flags[cross_flags.index('--memory') + 1], '3g')
            self.assertIn('--mac-address', native_flags)
            self.assertIn('02:7a:74:01:02:03', native_flags)

            # Apple Container keeps microVM default CAPS=all, supports CAPS=least, 3G cross-arch, and ,mac=
            apple = engine.AppleContainerEngine()
            apple.__dict__['_run_help_text'] = '--ulimit <spec> --network default,mac=xx:xx:xx:xx:xx:xx'
            self.assertEqual(apple.resolved_caps(), 'all')
            with mock.patch.object(engine.platform, 'machine', return_value='arm64'):
                a_native = apple.container_flags(arch='arm64', mac_address='02:7a:74:de:ad:be')
                a_cross = apple.container_flags(arch='amd64', mac_address='02:7a:74:de:ad:be')
            self.assertIn('ALL', a_native)
            self.assertEqual(a_native[a_native.index('--shm-size') + 1], '256m')
            self.assertEqual(a_native[a_native.index('--memory') + 1], '2G')
            self.assertEqual(a_cross[a_cross.index('--memory') + 1], '3G')
            self.assertIn('--network', a_native)
            self.assertIn('default,mac=02:7a:74:de:ad:be', a_native)
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

    def test_auto_engine_resolution_follows_running_then_reusable_images_then_container(self):
        atrust_ref = build.current_ref('atrust', 'arm64')
        ec_ref = build.current_ref('easyconnect', 'arm64')
        base_ref = build.current_ref('base', 'arm64')

        def make_fake(cli_name, installed=True, running=False, images=()):
            eng = mock.Mock(cli=cli_name, display_name=spec.ENGINE_NAMES[cli_name])
            eng.is_installed.return_value = installed
            eng.is_running.return_value = running
            eng.managed_images.return_value = list(images)
            return eng

        with tempfile.TemporaryDirectory() as tmp:
            clean_env = {k: v for k, v in os.environ.items() if not k.startswith('ZT_')}
            clean_env.update({'ZT_STATE': tmp, 'ZT_ARCH': 'arm64'})

            def run_resolve(c_eng, d_eng, extra_env=None):
                env = {**clean_env, **(extra_env or {})}
                with mock.patch.dict(os.environ, env, clear=True), \
                        mock.patch.object(
                            engine, '_engine_by_name',
                            side_effect=lambda n: c_eng if n == 'container' else d_eng,
                        ):
                    return engine.resolve_engine()

            # 1. Single installed engine (e.g. Linux/Windows without container): zero daemon probes.
            c1, d1 = make_fake('container', installed=False), make_fake('docker', installed=True)
            eng, _ = run_resolve(c1, d1)
            self.assertEqual(eng.cli, 'docker')
            d1.is_running.assert_not_called()

            # 2. Both installed, only docker running -> picks docker.
            eng, reason = run_resolve(
                make_fake('container', installed=True, running=False),
                make_fake('docker', installed=True, running=True),
            )
            self.assertEqual(eng.cli, 'docker')
            self.assertIn('only running', reason)

            # 3. Both installed, neither running -> prefers container.
            eng, reason = run_resolve(
                make_fake('container', installed=True, running=False),
                make_fake('docker', installed=True, running=False),
            )
            self.assertEqual(eng.cli, 'container')
            self.assertIn('none running', reason)

            # 4. Both running, docker has reusable current client image -> picks docker.
            eng, reason = run_resolve(
                make_fake('container', installed=True, running=True, images=()),
                make_fake('docker', installed=True, running=True, images=(atrust_ref,)),
            )
            self.assertEqual(eng.cli, 'docker')
            self.assertIn('reusing 1 current client image', reason)

            # 5. Both running, docker has 2 current clients vs container's 1 -> picks docker.
            eng, reason = run_resolve(
                make_fake('container', installed=True, running=True, images=(atrust_ref, base_ref)),
                make_fake('docker', installed=True, running=True, images=(atrust_ref, ec_ref, base_ref)),
            )
            self.assertEqual(eng.cli, 'docker')
            self.assertIn('reusing 2 current client images + base', reason)

            # 5b. Tied client count, base image breaks the tie clearly.
            eng, reason = run_resolve(
                make_fake('container', installed=True, running=True, images=(atrust_ref,)),
                make_fake('docker', installed=True, running=True, images=(atrust_ref, base_ref)),
            )
            self.assertEqual(eng.cli, 'docker')
            self.assertIn('reusing 1 current client image + base', reason)

            # 6. Both running, container has reusable base only vs docker's 0 -> picks container.
            eng, reason = run_resolve(
                make_fake('container', installed=True, running=True, images=(base_ref,)),
                make_fake('docker', installed=True, running=True, images=()),
            )
            self.assertEqual(eng.cli, 'container')
            self.assertIn('reusing current base image', reason)

            # 7. Both running and tied on reusable images -> prefers container.
            eng, reason = run_resolve(
                make_fake('container', installed=True, running=True, images=(atrust_ref,)),
                make_fake('docker', installed=True, running=True, images=(atrust_ref,)),
            )
            self.assertEqual(eng.cli, 'container')
            self.assertIn('preferred', reason)

            # 8. Saved engine overrides auto; ZT_ENGINE overrides saved.
            with mock.patch.dict(os.environ, clean_env, clear=True):
                config.save_engine('docker')
            eng, reason = run_resolve(
                make_fake('container', installed=True, running=True, images=(atrust_ref,)),
                make_fake('docker', installed=True, running=False),
            )
            self.assertEqual(eng.cli, 'docker')
            self.assertIn('saved in', reason)

            eng, reason = run_resolve(
                make_fake('container', installed=True, running=True),
                make_fake('docker', installed=True, running=True),
                extra_env={'ZT_ENGINE': 'container'},
            )
            self.assertEqual(eng.cli, 'container')
            self.assertEqual(reason, 'from ZT_ENGINE')

    def test_is_running_fails_fast_without_retries_and_managed_images_handles_podman_json(self):
        apple = engine.AppleContainerEngine()
        with mock.patch.object(engine.subprocess, 'run', return_value=self.answer('', 1, self.REFUSED)) as srun, \
                mock.patch.object(engine.time, 'sleep') as msleep:
            self.assertFalse(apple.is_running())
        self.assertEqual(srun.call_count, 1)
        msleep.assert_not_called()

        docker = engine.DockerEngine()
        with mock.patch.object(
            engine.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['docker', 'info'], 5)
        ):
            self.assertFalse(docker.is_running())

        # Podman emits a JSON array with `Names` rather than Docker NDJSON; errors never die().
        podman_json = json.dumps([
            {'Names': ['localhost/zt-atrust:2.5.16.20-arm64-0123456789ab']},
            {'Names': ['docker.io/library/ubuntu:24.04']},
        ])
        with mock.patch.object(
            docker, 'run_cli',
            side_effect=[self.answer('', 1), self.answer(podman_json, 0)],
        ):
            self.assertEqual(
                docker.managed_images('atrust'),
                ['localhost/zt-atrust:2.5.16.20-arm64-0123456789ab'],
            )

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
    def test_public_cli_exposes_only_the_nine_commands(self):
        with contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as ex:
            cli.main(['--help'])
        self.assertEqual(ex.exception.code, 0)
        help_text = out.getvalue()
        for expected in ('up', 'down', 'status', 'doctor', 'purge', 'accept', 'password', 'use', 'update'):
            self.assertRegex(help_text, rf'\b{expected}\b')
        for hidden in ('build', 'verify', 'prune', 'socks', 'logs', 'exec', 'shot', 'init', 'bridge'):
            self.assertNotRegex(help_text, rf'^\s+{hidden}\b', f'{hidden} must not be exposed')

    def test_use_command_persists_switches_and_clears_to_auto(self):
        with tempfile.TemporaryDirectory() as tmp:
            base_env = {k: v for k, v in os.environ.items() if not k.startswith('ZT_')}
            base_env['ZT_STATE'] = tmp
            with mock.patch.dict(os.environ, base_env, clear=True), \
                    mock.patch.object(cli.shutil, 'which', side_effect=lambda c: '/usr/bin/docker' if c == 'docker' else None):
                # Reject installing/saving an engine not on PATH
                with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                    cli.main(['use', 'container'])
                self.assertIn('Apple Container is not installed', err.getvalue())

                # Persist docker
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['use', 'docker'])
                self.assertIn('engine set to docker', out.getvalue())
                self.assertEqual(config.configured_engine()[0], 'docker')

                # Show active engine
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['use'])
                self.assertIn('docker (Docker; saved in', out.getvalue())

                # Clear back to auto
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['use', 'auto'])
                self.assertIn('engine set to auto', out.getvalue())
                self.assertEqual(config.configured_engine(), (None, 'auto'))

                # Refuse while ZT_ENGINE env override is set (empty ZT_ENGINE counts as unset)
                with mock.patch.dict(os.environ, {'ZT_ENGINE': ''}), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['use', 'docker'])
                self.assertIn('engine set to docker', out.getvalue())

                with mock.patch.dict(os.environ, {'ZT_ENGINE': 'docker'}), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    cli.main(['use', 'auto'])
                self.assertIn('ZT_ENGINE is set in the environment', err.getvalue())

                # Warn when switching while a bridge is still running on the other engine
                with mock.patch.object(
                    cli, 'bridge_record',
                    side_effect=lambda p: (999, 'container', 'local', '', 2) if p == 'atrust' else (None,) * 5,
                ), contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()) as err:
                    cli.main(['use', 'docker'])
                self.assertIn('atrust still has a running bridge on container', err.getvalue())

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

                # Cannot --clear while accept mode is 'all' (fail-closed).
                with contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    cli.main(['password', '--clear'])
                self.assertIn('cannot clear password while accept mode is "all"', err.getvalue())
                self.assertEqual(config.setting('VNC_PW'), 's3cret')

                # Switching back to local keeps existing password (orthogonal) until --clear.
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['accept', 'local'])
                self.assertEqual(config.accept_mode(), 'local')
                self.assertIn('127.0.0.1', out.getvalue())
                self.assertEqual(config.setting('VNC_PW'), 's3cret')
                self.assertEqual(config.auth_password(), 's3cret')

                # --clear removes VNC_PW atomically while keeping ACCEPT intact.
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['password', '--clear'])
                self.assertIn('Password cleared', out.getvalue())
                self.assertEqual(config.setting('VNC_PW'), '')
                self.assertEqual(config.accept_mode(), 'local')
                self.assertEqual(config.auth_password(), '')
                self.assertEqual(os.listdir(tmp), ['config'])
                if os.name != 'nt':
                    self.assertEqual(cfg.stat().st_mode & 0o777, 0o600)

                # Calling --clear when no password is set is clean & idempotent.
                with contextlib.redirect_stdout(io.StringIO()) as out:
                    cli.main(['password', '--clear'])
                self.assertIn('No password is set.', out.getvalue())

                # --clear refuses if ZT_VNC_PW comes from environment.
                with mock.patch.dict(os.environ, {'ZT_VNC_PW': 's3cret'}), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    cli.main(['password', '--clear'])
                self.assertIn('ZT_VNC_PW is set in the environment', err.getvalue())

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

    def test_ensure_container_attaches_persistent_volume_and_binds_loopback_in_lan_and_all_modes(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_STATE': tmp}):
            seen_macs = []
            for mode in ('lan', 'all'):
                eng = mock.Mock(cli='container', display_name='Apple Container')
                eng.inspect.return_value = None
                eng.port_holders.return_value = None
                eng.container_state.return_value = 'running'
                eng.fingerprint.return_value = 'abc123'
                with contextlib.redirect_stdout(io.StringIO()):
                    problem = cli.ensure_container(eng, 'atrust', {'ZT_AUTH': '0'}, mode=mode, arch='amd64')
                self.assertIsNone(problem, mode)
                eng.ensure_volume.assert_called_once_with('zt-state-atrust', 'atrust')
                eng.run_container.assert_called_once()
                args = eng.run_container.call_args
                self.assertEqual(args.args[3], spec.desktop_backend_port('atrust'))
                self.assertEqual(args.kwargs['bind_host'], '127.0.0.1')
                self.assertEqual(args.kwargs['arch'], 'amd64')
                self.assertEqual(args.kwargs['volume'], 'zt-state-atrust')
                mac = args.kwargs['mac_address']
                self.assertRegex(mac, r'^02:7a:74:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$')
                self.assertEqual(eng.fingerprint.call_args.kwargs['mac_address'], mac)
                seen_macs.append(mac)
            # Same (profile, engine) MUST reuse the exact same MAC across recreates.
            self.assertEqual(seen_macs[0], seen_macs[1])
            id_file = config.identity_file('atrust')
            self.assertTrue(id_file.is_file())
            if os.name != 'nt':
                self.assertEqual(id_file.stat().st_mode & 0o777, 0o600)

    def test_up_exits_nonzero_on_bridge_failure_and_status_shows_vpn_sso_and_disk_warning(self):
        eng = mock.Mock(cli='docker', display_name='Docker', is_rootless_podman=False, is_linux_rootful=False)
        eng.resolved_caps.return_value = 'least'
        eng.net_mode_for.return_value = 'gateway'
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / 'config'
            st = Path(tmp) / 'state'
            env = {k: v for k, v in os.environ.items() if not k.startswith('ZT_')}
            env.update({'ZT_CONFIG': str(cfg), 'ZT_STATE': str(st), 'ZT_ACCEPT': 'local'})
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(cli, 'make_engine', return_value=eng), \
                    mock.patch.object(cli, 'ensure_image'), \
                    mock.patch.object(cli, 'ensure_container', return_value=None), \
                    mock.patch.object(cli, 'bridge_start', return_value='port 16902 held by foo'), \
                    mock.patch.object(cli, 'cmd_status'), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()) as err, \
                    self.assertRaises(SystemExit) as ex:
                cli.cmd_up(argparse.Namespace(target='trustagent'))
            self.assertEqual(ex.exception.code, 1)
            self.assertIn('port 16902 held by foo', err.getvalue())

            # cmd_status renders vpn column, active SSO URL, and >=85% disk warning from health-<profile>.json
            now = int(cli.time.time())
            with mock.patch.dict(os.environ, env, clear=True):
                config.write_private_file(
                    config.health_file('trustagent'),
                    json.dumps({
                        'vpn': 'connected', 'iface': 'vnic0', 'updated_at': now,
                        'state_used_pct': 88, 'state_avail_mb': 240,
                    }),
                )
                config.write_private_file(
                    config.health_file('atrust'),
                    json.dumps({
                        'vpn': 'sso-pending', 'updated_at': now,
                        'sso_url': 'https://sso.corp.example/login', 'sso_ts': now,
                        'callback_ports': [54631],
                    }),
                )
                eng.inspect.side_effect = lambda n: {
                    'status': {'state': 'running'},
                    'configuration': {'labels': {'zt.image': build.current_ref(n[3:], 'arm64')}},
                } if n in ('zt-trustagent', 'zt-atrust') else None
                with mock.patch.object(cli, 'target_arch', return_value='arm64'), \
                        mock.patch.object(cli, 'bridge_record', return_value=(None,) * 5), \
                        mock.patch.object(cli, 'socks_any_listener', return_value=False), \
                        contextlib.redirect_stdout(io.StringIO()) as out, \
                        contextlib.redirect_stderr(io.StringIO()) as err:
                    cli.cmd_status(argparse.Namespace(target='all'), engine=eng)
            rendered = out.getvalue()
            self.assertIn('vpn', rendered)
            self.assertIn('connected (vnic0)', rendered)
            self.assertIn('sso-pending', rendered)
            self.assertIn('https://sso.corp.example/login', rendered)
            self.assertIn('127.0.0.1:54631', rendered)
            self.assertIn('state volume 88% full (240 MB free)', err.getvalue())

    def test_doctor_linux_and_macos_host_prechecks(self):
        # Linux prechecks: missing /dev/net/tun, apparmor userns=1 on rootless, missing binfmt F flag
        seen = []

        def record(name, good, detail=''):
            seen.append((name, good, detail))

        eng_rl = mock.Mock(is_rootless=True)
        with tempfile.TemporaryDirectory() as tmp:
            fake_aa = Path(tmp) / 'aa'
            fake_aa.write_text('1\n', encoding='utf-8')
            fake_cg = Path(tmp) / 'cgroup.controllers'
            fake_cg.write_text('cpu io\n', encoding='utf-8')
            fake_binfmt = Path(tmp) / 'binfmt'
            fake_binfmt.mkdir()
            (fake_binfmt / 'qemu-x86_64').write_text('enabled\nflags: OC\n', encoding='utf-8')

            real_path = cli.Path

            def fake_path(p):
                s = str(p)
                if s == '/dev/net/tun':
                    return Path(tmp) / 'missing-tun'
                if s == '/proc/sys/kernel/apparmor_restrict_unprivileged_userns':
                    return fake_aa
                if s.endswith('/cgroup.controllers'):
                    return fake_cg
                if s == '/proc/sys/fs/binfmt_misc':
                    return fake_binfmt
                return real_path(p)

            with mock.patch.object(cli, 'Path', side_effect=fake_path), \
                    mock.patch.object(cli.platform, 'machine', return_value='aarch64'):
                cli._check_linux_host_prechecks(eng_rl, 'amd64', record)

        by_name = {n: (g, d) for n, g, d in seen}
        self.assertFalse(by_name['/dev/net/tun'][0])
        self.assertFalse(by_name['apparmor userns'][0])
        self.assertFalse(by_name['cgroup v2 delegate'][0])
        self.assertFalse(by_name['binfmt (amd64)'][0])

        # macOS cross-arch Rosetta check
        mac_seen = []
        with mock.patch.object(cli.platform, 'machine', return_value='arm64'), \
                mock.patch.object(cli, 'Path', side_effect=lambda p: mock.Mock(exists=lambda: False)):
            cli._check_macos_cross_arch('amd64', lambda n, g, d='': mac_seen.append((n, g, d)))
        self.assertEqual(len(mac_seen), 1)
        self.assertEqual(mac_seen[0][0], 'rosetta (amd64)')
        self.assertFalse(mac_seen[0][1])

    def test_ensure_container_treats_stopped_as_immediate_exit(self):
        for terminal_state in ('exited', 'dead', 'stopped'):
            eng = mock.Mock(cli='container', display_name='Apple Container')
            eng.inspect.return_value = None
            eng.port_holders.return_value = None
            eng.container_state.return_value = terminal_state
            eng.fingerprint.return_value = 'abc123'
            with contextlib.redirect_stdout(io.StringIO()):
                problem = cli.ensure_container(eng, 'trustagent', {'ZT_AUTH': '0'}, mode='local', arch='arm64')
            self.assertIsNotNone(problem, terminal_state)
            self.assertIn('exited as soon as it started', problem)

    def test_doctor_checks_orthogonal_password_across_all_accept_modes(self):
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
                self.assertIn('OK   password              not set (passwordless)', out.getvalue())
                self.assertIn('OK   target platform', out.getvalue())

                with mock.patch.object(cli, 'make_engine', return_value=eng), \
                        mock.patch.dict(os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': mode, 'ZT_VNC_PW': 's3cret'}), \
                        contextlib.redirect_stdout(io.StringIO()) as out, \
                        self.assertRaises(SystemExit):
                    cli.cmd_doctor(argparse.Namespace())
                self.assertIn('OK   password              set (required on desktop and SOCKS5', out.getvalue())

                with mock.patch.object(cli, 'make_engine', return_value=eng), \
                        mock.patch.dict(os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': mode, 'ZT_VNC_PW': 'bad'}), \
                        contextlib.redirect_stdout(io.StringIO()) as out, \
                        self.assertRaises(SystemExit):
                    cli.cmd_doctor(argparse.Namespace())
                self.assertIn('FAIL password              must be 6 to 128 characters (got 3)', out.getvalue())

            with mock.patch.object(cli, 'make_engine', return_value=eng), \
                    mock.patch.dict(os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'all', 'ZT_VNC_PW': ''}), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit):
                cli.cmd_doctor(argparse.Namespace())
            self.assertIn('FAIL password              required for accept all', out.getvalue())

            with mock.patch.object(cli, 'make_engine', return_value=eng), \
                    mock.patch.dict(os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'all', 'ZT_VNC_PW': 'strong-passphrase-1234'}), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit):
                cli.cmd_doctor(argparse.Namespace())
            self.assertIn('OK   password              set (required on desktop and SOCKS5', out.getvalue())

            with mock.patch.object(cli, 'make_engine', return_value=eng), \
                    mock.patch.dict(os.environ, {'ZT_CONFIG': cfg, 'ZT_ACCEPT': 'all', 'ZT_VNC_PW': 'a' * 129}), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    self.assertRaises(SystemExit):
                cli.cmd_doctor(argparse.Namespace())
            self.assertIn('FAIL password              must be 6 to 128 characters (got 129)', out.getvalue())

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
                mock.patch.dict(os.environ, {'ZT_CACHE': tmp, 'ZT_STATE': str(Path(tmp) / 'state')}), \
                mock.patch.object(cli, 'make_engine', return_value=eng), \
                mock.patch.object(cli, 'bridge_stop') as bstop:
            cache = Path(tmp)
            (cache / 'build' / 'atrust-arm64-1234').mkdir(parents=True)
            (cache / 'build' / 'base-arm64-9999').mkdir(parents=True)
            (cache / 'blobs').mkdir(parents=True)
            (cache / 'blobs' / atrust_sha).write_bytes(b'atrust-deb')
            (cache / 'blobs' / base_sha).write_bytes(b'kasm-deb')
            config.ensure_identity_mac('atrust', 'container')
            config.write_private_file(config.health_file('atrust'), '{"vpn":"connected"}\n')

            with contextlib.redirect_stdout(io.StringIO()) as out:
                cli.main(['purge', 'atrust'])
            bstop.assert_called_once_with('atrust', engine_cli='container')
            eng.run_cli.assert_any_call('rm', '-f', 'zt-atrust', quiet=True)
            eng.remove_volume.assert_any_call('zt-state-atrust')
            eng.run_cli.assert_any_call('image', 'rm', 'localhost/zt-atrust:1.0-arm64-abc', quiet=True, check=False)
            self.assertFalse((cache / 'build' / 'atrust-arm64-1234').exists())
            self.assertFalse((cache / 'blobs' / atrust_sha).exists())
            self.assertFalse(config.identity_file('atrust').exists())
            self.assertFalse(config.health_file('atrust').exists())
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

    def test_two_boot_stateful_verify_and_cli_entry(self):
        # 1. compare_identity_snapshots catches drift, missing fields, and wrong MAC
        snap1 = {
            'machine_id': '0123456789abcdef0123456789abcdef',
            'dbus_machine_id': '0123456789abcdef0123456789abcdef',
            'smbios_sha256': 'c' * 64,
            'has_dmi_id': True,
            'product_uuid': '11111111-2222-4333-8444-555555555555',
            'product_serial': 'ZT-ABCDEF123456',
            'eth0_mac': '02:7a:74:11:22:33',
            'tls_cert_sha256': 'a' * 64,
        }
        err, detail = verify.compare_identity_snapshots(snap1, dict(snap1), expected_mac='02:7a:74:11:22:33')
        self.assertIsNone(err)
        self.assertIn('2-boot volume persisted', detail)
        drifted = {**snap1, 'tls_cert_sha256': 'b' * 64}
        err, _ = verify.compare_identity_snapshots(snap1, drifted, expected_mac='02:7a:74:11:22:33')
        self.assertIn('tls_cert_sha256 drifted', err)
        err, _ = verify.compare_identity_snapshots(snap1, dict(snap1), expected_mac='02:7a:74:aa:bb:cc')
        self.assertIn('eth0_mac=', err)

        # 2. verify() creates temp volume, boots twice with identical volume+MAC, and cleans both up
        eng = mock.Mock(cli='docker', is_rootless_podman=False)
        eng.net_mode_for.return_value = 'gateway'
        eng.image_exists.return_value = True
        eng.run_cli.return_value = mock.Mock(returncode=0)
        run_calls = []

        def fake_run(name, ref, env, port, labels, **kwargs):
            run_calls.append((name, ref, kwargs.get('volume'), kwargs.get('mac_address')))

        eng.run_container.side_effect = fake_run

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {'ZT_CONFIG': str(Path(tmp) / 'cfg'), 'ZT_ACCEPT': 'local'}), \
                mock.patch.object(verify, 'free_port', return_value=19999), \
                mock.patch.object(verify, 'wait_for_desktop', return_value=(True, 200)), \
                mock.patch.object(verify, 'guest_report', return_value=[('units', 'ok', '')]), \
                mock.patch.object(verify, 'mux_e2e_holds', return_value=(None, 'ok')), \
                mock.patch.object(verify, 'host_only_holds', return_value=(None, 'ok')), \
                mock.patch.object(verify, '_random_verify_mac', return_value='02:7a:74:11:22:33'), \
                mock.patch.object(verify, 'capture_identity_snapshot', return_value=snap1), \
                contextlib.redirect_stdout(io.StringIO()) as out:
            failures = verify.verify(eng, 'trustagent', mode='local', arch='arm64')

        self.assertEqual(failures, [])
        self.assertEqual(len(run_calls), 2)
        self.assertEqual(run_calls[0][2], run_calls[1][2])
        self.assertTrue(run_calls[0][2].startswith('zt-verify-state-trustagent-'))
        self.assertEqual(run_calls[0][3], '02:7a:74:11:22:33')
        self.assertEqual(run_calls[1][3], '02:7a:74:11:22:33')
        eng.ensure_volume.assert_called_once_with(run_calls[0][2], 'trustagent')
        eng.remove_volume.assert_called_once_with(run_calls[0][2])
        self.assertIn('ok   persistence:', out.getvalue())

        # 3. python3 -m zt.verify CLI argument parser & exit code contract
        parsed = verify.parse_args(['--profile', 'atrust', '--accept', 'all', '--arch', 'amd64', '--build', '--keep'])
        self.assertEqual((parsed.profile, parsed.mode, parsed.arch, parsed.build, parsed.keep),
                         ('atrust', 'all', 'amd64', True, True))
        defaults = verify.parse_args([])
        self.assertEqual((defaults.profile, defaults.mode, defaults.arch, defaults.build, defaults.keep),
                         ('trustagent', None, None, False, False))

        with mock.patch.object(verify, 'make_engine', return_value=eng), \
                mock.patch.object(verify, 'build') as mbuild, \
                mock.patch.object(verify, 'verify', return_value=[]) as mver, \
                self.assertRaises(SystemExit) as ex:
            verify.main(['--profile', 'trustagent', '--accept', 'local', '--arch', 'arm64', '--build'])
        self.assertEqual(ex.exception.code, 0)
        mbuild.assert_called_once_with(eng, 'trustagent', arch='arm64')
        mver.assert_called_once_with(eng, 'trustagent', mode='local', arch='arm64', keep=False)


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

    def test_zt_update_verifies_sha256_smoke_tests_and_replaces_atomically(self):
        # Build a tiny runnable synthetic zipapp claiming version 9.9.9.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('__main__.py', 'print("zt 9.9.9")\n')
        new_payload = b'#!/usr/bin/env python3\n' + buf.getvalue()
        good_sha = hashlib.sha256(new_payload).hexdigest()

        old_buf = io.BytesIO()
        with zipfile.ZipFile(old_buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('__main__.py', f'print("zt {VERSION}")\n')
        old_payload = b'#!/usr/bin/env python3\n' + old_buf.getvalue()

        state = {'tag': 'v9.9.9', 'tamper': False, 'prerelease': False, 'rate_limit': False, 'dl_paths': []}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                base = f'http://127.0.0.1:{self.server.server_port}'
                if self.path == '/repos/ArakawaHenri/zt/releases/latest':
                    if state['rate_limit']:
                        self.send_response(403)
                        self.send_header('X-RateLimit-Remaining', '0')
                        self.end_headers()
                        return
                    body = json.dumps({
                        'tag_name': state['tag'],
                        'draft': False,
                        'prerelease': state['prerelease'],
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
                elif self.path in (
                    '/dl/zt', '/dl/zt.pyz',
                    f'/ArakawaHenri/zt/releases/download/{state["tag"]}/zt',
                    f'/ArakawaHenri/zt/releases/download/{state["tag"]}/zt.pyz',
                ):
                    state['dl_paths'].append(self.path)
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(new_payload)))
                    self.end_headers()
                    self.wfile.write(new_payload)
                elif self.path in (
                    '/dl/SHA256SUMS',
                    f'/ArakawaHenri/zt/releases/download/{state["tag"]}/SHA256SUMS',
                ):
                    state['dl_paths'].append(self.path)
                    digest = ('0' * 64) if state['tamper'] else good_sha
                    body = f'{digest}  ./zt\n{digest}  *zt.pyz\n'.encode('utf-8')
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
            # Helpers: version normalization & URL scheme guard
            self.assertEqual(update._compare_versions((1, 2), (1, 2, 0)), 0)
            self.assertIsNone(update.parse_version('v1.2.0-rc1'))
            self.assertIsNone(update.parse_version('vv1.2.0'))
            with mock.patch.dict(os.environ, {}, clear=True), \
                    contextlib.redirect_stderr(io.StringIO()) as err, \
                    self.assertRaises(SystemExit):
                update._validate_url('file:///etc/passwd')
            self.assertIn('unsupported URL scheme', err.getvalue())

            with tempfile.TemporaryDirectory() as tmp:
                bin_name = 'zt.pyz' if os.name == 'nt' else 'zt'
                target = Path(tmp) / bin_name
                target.write_bytes(old_payload)
                if os.name != 'nt':
                    target.chmod(0o755)
                clean_env = {k: v for k, v in os.environ.items() if not k.startswith('ZT_')}
                api_env = {**clean_env, 'ZT_API_BASE': base_url}

                # 1. Source checkout refused for install, allowed for --check
                with mock.patch.dict(os.environ, api_env, clear=True), \
                        mock.patch.object(update, 'zipapp_archive', return_value=None):
                    with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                        update.run_update(check_only=False)
                    self.assertIn('source checkout', err.getvalue())
                    with contextlib.redirect_stdout(io.StringIO()) as out:
                        self.assertTrue(update.run_update(check_only=True))
                    self.assertIn('update available', out.getvalue())

                # 2. Tampered SHA256 rejected without modifying existing binary
                state['tamper'] = True
                with mock.patch.dict(os.environ, api_env, clear=True), \
                        mock.patch.object(update, 'zipapp_archive', return_value=str(target)), \
                        contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    update.run_update(check_only=False)
                self.assertIn('SHA256 mismatch', err.getvalue())
                self.assertEqual(target.read_bytes(), old_payload)
                self.assertEqual(os.listdir(tmp), [bin_name])
                state['tamper'] = False

                # 3. Prerelease, non-semver tag, and GitHub rate-limit errors rejected cleanly
                state['prerelease'] = True
                with mock.patch.dict(os.environ, api_env, clear=True), \
                        mock.patch.object(update, 'zipapp_archive', return_value=str(target)), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    update.run_update(check_only=False)
                self.assertIn('not a stable release', err.getvalue())
                state['prerelease'] = False

                state['tag'] = 'v9.9.9-rc1'
                with mock.patch.dict(os.environ, api_env, clear=True), \
                        mock.patch.object(update, 'zipapp_archive', return_value=str(target)), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    update.run_update(check_only=False)
                self.assertIn('not a stable semantic version', err.getvalue())
                state['tag'] = 'v9.9.9'

                state['rate_limit'] = True
                with mock.patch.dict(os.environ, api_env, clear=True), \
                        mock.patch.object(update, 'zipapp_archive', return_value=str(target)), \
                        contextlib.redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit):
                    update.run_update(check_only=True)
                self.assertIn('rate limit exceeded', err.getvalue())
                state['rate_limit'] = False

                # 4. Valid update using default browser_download_url (without ZT_DOWNLOAD_BASE)
                state['dl_paths'].clear()
                with mock.patch.dict(os.environ, api_env, clear=True), \
                        mock.patch.object(update, 'zipapp_archive', return_value=str(target)), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertTrue(update.run_update(check_only=False))
                self.assertIn(f'updated zt: {VERSION} -> 9.9.9', out.getvalue())
                self.assertEqual(state['dl_paths'], ['/dl/SHA256SUMS', f'/dl/{bin_name}'])
                self.assertEqual(target.read_bytes(), new_payload)
                self.assertEqual(os.listdir(tmp), [bin_name])
                if os.name != 'nt':
                    self.assertTrue(target.stat().st_mode & 0o111)
                ver = subprocess.run([sys.executable, str(target), '--version'], capture_output=True, text=True, check=True)
                self.assertEqual(ver.stdout.strip(), 'zt 9.9.9')

                # 4b. Explicit ZT_DOWNLOAD_BASE overrides release asset browser_download_url
                state['dl_paths'].clear()
                target.write_bytes(old_payload)
                mirror_env = {**api_env, 'ZT_DOWNLOAD_BASE': base_url}
                with mock.patch.dict(os.environ, mirror_env, clear=True), \
                        mock.patch.object(update, 'zipapp_archive', return_value=str(target)), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertTrue(update.run_update(check_only=False))
                self.assertEqual(
                    state['dl_paths'],
                    [
                        '/ArakawaHenri/zt/releases/download/v9.9.9/SHA256SUMS',
                        f'/ArakawaHenri/zt/releases/download/v9.9.9/{bin_name}',
                    ],
                )

                # 5. Already up to date -> no-op
                state['tag'] = f'v{VERSION}'
                with mock.patch.dict(os.environ, api_env, clear=True), \
                        mock.patch.object(update, 'zipapp_archive', return_value=str(target)), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    self.assertFalse(update.run_update(check_only=False))
                self.assertIn('already up to date', out.getvalue())
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == '__main__':
    unittest.main()
