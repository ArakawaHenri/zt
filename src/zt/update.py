"""Self-updater for standalone zt zipapp binaries against GitHub stable releases."""
import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from zt import VERSION
from zt.config import die, say
from zt.resources import zipapp_archive

REPO = 'ArakawaHenri/zt'
DEFAULT_API_BASE = 'https://api.github.com'
DEFAULT_DOWNLOAD_BASE = 'https://github.com'
MAX_BINARY_BYTES = 50 * 1024 * 1024


def _repo():
    return (os.environ.get('ZT_REPO') or REPO).strip('/')


def _strip_v(raw):
    text = (raw or '').strip()
    return text[1:] if text.startswith(('v', 'V')) else text


def parse_version(raw):
    """Parse a semver string like 'v1.1.1' into a comparable integer tuple, or None."""
    text = _strip_v(raw)
    parts = text.split('.')
    if not parts or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def _compare_versions(a, b):
    """Compare two version tuples with trailing-zero normalization (-1, 0, or 1)."""
    n = max(len(a), len(b))
    pa = a + (0,) * (n - len(a))
    pb = b + (0,) * (n - len(b))
    return (pa > pb) - (pa < pb)


def parse_sha256sums(text, asset_name):
    """Extract the 64-hex SHA256 digest for `asset_name` from a SHA256SUMS file."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0].lower(), parts[1].strip().lstrip('*')
        if name.startswith('./'):
            name = name[2:]
        if name == asset_name and len(digest) == 64:
            try:
                int(digest, 16)
            except ValueError:
                continue
            return digest
    return None


def _validate_url(url):
    allow_http = bool(os.environ.get('ZT_API_BASE') or os.environ.get('ZT_DOWNLOAD_BASE'))
    allowed = ('https://', 'http://') if allow_http else ('https://',)
    if not isinstance(url, str) or not url.startswith(allowed):
        die(f'refusing unsupported URL scheme: {url!r}')


def _http_get_bytes(url, accept=None, timeout=60, max_bytes=None, github_api=False):
    _validate_url(url)
    headers = {'User-Agent': f'zt/{VERSION}'}
    if accept:
        headers['Accept'] = accept
    if github_api:
        headers['X-GitHub-Api-Version'] = '2022-11-28'
        if url.startswith(DEFAULT_API_BASE + '/'):
            token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
            if token:
                headers['Authorization'] = f'Bearer {token}'
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read(max_bytes + 1) if max_bytes is not None else resp.read()
            if max_bytes is not None and len(data) > max_bytes:
                die(f'response from {url} exceeded size limit')
            return data
    except urllib.error.HTTPError as err:
        if github_api and err.code == 403 and err.headers and err.headers.get('X-RateLimit-Remaining') == '0':
            die('GitHub API rate limit exceeded; retry later or set GITHUB_TOKEN')
        die(f'failed to fetch {url}: {err}')
    except (OSError, urllib.error.URLError) as err:
        die(f'failed to fetch {url}: {err}')


def fetch_latest_release():
    """Fetch latest stable GitHub release metadata (rejecting drafts & prereleases)."""
    api_base = (os.environ.get('ZT_API_BASE') or DEFAULT_API_BASE).rstrip('/')
    url = f'{api_base}/repos/{_repo()}/releases/latest'
    raw = _http_get_bytes(
        url,
        accept='application/vnd.github+json',
        timeout=30,
        max_bytes=1 << 20,
        github_api=True,
    )
    try:
        release = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError) as err:
        die(f'invalid release metadata from {url}: {err}')
    if not isinstance(release, dict) or not release.get('tag_name'):
        die(f'no stable release found at {url}')
    if release.get('draft') or release.get('prerelease'):
        die(f'latest release {release.get("tag_name")} is not a stable release')
    return release


def _asset_url(release, tag, name):
    custom_dl = os.environ.get('ZT_DOWNLOAD_BASE')
    if custom_dl:
        return f'{custom_dl.rstrip("/")}/{_repo()}/releases/download/{tag}/{name}'
    for asset in release.get('assets') or ():
        if isinstance(asset, dict) and asset.get('name') == name and asset.get('browser_download_url'):
            return asset['browser_download_url']
    return f'{DEFAULT_DOWNLOAD_BASE}/{_repo()}/releases/download/{tag}/{name}'


def _download_to_file(url, dest_path, timeout=120, max_bytes=MAX_BINARY_BYTES):
    _validate_url(url)
    req = urllib.request.Request(url, headers={'User-Agent': f'zt/{VERSION}'})
    hasher = hashlib.sha256()
    written = 0
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp, dest_path.open('wb') as out:
            while chunk := resp.read(1 << 16):
                written += len(chunk)
                if max_bytes is not None and written > max_bytes:
                    die(f'download from {url} exceeded size limit ({max_bytes} bytes)')
                out.write(chunk)
                hasher.update(chunk)
            out.flush()
            os.fsync(out.fileno())
    except (OSError, urllib.error.URLError) as err:
        die(f'failed to download {url}: {err}')
    return hasher.hexdigest()


def _permission_hint(path):
    if os.name == 'nt':
        return f'cannot write to {path} (permission denied); run from an elevated prompt or update via install.ps1'
    return f'cannot write to {path} (permission denied); re-run with sudo or update via install.sh'


def _replace_binary(tmp, target):
    """Atomically replace `target` with `tmp` (handling Windows in-use rename fallback)."""
    if os.name == 'nt':
        old = target.with_name(target.name + '.old')
        with contextlib.suppress(OSError):
            old.unlink()
        try:
            os.replace(tmp, target)
            return
        except PermissionError:
            try:
                os.replace(target, old)
            except OSError as err:
                die(f'cannot replace {target} while running ({err}); update with install.ps1')
            try:
                os.replace(tmp, target)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.replace(old, target)
                raise
            return

    mode = 0o755
    with contextlib.suppress(OSError):
        mode = (target.stat().st_mode & 0o777) | 0o100
    os.chmod(tmp, mode)
    try:
        os.replace(tmp, target)
    except PermissionError:
        die(_permission_hint(target))


def run_update(check_only=False):
    """Check for (and optionally install) the latest stable zt release."""
    archive = zipapp_archive()
    if not check_only and not archive:
        die('zt is running from a source checkout; update with "git pull && make install"')

    release = fetch_latest_release()
    tag = str(release['tag_name']).strip()
    remote_ver = _strip_v(tag)
    local_parsed = parse_version(VERSION)
    remote_parsed = parse_version(tag)
    if remote_parsed is None:
        die(f'latest release {tag!r} is not a stable semantic version')

    if local_parsed is not None:
        cmp = _compare_versions(remote_parsed, local_parsed)
        if cmp == 0:
            say(f'zt {VERSION} is already up to date ({tag}).')
            return False
        if cmp < 0:
            say(f'zt {VERSION} is newer than latest stable release {tag}.')
            return False
    elif remote_ver == VERSION:
        say(f'zt {VERSION} is already up to date ({tag}).')
        return False

    if check_only:
        say(f'update available: zt {VERSION} -> {tag} (run "zt update" to install)')
        return True

    target = Path(archive).resolve()
    asset_name = 'zt.pyz' if (os.name == 'nt' or target.suffix.lower() == '.pyz') else 'zt'

    sums_url = _asset_url(release, tag, 'SHA256SUMS')
    sums_text = _http_get_bytes(sums_url, timeout=30, max_bytes=64 * 1024).decode('utf-8', errors='replace')
    expected_sha = parse_sha256sums(sums_text, asset_name)
    if not expected_sha:
        die(f'SHA256SUMS for {tag} does not contain a valid digest for {asset_name}')

    bin_url = _asset_url(release, tag, asset_name)
    try:
        fd, tmp_name = tempfile.mkstemp(prefix='.zt-update-', dir=target.parent)
        os.close(fd)
    except PermissionError:
        die(_permission_hint(target.parent))
    tmp = Path(tmp_name)
    try:
        say(f'downloading zt {tag} ({asset_name})...')
        actual_sha = _download_to_file(bin_url, tmp)
        if actual_sha != expected_sha:
            die(f'SHA256 mismatch for {asset_name}: expected {expected_sha}, got {actual_sha}')

        # Smoke-test the downloaded zipapp before swapping it into place.
        try:
            probe = subprocess.run(
                [sys.executable, str(tmp), '--version'],
                capture_output=True, text=True, check=False, timeout=15,
            )
        except (OSError, subprocess.TimeoutExpired) as err:
            die(f'downloaded {asset_name} failed self-check: {err}')
        if probe.returncode != 0 or probe.stdout.strip() != f'zt {remote_ver}':
            detail = (probe.stderr or '').strip()
            extra = f'; stderr: {detail.splitlines()[-1]}' if detail else ''
            die(
                f'downloaded {asset_name} failed version check '
                f'(exit {probe.returncode}, stdout {probe.stdout.strip()!r}, '
                f'expected {f"zt {remote_ver}"!r}{extra})'
            )

        _replace_binary(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise

    say(f'updated zt: {VERSION} -> {remote_ver} ({target})')
    say('Run "zt up" to apply any updated images or bridges.')
    return True
