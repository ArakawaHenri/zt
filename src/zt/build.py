"""Content-addressed multi-arch image build DAG, layered overlays, and SHA256 blob cache."""
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from zt import VERSION
from zt.config import cache_dir, die, say, target_arch, warn
from zt.resources import overlay_files
from zt.spec import BASE, blobs_for, image_ref, platform_for, spec_args_for, spec_of

DOWNLOAD_RETRIES = 3


def overlay_for(spec):
    """Layered overlay files for `spec`, applied in declared order.

    Later layers override earlier ones if paths overlap; each image sees only
    its own layer chain (so editing easyconnect never invalidates atrust).
    """
    layers = spec.get('overlays') or ()
    if not layers:
        return {}
    all_files = overlay_files()
    merged = {}
    for layer in layers:
        prefix = layer.rstrip('/') + '/'
        for name, content in all_files.items():
            if name.startswith(prefix):
                merged[name[len(prefix):]] = content
    return merged


def base_digest(arch=None):
    """Content digest of BASE alone for `arch`."""
    return content_hash(BASE, arch=arch)


def build_args(spec, arch=None):
    arch = arch or target_arch()
    args = spec_args_for(spec, arch)
    if spec is not BASE:
        args['BASE_IMAGE'] = image_ref('base', base_digest(arch), arch)
    return args


def content_hash(spec, arch=None):
    """SHA256[:12] over every input: arch, Dockerfile, args, verified blobs, base ref, overlays."""
    arch = arch or target_arch()
    digest = hashlib.sha256()
    digest.update(f'{arch} {spec["version"]} {spec["dockerfile"]}\n'.encode())
    digest.update(json.dumps(build_args(spec, arch), sort_keys=True).encode())
    digest.update(json.dumps(list(blobs_for(spec, arch)), sort_keys=True).encode())
    if spec is not BASE:
        digest.update(image_ref('base', base_digest(arch), arch).encode())
    for name, (data, mode) in sorted(overlay_for(spec).items()):
        digest.update(f'{name} {mode:o}\n'.encode())
        digest.update(data)
    return digest.hexdigest()[:12]


def current_ref(name, arch=None):
    arch = arch or target_arch()
    return image_ref(name, content_hash(spec_of(name), arch), arch)


def _sha256_file(path):
    h = hashlib.sha256()
    with path.open('rb') as handle:
        while chunk := handle.read(1 << 16):
            h.update(chunk)
    return h.hexdigest()


def _format_mb(num_bytes):
    return f'{num_bytes / (1024 * 1024):.1f} MB'


def _download_once(filename, url, tmp_path):
    request = urllib.request.Request(url, headers={'User-Agent': f'zt/{VERSION}'})
    hasher = hashlib.sha256()
    is_tty = hasattr(sys.stderr, 'isatty') and sys.stderr.isatty()
    started = time.monotonic()
    last_draw = 0.0
    downloaded = 0

    with urllib.request.urlopen(request, timeout=300) as response:
        total_raw = response.headers.get('Content-Length') if hasattr(response, 'headers') and response.headers else None
        total = int(total_raw) if (total_raw and total_raw.isdigit() and int(total_raw) > 0) else 0
        if not is_tty:
            size_note = f' ({_format_mb(total)})' if total else ''
            say(f'downloading {filename}{size_note} <- {url}')
        with tmp_path.open('wb') as out:
            while chunk := response.read(1 << 16):
                out.write(chunk)
                hasher.update(chunk)
                downloaded += len(chunk)
                if is_tty:
                    now = time.monotonic()
                    if now - last_draw >= 0.2 or (total and downloaded >= total):
                        elapsed = max(now - started, 0.01)
                        rate = downloaded / (1024 * 1024) / elapsed
                        if total:
                            pct = min(100, int(downloaded * 100 / total))
                            line = (
                                f'\r  {filename}: {_format_mb(downloaded)} / {_format_mb(total)} '
                                f'({pct:3d}%, {rate:.1f} MB/s)'
                            )
                        else:
                            line = f'\r  {filename}: {_format_mb(downloaded)} ({rate:.1f} MB/s)'
                        sys.stderr.write(line)
                        sys.stderr.flush()
                        last_draw = now

    elapsed = max(time.monotonic() - started, 0.01)
    if is_tty:
        rate = downloaded / (1024 * 1024) / elapsed
        sys.stderr.write(
            f'\r  {filename}: {_format_mb(downloaded)} done in {elapsed:.1f}s ({rate:.1f} MB/s)   \n'
        )
        sys.stderr.flush()
    else:
        say(f'downloaded {filename} ({_format_mb(downloaded)} in {elapsed:.1f}s)')
    return hasher.hexdigest()


def fetch_blob(filename, url, expected_sha256, retries=DOWNLOAD_RETRIES):
    """Download with progress + retries and SHA256-verify an archive into host cache."""
    blobs_dir = cache_dir() / 'blobs'
    dest = blobs_dir / expected_sha256
    if dest.is_file():
        if _sha256_file(dest) == expected_sha256:
            return dest
        dest.unlink(missing_ok=True)

    blobs_dir.mkdir(parents=True, exist_ok=True)
    last_error = ''
    for attempt in range(1, max(1, retries) + 1):
        fd, tmp_name = tempfile.mkstemp(prefix=f'.{filename}-', dir=blobs_dir)
        os.close(fd)
        tmp = Path(tmp_name)
        try:
            actual = _download_once(filename, url, tmp)
            if actual != expected_sha256:
                tmp.unlink(missing_ok=True)
                last_error = (
                    f'SHA256 mismatch for {filename} ({url}): '
                    f'expected {expected_sha256}, got {actual}'
                )
                if attempt < retries:
                    warn(f'zt: {last_error}; retrying ({attempt}/{retries - 1})')
                    time.sleep(2 * attempt)
                    continue
                die(last_error)
            os.replace(tmp, dest)
            return dest
        except (OSError, urllib.error.URLError) as err:
            tmp.unlink(missing_ok=True)
            last_error = f'failed to download {filename} ({url}): {err}'
            if attempt < retries:
                warn(f'zt: {last_error}; retrying ({attempt}/{retries - 1})')
                time.sleep(2 * attempt)
                continue
            die(last_error)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    die(last_error or f'failed to download {filename}')


def _link_or_copy(src, dst):
    """Prefer a zero-copy hardlink (same filesystem), falling back to shutil.copy2."""
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def _normalize_context_modes(root, spec):
    """Force umask-independent 0755 dir modes and non-group/world-writable overlay file modes.

    Linux distros with user-private-groups default to umask 0002, causing mkdir
    to create 0775 dirs under the build context; `COPY ./rootfs/ /` would then
    propagate 0775 onto /etc, /usr, /usr/bin, etc. and fail the `programs` check.
    """
    if os.name == 'nt':
        return
    expected_files = {key: mode & ~0o022 for key, (_, mode) in overlay_for(spec).items()}
    root.chmod(0o755)
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames:
            Path(dirpath, name).chmod(0o755)
        for name in filenames:
            full = Path(dirpath, name)
            rel = full.relative_to(root).as_posix()
            if rel in expected_files:
                full.chmod(expected_files[rel])
            else:
                mode = full.stat().st_mode & 0o777
                if mode & 0o022:
                    full.chmod(mode & ~0o022)


def build_context(name, arch=None):
    """Return (context_dir, digest): self-contained overlays + hardlinked verified blobs."""
    arch = arch or target_arch()
    spec = spec_of(name)
    digest = content_hash(spec, arch)
    context = cache_dir() / 'build' / f'{name}-{arch}-{digest}'
    if context.is_dir():
        _normalize_context_modes(context, spec)
        return context, digest
    blobs = [
        (filename, fetch_blob(filename, url, sha256))
        for filename, url, sha256 in blobs_for(spec, arch)
    ]
    context.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f'.{name}-{arch}-', dir=context.parent))
    try:
        for key, (data, mode) in overlay_for(spec).items():
            target = staging / key
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            if os.name != 'nt':
                target.chmod(mode & ~0o022)
        if blobs:
            blobs_target = staging / 'blobs'
            blobs_target.mkdir(parents=True, exist_ok=True)
            for filename, cached_path in blobs:
                _link_or_copy(cached_path, blobs_target / filename)
        _normalize_context_modes(staging, spec)
        try:
            staging.rename(context)
        except OSError:
            if not context.is_dir():
                raise
            shutil.rmtree(staging, ignore_errors=True)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    for stale in context.parent.glob(f'{name}-{arch}-*'):
        if stale != context and not stale.name.startswith('.'):
            shutil.rmtree(stale, ignore_errors=True)
    return context, digest


def _base_oci_dir(arch):
    return cache_dir() / 'oci' / f'base-{arch}-{base_digest(arch)}'


def _csv_quote(value):
    text = str(value)
    if any(ch in text for ch in (',', '"', ' ', '\t')):
        return '"' + text.replace('"', '""') + '"'
    return text


def build(engine, name, force=False, arch=None, tag=None):
    """Build `name` if missing (or forced), returning its image ref (or custom `tag`)."""
    arch = arch or target_arch()
    spec = spec_of(name)
    ref = tag or current_ref(name, arch)
    external_builder = getattr(engine, 'needs_external_build_load', False) is True
    base_oci = _base_oci_dir(arch) if external_builder else None
    oci_ready = (name != 'base') or (not external_builder) or (base_oci / 'oci-layout').is_file()
    if engine.image_exists(ref) and not force and oci_ready:
        say(f'{name}: image up to date ({ref})')
        return ref
    if name != 'base':
        build(engine, 'base', arch=arch)
    context, _ = build_context(name, arch=arch)
    say(f'==> building {ref} ({platform_for(arch)})')

    extra_args = []
    staging_oci = None
    if external_builder:
        extra_args.append('--load')
        if name == 'base':
            base_oci.parent.mkdir(parents=True, exist_ok=True)
            staging_oci = Path(tempfile.mkdtemp(prefix=f'.base-{arch}-', dir=base_oci.parent))
            extra_args += ['--output', f'type=oci,dest={_csv_quote(staging_oci)},tar=false']
        else:
            base_ref = current_ref('base', arch)
            extra_args += ['--build-context', f'{base_ref}=oci-layout://{base_oci.as_posix()}']

    try:
        engine.run_cli(
            'build',
            '--platform', platform_for(arch),
            '-f', str(context / spec['dockerfile']),
            '-t', ref,
            '--label', 'org.zt.managed=true',
            '--label', f'org.zt.profile={name}',
            '--label', f'org.zt.arch={arch}',
            *[f'--build-arg={key}={value}' for key, value in build_args(spec, arch).items()],
            *extra_args,
            str(context),
            timeout=3600,
        )
        if staging_oci is not None:
            if not (staging_oci / 'oci-layout').is_file():
                die(f'buildx did not export OCI layout for {ref}')
            if base_oci.exists():
                shutil.rmtree(base_oci, ignore_errors=True)
            staging_oci.rename(base_oci)
            staging_oci = None
            for stale in base_oci.parent.glob(f'base-{arch}-*'):
                if stale != base_oci and not stale.name.startswith('.'):
                    shutil.rmtree(stale, ignore_errors=True)
    except BaseException:
        if staging_oci is not None:
            shutil.rmtree(staging_oci, ignore_errors=True)
        raise
    return ref
