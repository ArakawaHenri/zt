"""Access overlay files and standalone guest scripts from checkout or zipapp."""
import os
import zipfile
from pathlib import Path

from zt.spec import EXECUTABLE_OVERLAYS


def zipapp_archive():
    """Return path to the running zipapp archive, or None when running from a source checkout."""
    spec = globals().get('__spec__')
    loader = getattr(spec, 'loader', None)
    archive = getattr(loader, 'archive', None)
    if archive and zipfile.is_zipfile(archive):
        return archive
    return None


def _checkout_root():
    # src/zt/resources.py -> repo root
    return Path(__file__).resolve().parents[2]


def _checkout_mode(rel_posix, path):
    if os.name == 'nt':
        return 0o755 if rel_posix in EXECUTABLE_OVERLAYS else 0o644
    return path.stat().st_mode & 0o777


def overlay_files():
    """Return {relative_posix_path: (bytes, posix_mode)} for all files under overlay/."""
    archive = zipapp_archive()
    if archive:
        files = {}
        with zipfile.ZipFile(archive, 'r') as zf:
            for info in zf.infolist():
                if not info.filename.startswith('overlay/') or info.is_dir():
                    continue
                rel = info.filename[len('overlay/'):]
                mode = (info.external_attr >> 16) & 0o777
                files[rel] = (zf.read(info.filename), mode or 0o644)
        return dict(sorted(files.items()))

    root = _checkout_root() / 'overlay'
    files = {}
    for path in sorted(root.rglob('*')):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            files[rel] = (path.read_bytes(), _checkout_mode(rel, path))
    return dict(sorted(files.items()))


def guest_script(name):
    """Return UTF-8 source text of src/zt/guest/<name>.py."""
    archive = zipapp_archive()
    member = f'zt/guest/{name}.py'
    if archive:
        with zipfile.ZipFile(archive, 'r') as zf:
            return zf.read(member).decode('utf-8')
    path = Path(__file__).resolve().parent / 'guest' / f'{name}.py'
    return path.read_text(encoding='utf-8')
