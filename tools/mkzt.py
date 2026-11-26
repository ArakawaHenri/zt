#!/usr/bin/env python3
"""Assemble the deterministic single-file zipapp executable: ./zt (src/zt + overlay/)."""
import argparse
import io
import os
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_PARENT = ROOT / 'src'
SRC = SRC_PARENT / 'zt'
OVERLAY = ROOT / 'overlay'
DEFAULT_OUTPUT = ROOT / 'zt'

if str(SRC_PARENT) not in sys.path:
    sys.path.insert(0, str(SRC_PARENT))

from zt.spec import EXECUTABLE_OVERLAYS  # noqa: E402

FIXED_TIME = (1980, 1, 1, 0, 0, 0)
MAIN_PY = b'from zt.cli import run_main\n\nif __name__ == "__main__":\n    run_main()\n'


def _add_bytes(zf, arcname, data, mode=0o644):
    info = zipfile.ZipInfo(arcname, date_time=FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3  # Unix
    info.external_attr = (0o100000 | (mode & 0o777)) << 16
    zf.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _file_mode(path, rel_overlay=None):
    if os.name == 'nt':
        if rel_overlay is not None:
            return 0o755 if rel_overlay in EXECUTABLE_OVERLAYS else 0o644
        return 0o644
    return path.stat().st_mode & 0o777


def build_zipapp(output=DEFAULT_OUTPUT):
    output = Path(output)
    buf = io.BytesIO()
    py_count = 0
    overlay_count = 0
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        _add_bytes(zf, '__main__.py', MAIN_PY, 0o644)

        for path in sorted(SRC.rglob('*.py')):
            if path.is_symlink():
                sys.exit(f'src/{path.relative_to(SRC_PARENT)} is a symlink')
            rel = (Path('zt') / path.relative_to(SRC)).as_posix()
            _add_bytes(zf, rel, path.read_bytes(), _file_mode(path))
            py_count += 1

        for path in sorted(OVERLAY.rglob('*')):
            if path.is_symlink():
                sys.exit(f'overlay/{path.relative_to(OVERLAY)} is a symlink, which zt cannot carry')
            if not path.is_file():
                continue
            rel_overlay = path.relative_to(OVERLAY).as_posix()
            rel = f'overlay/{rel_overlay}'
            _add_bytes(zf, rel, path.read_bytes(), _file_mode(path, rel_overlay))
            overlay_count += 1

    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_name(f'.{output.name}.tmp')
    tmp.write_bytes(b'#!/usr/bin/env python3\n' + buf.getvalue())
    if os.name != 'nt':
        tmp.chmod(0o755)
    os.replace(tmp, output)
    label = output.relative_to(ROOT) if output.is_relative_to(ROOT) else output
    print(
        f'{label}: {py_count} Python modules + '
        f'{overlay_count} overlay files embedded, {output.stat().st_size} bytes'
    )


def main():
    parser = argparse.ArgumentParser(description='Build deterministic zt single-file zipapp.')
    parser.add_argument('-o', '--output', default=str(DEFAULT_OUTPUT), help='Output executable path')
    args = parser.parse_args()
    build_zipapp(Path(args.output))


if __name__ == '__main__':
    main()
