#!/bin/sh
# One-line installer for zt on macOS and Linux (arm64 / amd64).
# Usage: curl -fsSL https://raw.githubusercontent.com/ArakawaHenri/zt/master/install.sh | sh
set -eu

REPO="${ZT_REPO:-ArakawaHenri/zt}"
API_BASE="${ZT_API_BASE:-https://api.github.com}"
DOWNLOAD_BASE="${ZT_DOWNLOAD_BASE:-https://github.com}"
INSTALL_DIR="${ZT_INSTALL_DIR:-$HOME/.local/bin}"
REQUESTED_VERSION="${ZT_VERSION:-}"

say() { printf '%s\n' "$*"; }
die() { printf 'zt-install: %s\n' "$*" >&2; exit 1; }

# 1. Detect OS and CPU architecture.
OS="$(uname -s 2>/dev/null || printf 'unknown')"
case "$OS" in
    Darwin) OS_LABEL="macOS" ;;
    Linux)  OS_LABEL="Linux" ;;
    MINGW*|MSYS*|CYGWIN*)
        die "detected Windows ($OS); use the PowerShell installer instead: irm https://raw.githubusercontent.com/${REPO}/master/install.ps1 | iex"
        ;;
    *)
        die "unsupported operating system: $OS (supported: macOS, Linux)"
        ;;
esac

RAW_ARCH="$(uname -m 2>/dev/null || printf 'unknown')"
case "$RAW_ARCH" in
    arm64|aarch64) ARCH="arm64" ;;
    x86_64|amd64)  ARCH="amd64" ;;
    *)
        die "unsupported CPU architecture: $RAW_ARCH (supported: arm64, amd64)"
        ;;
esac

# 2. Verify Python 3.9+ is available.
PYTHON="$(command -v python3 2>/dev/null || true)"
if [ -z "$PYTHON" ]; then
    case "$OS" in
        Darwin) hint="Install via Homebrew (brew install python) or https://www.python.org/downloads/" ;;
        *)      hint="Install via your package manager (e.g. apt install python3) or https://www.python.org/downloads/" ;;
    esac
    die "python3 (3.9 or later) is required, but was not found. $hint"
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)'; then
    PY_VER="$("$PYTHON" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null || printf 'unknown')"
    die "python3 3.9 or later is required (found $PY_VER at $PYTHON)"
fi

# 3. Choose downloader (curl or wget).
download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -H "User-Agent: zt-installer" "$url" -o "$dest"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" --header="User-Agent: zt-installer" "$url"
    else
        die "neither curl nor wget was found; install one and retry"
    fi
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zt-install.XXXXXX")"
STAGE=""
cleanup() { rm -rf "$TMP_DIR" "${STAGE:-}"; }
trap cleanup EXIT HUP INT TERM

# 4. Resolve latest stable release (or user-specified ZT_VERSION).
if [ -n "$REQUESTED_VERSION" ]; then
    case "$REQUESTED_VERSION" in
        v*) TAG="$REQUESTED_VERSION" ;;
        *)  TAG="v$REQUESTED_VERSION" ;;
    esac
    ZT_URL="${DOWNLOAD_BASE%/}/${REPO}/releases/download/${TAG}/zt"
    SUMS_URL="${DOWNLOAD_BASE%/}/${REPO}/releases/download/${TAG}/SHA256SUMS"
else
    say "Checking latest stable release for ${OS_LABEL} (${ARCH})..."
    META_FILE="$TMP_DIR/release.json"
    download "${API_BASE%/}/repos/${REPO}/releases/latest" "$META_FILE" \
        || die "failed to query latest stable release from ${API_BASE%/}/repos/${REPO}/releases/latest"

    RESOLVED="$("$PYTHON" - "$META_FILE" <<'PY'
import json, sys

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    data = json.load(f)
if data.get('draft') or data.get('prerelease'):
    sys.exit('latest release is not a stable release')
tag = data.get('tag_name') or ''
assets = {a.get('name'): a.get('browser_download_url') for a in data.get('assets') or ()}
zt_url = assets.get('zt') or ''
sums_url = assets.get('SHA256SUMS') or ''
if not tag or not zt_url or not sums_url:
    sys.exit('release metadata is missing zt or SHA256SUMS assets')
print(tag)
print(zt_url)
print(sums_url)
PY
)" || die "could not parse stable release metadata"

    TAG="$(printf '%s\n' "$RESOLVED" | sed -n '1p')"
    ZT_URL="$(printf '%s\n' "$RESOLVED" | sed -n '2p')"
    SUMS_URL="$(printf '%s\n' "$RESOLVED" | sed -n '3p')"
fi

# 5. Download artifact and SHA256SUMS, then verify integrity.
say "Downloading zt ${TAG} (${OS_LABEL}/${ARCH})..."
download "$ZT_URL" "$TMP_DIR/zt" || die "failed to download $ZT_URL"
download "$SUMS_URL" "$TMP_DIR/SHA256SUMS" || die "failed to download $SUMS_URL"

"$PYTHON" - "$TMP_DIR/zt" "$TMP_DIR/SHA256SUMS" <<'PY'
import hashlib, sys

artifact, sums_path = sys.argv[1], sys.argv[2]
expected = ''
with open(sums_path, 'r', encoding='utf-8') as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[-1].lstrip('*./') == 'zt':
            expected = parts[0].lower()
            break
if not expected:
    sys.exit('zt-install: SHA256SUMS does not contain an entry for zt')
h = hashlib.sha256()
with open(artifact, 'rb') as f:
    while True:
        chunk = f.read(65536)
        if not chunk:
            break
        h.update(chunk)
actual = h.hexdigest().lower()
if actual != expected:
    sys.exit(f'zt-install: SHA256 mismatch for zt (expected {expected}, got {actual})')
PY

# 6. Install atomically into INSTALL_DIR.
mkdir -p "$INSTALL_DIR"
STAGE="$(mktemp "${INSTALL_DIR}/.zt.XXXXXX")"
cp "$TMP_DIR/zt" "$STAGE"
chmod 0755 "$STAGE"
mv -f "$STAGE" "$INSTALL_DIR/zt"
STAGE=""

INSTALLED_VER="$("$INSTALL_DIR/zt" --version 2>/dev/null || printf 'zt %s' "$TAG")"
say "Installed ${INSTALLED_VER} to ${INSTALL_DIR}/zt"

case ":${PATH:-}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
        say ""
        say "Note: ${INSTALL_DIR} is not in your PATH. Add it to your shell profile:"
        say "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
esac

if ! command -v container >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
    say ""
    if [ "$OS" = "Darwin" ]; then
        say "Next: install Apple Container (https://github.com/apple/container) or Docker, then run: zt up"
    else
        say "Next: install Docker or Podman, then run: zt up"
    fi
fi
