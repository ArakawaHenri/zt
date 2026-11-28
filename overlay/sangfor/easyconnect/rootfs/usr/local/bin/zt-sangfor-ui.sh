#!/bin/bash
# Sangfor EasyConnect Electron desktop UI (runs as kasm-user under systemd supervision).
set -eu
VPN_ROOT=/usr/share/sangfor/EasyConnect
export LD_LIBRARY_PATH="$VPN_ROOT:${LD_LIBRARY_PATH:-}"
exec "$VPN_ROOT/EasyConnect" --enable-transparent-visuals --disable-gpu
