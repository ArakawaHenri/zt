#!/bin/bash
# Sangfor aTrust Electron tray UI (runs as kasm-user under systemd supervision).
set -eu
VPN_ROOT=/usr/share/sangfor/aTrust
exec "$VPN_ROOT/aTrustTray" --no-sandbox
