#!/bin/bash
# Sangfor aTrust session: aTrustAgent runs as root (with FAKE_LOGIN=sangfor so
# its local HTTP service binds as the non-root sangfor user); the Electron tray
# runs as kasm-user with zero capabilities and NoNewPrivs.
set -u
VPN_ROOT=/usr/share/sangfor/aTrust
VPN_BIN="$VPN_ROOT/resources/bin"

while true; do
    FAKE_LOGIN=sangfor \
    LD_PRELOAD=/usr/local/lib/fake-getlogin.so \
    LD_LIBRARY_PATH="$VPN_ROOT:$VPN_BIN:${LD_LIBRARY_PATH:-}" \
        "$VPN_BIN/aTrustAgent" --plugin plugin-daemon --plugin-cmd '|' >/dev/null &

    setpriv --reuid kasm-user --regid kasm-user --init-groups --no-new-privs \
        env HOME=/home/kasm-user USER=kasm-user LOGNAME=kasm-user \
        "$VPN_ROOT/aTrustTray" --no-sandbox

    killall aTrustAgent 2>/dev/null || true
    sleep 4
    killall -9 aTrustAgent 2>/dev/null || true
done
