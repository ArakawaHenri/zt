#!/bin/bash
# Sangfor EasyConnect session: ECAgent, svpnservice and CSClient run as root;
# the Electron GUI runs as kasm-user with zero capabilities and NoNewPrivs.
set -u
VPN_ROOT=/usr/share/sangfor/EasyConnect
VPN_RES="$VPN_ROOT/resources"
VPN_BIN="$VPN_RES/bin"
VPN_CONF="$VPN_RES/conf"

start_daemons() {
    rm -f "$VPN_CONF/ECDomainFile"
    {
        "$VPN_BIN/ECAgent"
    } > >(
        grep -Em 1 --line-buffered \
            '\[Register\]cms client connect failed|ECDomainFile domain socket connect failed'
        killall -9 svpnservice CSClient 2>/dev/null || true
        killall -STOP ECAgent 2>/dev/null || true
        "$VPN_BIN/svpnservice" -h "$VPN_RES" &
        "$VPN_BIN/CSClient" &
        wait
        until [ -e "$VPN_CONF/ECDomainFile" ]; do
            sleep 0.1
        done
        killall -CONT ECAgent 2>/dev/null || true
        exec cat >/dev/null
    ) &
}

while true; do
    start_daemons
    setpriv --reuid kasm-user --regid kasm-user --init-groups --no-new-privs \
        env HOME=/home/kasm-user USER=kasm-user LOGNAME=kasm-user \
        LD_LIBRARY_PATH="$VPN_ROOT:${LD_LIBRARY_PATH:-}" \
        "$VPN_ROOT/EasyConnect" --enable-transparent-visuals --disable-gpu

    killall CSClient svpnservice ECAgent 2>/dev/null || true
    sleep 4
    killall -9 CSClient svpnservice ECAgent 2>/dev/null || true
done
