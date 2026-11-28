#!/bin/bash
# Sangfor aTrust background daemon (aTrustAgent runs as root with FAKE_LOGIN=sangfor
# so its local HTTP service binds as the non-root sangfor user).
#
# `aTrustAgent --plugin plugin-daemon --plugin-cmd '|'` forks a background daemon
# and exits 0 from its launcher process. Under Type=simple systemd supervision we
# reap the launcher once it forks, monitor the live daemon process in the foreground,
# forward SIGTERM/SIGINT cleanly on stop, and exit non-zero on crash so systemd
# applies Restart=on-failure + StartLimitBurst=5.
set -eu
VPN_ROOT=/usr/share/sangfor/aTrust
VPN_BIN="$VPN_ROOT/resources/bin"

export FAKE_LOGIN=sangfor
export LD_PRELOAD=/usr/local/lib/fake-getlogin.so
export LD_LIBRARY_PATH="$VPN_ROOT:$VPN_BIN:${LD_LIBRARY_PATH:-}"

launch_pid=
stopping=0

reap_launcher() {
    [ -n "$launch_pid" ] || return 0
    if [ ! -r "/proc/$launch_pid/stat" ] || awk -F'[)] ' '{exit (substr($2, 1, 1) != "Z")}' "/proc/$launch_pid/stat" 2>/dev/null; then
        wait "$launch_pid" 2>/dev/null || true
        launch_pid=
    fi
}

agent_running() {
    reap_launcher
    ps -C aTrustAgent -o stat= 2>/dev/null | awk '$1 !~ /^Z/ && NF > 0 { found=1 } END { exit !found }'
}

# shellcheck disable=SC2329
cleanup() {
    if [ -n "$launch_pid" ]; then
        kill "$launch_pid" 2>/dev/null || true
        wait "$launch_pid" 2>/dev/null || true
        launch_pid=
    fi
    killall aTrustAgent 2>/dev/null || true
}

trap 'stopping=1' TERM INT
trap cleanup EXIT

"$VPN_BIN/aTrustAgent" --plugin plugin-daemon --plugin-cmd '|' &
launch_pid=$!

ready=0
for _ in $(seq 30); do
    [ "$stopping" -eq 1 ] && exit 0
    reap_launcher
    if [ -z "$launch_pid" ] && agent_running; then
        ready=1
        break
    fi
    sleep 0.5 &
    wait "$!" 2>/dev/null || true
done

if [ "$stopping" -eq 1 ]; then
    exit 0
fi

if [ "$ready" -ne 1 ] && ! agent_running; then
    echo 'zt-sangfor-daemon: aTrustAgent did not start within 15s' >&2
    exit 1
fi

while [ "$stopping" -eq 0 ]; do
    if ! agent_running; then
        echo 'zt-sangfor-daemon: aTrustAgent exited unexpectedly' >&2
        exit 1
    fi
    sleep 2 &
    wait "$!" 2>/dev/null || true
done
exit 0
