#!/bin/bash
# Sangfor EasyConnect background daemons (ECAgent, svpnservice, CSClient).
# Supervised by systemd without a while-true loop:
# - Stays alive indefinitely while ECAgent is idle awaiting user login.
# - Once ECAgent logs its domain-socket bootstrap trigger, launches svpnservice
#   and CSClient, waits up to 20s for ECDomainFile, resumes ECAgent, and monitors it.
# - Exits 0 on SIGTERM/SIGINT; exits non-zero on crash so systemd applies
#   Restart=on-failure + StartLimitBurst=5.
set -eu
VPN_ROOT=/usr/share/sangfor/EasyConnect
VPN_RES="$VPN_ROOT/resources"
VPN_BIN="$VPN_RES/bin"
VPN_CONF="$VPN_RES/conf"

fifo_dir=$(mktemp -d /tmp/zt-ec-daemon.XXXXXX)
fifo="$fifo_dir/ecagent.fifo"
mkfifo "$fifo"
ec_pid=
drain_pid=
stopping=0

ec_alive() {
    [ -n "$ec_pid" ] || return 1
    if ! kill -0 "$ec_pid" 2>/dev/null; then
        return 1
    fi
    if [ -r "/proc/$ec_pid/stat" ] && awk -F'[)] ' '{exit (substr($2, 1, 1) != "Z")}' "/proc/$ec_pid/stat" 2>/dev/null; then
        return 1
    fi
    return 0
}

# shellcheck disable=SC2329
cleanup() {
    if [ -n "$drain_pid" ]; then
        kill "$drain_pid" 2>/dev/null || true
    fi
    if [ -n "$ec_pid" ]; then
        kill -CONT "$ec_pid" 2>/dev/null || true
        kill "$ec_pid" 2>/dev/null || true
    fi
    killall CSClient svpnservice ECAgent 2>/dev/null || true
    rm -rf -- "$fifo_dir"
}

trap 'stopping=1' TERM INT
trap cleanup EXIT

killall -9 svpnservice CSClient ECAgent 2>/dev/null || true
rm -f -- "$VPN_CONF/ECDomainFile"

"$VPN_BIN/ECAgent" > "$fifo" 2>&1 &
ec_pid=$!

exec 3< "$fifo"
matched=0
while [ "$stopping" -eq 0 ]; do
    rc=0
    IFS= read -r -t 1 line <&3 || rc=$?
    if [ "$rc" -eq 0 ]; then
        printf '%s\n' "$line"
        if printf '%s\n' "$line" | grep -Eq '\[Register\]cms client connect failed|ECDomainFile domain socket connect failed'; then
            matched=1
            break
        fi
    else
        if ! ec_alive; then
            break
        fi
        # Avoid busy-spinning if ECAgent closed stdout/FIFO while remaining alive.
        if [ "$rc" -le 128 ]; then
            sleep 0.5 &
            wait "$!" 2>/dev/null || true
        fi
    fi
done

if [ "$stopping" -eq 1 ]; then
    exit 0
fi

if [ "$matched" -ne 1 ]; then
    echo 'zt-sangfor-daemon: ECAgent exited before domain-socket bootstrap' >&2
    exit 1
fi

# Keep draining ECAgent output so it never blocks on a full FIFO buffer.
cat <&3 &
drain_pid=$!

kill -STOP "$ec_pid" 2>/dev/null || true
"$VPN_BIN/svpnservice" -h "$VPN_RES" &
svpn_pid=$!
"$VPN_BIN/CSClient" &
cs_pid=$!

sock_ready=0
for _ in $(seq 200); do
    if [ "$stopping" -eq 1 ]; then
        exit 0
    fi
    if [ -e "$VPN_CONF/ECDomainFile" ]; then
        sock_ready=1
        break
    fi
    sleep 0.1 &
    wait "$!" 2>/dev/null || true
done

# Reap short-lived daemonizer parents without blocking indefinitely if one stays foreground.
for pid in "$svpn_pid" "$cs_pid"; do
    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
    fi
done

if [ "$stopping" -eq 1 ]; then
    exit 0
fi

if [ "$sock_ready" -ne 1 ]; then
    echo 'zt-sangfor-daemon: ECDomainFile did not appear within 20s' >&2
    exit 1
fi

kill -CONT "$ec_pid" 2>/dev/null || true
ec_rc=0
wait "$ec_pid" || ec_rc=$?
if [ "$stopping" -eq 1 ]; then
    exit 0
fi
echo "zt-sangfor-daemon: ECAgent exited unexpectedly (status ${ec_rc})" >&2
exit 1
