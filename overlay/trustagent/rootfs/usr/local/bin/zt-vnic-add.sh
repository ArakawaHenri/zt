#!/bin/bash
# Clamp TCP MSS on TrustAgent's vnic tunnel interface (NAT MASQUERADE is
# already managed idempotently by zt-net-setup.sh for vnic+).
set -eu
device=${1:-}
[ -n "$device" ] || { echo 'usage: zt-vnic-add.sh <device>' >&2; exit 1; }
iptables -t mangle -C FORWARD -o "$device" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null \
    || iptables -t mangle -A FORWARD -o "$device" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360
