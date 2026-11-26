#!/bin/bash
# Remove TCP MSS clamp when TrustAgent tears down its vnic interface.
set -eu
device=${1:-}
[ -n "$device" ] || { echo 'usage: zt-vnic-remove.sh <device>' >&2; exit 1; }
iptables -t mangle -D FORWARD -o "$device" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360 2>/dev/null || true
