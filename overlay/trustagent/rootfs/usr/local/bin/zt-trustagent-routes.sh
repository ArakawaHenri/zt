#!/bin/bash
# Configure optional policy-based bypass routes for TrustAgent so specified
# CIDRs continue leaving via the container's default gateway rather than the
# VPN tunnel. Idempotent across container restarts and independent of NIC name.
# (TCP MSS clamping for vnic+ is managed centrally by zt-net-setup.sh.)
set -eu

[ -n "${BYPASS_ROUTES:-}" ] || exit 0

WAN_ENV=/run/zt/wan.env
gateway=''
wan=''

if [ -r "$WAN_ENV" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            WAN=*) wan=${line#WAN=} ;;
            GATEWAY=*) gateway=${line#GATEWAY=} ;;
        esac
    done < "$WAN_ENV"
fi

if [ -z "$gateway" ] || [ -z "$wan" ]; then
    for _ in $(seq 30); do
        read -r gateway wan <<<"$(ip -4 route show default | awk '$2 == "via" && $5 !~ /^(lo|tun|utun|vnic|tap|wg)/ {print $3, $5; exit}')"
        [ -n "$gateway" ] && [ -n "$wan" ] && break
        sleep 0.2
    done
fi
[ -n "$gateway" ] && [ -n "$wan" ] || {
    echo 'zt-trustagent-routes: no default route, skipping bypass routes' >&2
    exit 0
}

mkdir -p /etc/iproute2
touch /etc/iproute2/rt_tables
grep -Eq '^[[:space:]]*100[[:space:]]+bypass$' /etc/iproute2/rt_tables \
    || echo '100 bypass' >> /etc/iproute2/rt_tables

ip rule list priority 100 | grep -q 'lookup bypass' \
    || ip rule add from all lookup bypass priority 100

IFS=',' read -r -a routes <<< "$BYPASS_ROUTES"
for cidr in "${routes[@]}"; do
    cidr=${cidr//[[:space:]]/}
    [ -n "$cidr" ] || continue
    ip route replace "$cidr" via "$gateway" dev "$wan" table bypass
done
