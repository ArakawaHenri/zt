#!/bin/bash
# Container network policy, applied once per boot by zt-net.service:
#   * All rules live in a dedicated ZT-INPUT chain jumped from INPUT rule #1
#     (IPv4 and IPv6). The chain is flushed and rebuilt in canonical order on
#     each run, so precedence cannot drift and re-running is strictly idempotent.
#   * On $wan (ZT_NET_MODE):
#       - gateway (default: Apple Container, rootful Docker): accept TCP from
#         the gateway only; drop all other unsolicited TCP and UDP (except
#         DHCP client renewals).
#       - subnet (rootless Podman / gvproxy): accept TCP from the gateway and
#         drop same-subnet peer containers, letting gvproxy's routed host
#         forwarder through.
#   * Nothing may open unsolicited TCP or UDP connections from any VPN tunnel
#     (tun+, utun+, vnic+). Outbound replies are allowed via conntrack.
#   * Traffic leaving through an IPv4 VPN tunnel is NATed (MASQUERADE).
set -eu

mode=${ZT_NET_MODE:-gateway}
case "$mode" in
    gateway|subnet) ;;
    *)
        echo "zt-net: unknown ZT_NET_MODE '$mode' (expected gateway or subnet)" >&2
        exit 1
        ;;
esac

# The default route may not exist yet when this unit starts.
gateway=
wan=
for _ in $(seq 50); do
    read -r gateway wan <<<"$(ip -4 route show default | head -n 1 | awk '$2 == "via" {print $3, $5}')"
    [ -n "$wan" ] && [ -n "$gateway" ] && break
    sleep 0.2
done
if [ -z "$wan" ] || [ -z "$gateway" ]; then
    echo 'zt-net: no default route, cannot apply the host-only policy' >&2
    exit 1
fi

subnet=$(ip -4 route show dev "$wan" scope link | awk '{print $1; exit}')
if [ "$mode" = subnet ] && [ -z "$subnet" ]; then
    echo "zt-net: no link-scope subnet on $wan, cannot apply subnet policy" >&2
    exit 1
fi

ensure_jump_first() { # tool
    local tool=$1 first
    "$tool" -t filter -N ZT-INPUT 2>/dev/null || true
    first=$("$tool" -t filter -S INPUT | awk 'NR==2 {print; exit}')
    if [ "$first" != '-A INPUT -j ZT-INPUT' ]; then
        while "$tool" -t filter -D INPUT -j ZT-INPUT 2>/dev/null; do :; done
        "$tool" -t filter -I INPUT 1 -j ZT-INPUT
    fi
    "$tool" -t filter -F ZT-INPUT
}

nat_rule() { # chain rule...
    local chain=$1; shift
    iptables -t nat -C "$chain" "$@" 2>/dev/null || iptables -t nat -A "$chain" "$@"
}

# ---- IPv4 ------------------------------------------------------------------
ensure_jump_first iptables
iptables -t filter -A ZT-INPUT -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment 'zt: replies' -j ACCEPT
iptables -t filter -A ZT-INPUT -i "$wan" -s "$gateway" -p tcp \
    -m comment --comment 'zt: host' -j ACCEPT
iptables -t filter -A ZT-INPUT -i "$wan" -p udp --dport 68 \
    -m comment --comment 'zt: dhcp' -j ACCEPT
if [ "$mode" = subnet ]; then
    iptables -t filter -A ZT-INPUT -i "$wan" -s "$subnet" -p tcp \
        -m comment --comment 'zt: host only' -j DROP
    iptables -t filter -A ZT-INPUT -i "$wan" -s "$subnet" -p udp \
        -m comment --comment 'zt: host only udp' -j DROP
else
    iptables -t filter -A ZT-INPUT -i "$wan" -p tcp \
        -m comment --comment 'zt: host only' -j DROP
    iptables -t filter -A ZT-INPUT -i "$wan" -p udp \
        -m comment --comment 'zt: host only udp' -j DROP
fi
for tunnel in tun+ utun+ vnic+; do
    iptables -t filter -A ZT-INPUT -i "$tunnel" -p tcp \
        -m comment --comment 'zt: tunnel' -j DROP
    iptables -t filter -A ZT-INPUT -i "$tunnel" -p udp \
        -m comment --comment 'zt: tunnel udp' -j DROP
    nat_rule POSTROUTING -o "$tunnel" -m comment --comment 'zt: tunnel nat' -j MASQUERADE
done

# ---- IPv6 ------------------------------------------------------------------
# The engine reaches the container over IPv4, so nobody on $wan or any tunnel
# may open unsolicited TCP or UDP connections over IPv6.
ensure_jump_first ip6tables
ip6tables -t filter -A ZT-INPUT -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment 'zt: replies' -j ACCEPT
ip6tables -t filter -A ZT-INPUT -i "$wan" -p udp --dport 546 \
    -m comment --comment 'zt: dhcpv6' -j ACCEPT
ip6tables -t filter -A ZT-INPUT -i "$wan" -p tcp \
    -m comment --comment 'zt: host only' -j DROP
ip6tables -t filter -A ZT-INPUT -i "$wan" -p udp \
    -m comment --comment 'zt: host only udp' -j DROP
for tunnel in tun+ utun+ vnic+; do
    ip6tables -t filter -A ZT-INPUT -i "$tunnel" -p tcp \
        -m comment --comment 'zt: tunnel' -j DROP
    ip6tables -t filter -A ZT-INPUT -i "$tunnel" -p udp \
        -m comment --comment 'zt: tunnel udp' -j DROP
done
