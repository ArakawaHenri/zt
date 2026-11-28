#!/bin/bash
# Container network policy & asymmetric return routing, applied at boot by
# zt-net.service (and re-asserted via --reapply by zt-iptables if displaced):
#   * Snapshots boot-time WAN/gateway/subnet into /run/zt/wan.env (excluding
#     tunnel interfaces) so re-runs while a VPN is connected never hijack $wan.
#   * Strict allowlist ZT-INPUT jumped from INPUT #1 (IPv4 & IPv6):
#       - Accept lo; unconditionally drop non-lo packets destined for loopback
#         (127.0.0.0/8, ::1/128) to neutralize route_localnet=1 side effects.
#       - Accept ESTABLISHED,RELATED replies.
#       - On $wan (IPv4): accept TCP :6901 from $gateway (and non-$subnet in
#         subnet mode) plus DHCP UDP 68; drop all other unsolicited TCP/UDP.
#       - On all other non-lo interfaces (any VPN tunnel name): drop all
#         unsolicited TCP and UDP (IPv4 & IPv6).
#   * filter ZT-OUTPUT jumped from OUTPUT #1: allows loopback and marked/:6901
#     KasmVNC replies before returning to vendor chains (e.g. SANGFOR_VIRTUAL).
#   * Asymmetric return routing for KasmVNC :6901 via table 90 + CONNMARK/fwmark
#     0x10000 (with sport 6901 fallback if xt_connmark is absent) + $wan rp_filter=2.
#   * Dual-stack two-stage TCPMSS clamping in mangle POSTROUTING for tun+, utun+,
#     vnic+ plus IPv4 nat POSTROUTING MASQUERADE.
set -eu

export ZT_IPT_INTERNAL=1

STATE_DIR=/run/zt
WAN_ENV="$STATE_DIR/wan.env"
LOCK_FILE="$STATE_DIR/iptables.lock"
ZT_IPT=/usr/local/sbin/zt-iptables
MARK_HEX=0x10000
MARK_MASK=0x10000
WAN_TABLE=90

reapply=0
if [ "${1:-}" = "--reapply" ]; then
    reapply=1
elif [ "$#" -gt 0 ]; then
    echo "zt-net: unknown argument '$1' (expected none or --reapply)" >&2
    exit 2
fi

valid_token() {
    case "$1" in
        ''|*[!a-zA-Z0-9._:/-]*) return 1 ;;
        *) return 0 ;;
    esac
}

load_wan_env() {
    local line key val
    [ -r "$WAN_ENV" ] || return 1
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|\#*) continue ;;
            *=*)
                key=${line%%=*}
                val=${line#*=}
                case "$key" in
                    WAN) valid_token "$val" && wan=$val ;;
                    GATEWAY) valid_token "$val" && gateway=$val ;;
                    SUBNET) valid_token "$val" && subnet=$val ;;
                    MODE)
                        case "$val" in
                            gateway|subnet) saved_mode=$val ;;
                        esac
                        ;;
                esac
                ;;
        esac
    done < "$WAN_ENV"
    [ -n "${wan:-}" ] && [ -n "${gateway:-}" ]
}

save_wan_env() {
    local tmp
    mkdir -p "$STATE_DIR"
    chmod 0755 "$STATE_DIR" 2>/dev/null || true
    tmp=$(mktemp "$STATE_DIR/.wan.env.XXXXXX")
    {
        printf 'WAN=%s\n' "$wan"
        printf 'GATEWAY=%s\n' "$gateway"
        printf 'SUBNET=%s\n' "$subnet"
        printf 'MODE=%s\n' "$mode"
    } > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$WAN_ENV"
}

# Ensure the unified iptables backend is initialized before issuing any rules.
if [ ! -r "$STATE_DIR/iptables-backend" ] && [ -x "$ZT_IPT" ]; then
    "$ZT_IPT" --init || true
fi

# Serialize full rebuilds against concurrent vendor iptables writes.
# Under --reapply, zt-iptables already holds LOCK_FILE on fd 9.
mkdir -p "$STATE_DIR"
chmod 0755 "$STATE_DIR" 2>/dev/null || true
if [ "$reapply" -eq 0 ]; then
    exec 9>>"$LOCK_FILE"
    flock -x 9
fi

wan=''
gateway=''
subnet=''
saved_mode=''

if load_wan_env; then
    if [ "$reapply" -eq 1 ]; then
        mode=${saved_mode:-gateway}
    else
        mode=${ZT_NET_MODE:-${saved_mode:-gateway}}
    fi
else
    if [ "$reapply" -eq 1 ]; then
        echo "zt-net: missing $WAN_ENV during --reapply" >&2
        exit 1
    fi
    mode=${ZT_NET_MODE:-gateway}
    # The default route may not exist yet when this unit starts; ignore VPN tunnels.
    for _ in $(seq 50); do
        read -r gateway wan <<<"$(ip -4 route show default | awk '$2 == "via" && $5 !~ /^(lo|tun|utun|vnic|tap|wg)/ {print $3, $5; exit}')"
        [ -n "$wan" ] && [ -n "$gateway" ] && break
        sleep 0.2
    done
    if [ -z "$wan" ] || [ -z "$gateway" ]; then
        echo 'zt-net: no default route, cannot apply the host-only policy' >&2
        exit 1
    fi
    subnet=$(ip -4 route show dev "$wan" scope link | awk '{print $1; exit}')
fi

case "$mode" in
    gateway|subnet) ;;
    *)
        echo "zt-net: unknown ZT_NET_MODE '$mode' (expected gateway or subnet)" >&2
        exit 1
        ;;
esac

if [ "$mode" = subnet ] && [ -z "$subnet" ]; then
    echo "zt-net: no link-scope subnet on $wan, cannot apply subnet policy" >&2
    exit 1
fi

if [ ! -r "$WAN_ENV" ] || [ "${saved_mode:-}" != "$mode" ]; then
    save_wan_env
fi

ensure_chain_first() { # tool table hook chain
    local tool=$1 table=$2 hook=$3 chain=$4 rules first
    "$tool" -t "$table" -N "$chain" 2>/dev/null || true
    rules=$("$tool" -t "$table" -S "$hook") || return 1
    first=$(printf '%s\n' "$rules" | awk 'NR==2 {print; exit}')
    if [ "$first" != "-A $hook -j $chain" ]; then
        while "$tool" -t "$table" -D "$hook" -j "$chain" 2>/dev/null; do :; done
        "$tool" -t "$table" -I "$hook" 1 -j "$chain" || return 1
    fi
    "$tool" -t "$table" -F "$chain" || return 1
}

nat_rule() { # chain rule...
    local chain=$1; shift
    iptables -t nat -C "$chain" "$@" 2>/dev/null || iptables -t nat -A "$chain" "$@"
}

# ---- Per-interface sysctl & table 90 asymmetric return routing -------------
if [ -w "/proc/sys/net/ipv4/conf/$wan/rp_filter" ]; then
    printf '2\n' > "/proc/sys/net/ipv4/conf/$wan/rp_filter" 2>/dev/null || true
fi
if [ -w "/proc/sys/net/ipv4/conf/$wan/src_valid_mark" ]; then
    printf '1\n' > "/proc/sys/net/ipv4/conf/$wan/src_valid_mark" 2>/dev/null || true
fi
if [ -w /proc/sys/net/ipv4/tcp_mtu_probing ]; then
    printf '1\n' > /proc/sys/net/ipv4/tcp_mtu_probing 2>/dev/null || true
fi

if mkdir -p /etc/iproute2 2>/dev/null; then
    touch /etc/iproute2/rt_tables 2>/dev/null || true
    if [ -w /etc/iproute2/rt_tables ]; then
        grep -Eq "^[[:space:]]*${WAN_TABLE}[[:space:]]+zt-wan$" /etc/iproute2/rt_tables \
            || echo "${WAN_TABLE} zt-wan" >> /etc/iproute2/rt_tables
    fi
fi
if [ -n "$subnet" ]; then
    ip -4 route replace "$subnet" dev "$wan" scope link table "$WAN_TABLE" 2>/dev/null || true
fi
ip -4 route replace default via "$gateway" dev "$wan" table "$WAN_TABLE" 2>/dev/null || true

connmark_ok=0
if ensure_chain_first iptables mangle PREROUTING ZT-PREROUTING 2>/dev/null \
    && ensure_chain_first iptables mangle OUTPUT ZT-OUTPUT 2>/dev/null \
    && iptables -t mangle -A ZT-PREROUTING -i "$wan" -p tcp --dport 6901 \
        -m conntrack --ctstate NEW \
        -m comment --comment 'zt: kasmvnc mark' \
        -j CONNMARK --set-xmark "${MARK_HEX}/${MARK_MASK}" 2>/dev/null \
    && iptables -t mangle -A ZT-PREROUTING -i "$wan" -p tcp --dport 6901 \
        -m comment --comment 'zt: kasmvnc rpf' \
        -j MARK --set-xmark "${MARK_HEX}/${MARK_MASK}" 2>/dev/null \
    && iptables -t mangle -A ZT-OUTPUT -p tcp --sport 6901 \
        -m connmark --mark "${MARK_HEX}/${MARK_MASK}" \
        -m comment --comment 'zt: kasmvnc mark' \
        -j CONNMARK --restore-mark --nfmask "$MARK_MASK" --ctmask "$MARK_MASK" 2>/dev/null; then
    connmark_ok=1
    : > "$STATE_DIR/connmark.ok"
    ip -4 rule list priority "$WAN_TABLE" | grep -Eq "fwmark ${MARK_HEX}(/${MARK_MASK})? .*lookup (${WAN_TABLE}|zt-wan)" \
        || ip -4 rule add fwmark "${MARK_HEX}/${MARK_MASK}" lookup "$WAN_TABLE" priority "$WAN_TABLE" 2>/dev/null \
        || true
else
    rm -f "$STATE_DIR/connmark.ok"
    # Fallback when xt_connmark is absent (older/stripped kernels): route locally
    # originated KasmVNC replies by source port (table local at pref 0 still keeps lo).
    ip -4 rule list priority "$WAN_TABLE" | grep -Eq "sport 6901 .*lookup (${WAN_TABLE}|zt-wan)" \
        || ip -4 rule add iif lo sport 6901 lookup "$WAN_TABLE" priority "$WAN_TABLE" 2>/dev/null \
        || true
fi

# ---- IPv4 filter (ZT-INPUT & ZT-OUTPUT) ------------------------------------
ensure_chain_first iptables filter INPUT ZT-INPUT
iptables -t filter -A ZT-INPUT -i lo \
    -m comment --comment 'zt: loopback' -j ACCEPT
iptables -t filter -A ZT-INPUT ! -i lo -d 127.0.0.0/8 \
    -m comment --comment 'zt: loopback guard' -j DROP
iptables -t filter -A ZT-INPUT -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment 'zt: replies' -j ACCEPT
iptables -t filter -A ZT-INPUT -i "$wan" -s "$gateway" -p tcp --dport 6901 \
    -m comment --comment 'zt: host' -j ACCEPT
if [ "$mode" = subnet ]; then
    iptables -t filter -A ZT-INPUT -i "$wan" ! -s "$subnet" -p tcp --dport 6901 \
        -m comment --comment 'zt: host routed' -j ACCEPT
fi
iptables -t filter -A ZT-INPUT -i "$wan" -p udp --dport 68 \
    -m comment --comment 'zt: dhcp' -j ACCEPT
iptables -t filter -A ZT-INPUT -i "$wan" -p tcp \
    -m comment --comment 'zt: host only' -j DROP
iptables -t filter -A ZT-INPUT -i "$wan" -p udp \
    -m comment --comment 'zt: host only udp' -j DROP
iptables -t filter -A ZT-INPUT ! -i "$wan" -p tcp \
    -m comment --comment 'zt: tunnel' -j DROP
iptables -t filter -A ZT-INPUT ! -i "$wan" -p udp \
    -m comment --comment 'zt: tunnel udp' -j DROP

# Protect KasmVNC :6901 replies & loopback from vendor OUTPUT DROP chains
# (e.g. EasyConnect SANGFOR_VIRTUAL) while returning all other traffic to them.
ensure_chain_first iptables filter OUTPUT ZT-OUTPUT
iptables -t filter -A ZT-OUTPUT -o lo -d 127.0.0.0/8 \
    -m comment --comment 'zt: loopback out' -j ACCEPT
if [ "$connmark_ok" = 1 ]; then
    iptables -t filter -A ZT-OUTPUT -p tcp --sport 6901 \
        -m connmark --mark "${MARK_HEX}/${MARK_MASK}" \
        -m comment --comment 'zt: kasmvnc out' -j ACCEPT
fi
iptables -t filter -A ZT-OUTPUT -o "$wan" -p tcp --sport 6901 \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment 'zt: kasmvnc out' -j ACCEPT

# ---- IPv4 tunnel NAT & two-stage TCPMSS clamping ---------------------------
for tunnel in tun+ utun+ vnic+; do
    nat_rule POSTROUTING -o "$tunnel" -m comment --comment 'zt: tunnel nat' -j MASQUERADE
done

mangle4_count=0
if ensure_chain_first iptables mangle POSTROUTING ZT-POSTROUTING 2>/dev/null; then
    for tunnel in tun+ utun+ vnic+; do
        if iptables -t mangle -A ZT-POSTROUTING -o "$tunnel" -p tcp --tcp-flags SYN,RST SYN \
            -m comment --comment 'zt: mss' -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
            mangle4_count=$((mangle4_count + 1))
        fi
        if iptables -t mangle -A ZT-POSTROUTING -o "$tunnel" -p tcp --tcp-flags SYN,RST SYN \
            -m comment --comment 'zt: mss' -j TCPMSS --set-mss 1340 2>/dev/null; then
            mangle4_count=$((mangle4_count + 1))
        fi
    done
fi
if [ "$mangle4_count" -gt 0 ]; then
    printf '%s\n' "$mangle4_count" > "$STATE_DIR/mangle.ok"
else
    rm -f "$STATE_DIR/mangle.ok"
fi

# ---- IPv6 filter & two-stage TCPMSS clamping -------------------------------
# The engine reaches the container over IPv4, so nobody on $wan or any tunnel
# may open unsolicited TCP or UDP connections over IPv6. On kernels booted with
# ipv6.disable=1 (/proc/sys/net/ipv6 absent), skip ip6tables cleanly.
if [ -d /proc/sys/net/ipv6 ]; then
    ensure_chain_first ip6tables filter INPUT ZT-INPUT
    ip6tables -t filter -A ZT-INPUT -i lo \
        -m comment --comment 'zt: loopback' -j ACCEPT
    ip6tables -t filter -A ZT-INPUT ! -i lo -d ::1/128 \
        -m comment --comment 'zt: loopback guard' -j DROP
    ip6tables -t filter -A ZT-INPUT -m conntrack --ctstate ESTABLISHED,RELATED \
        -m comment --comment 'zt: replies' -j ACCEPT
    ip6tables -t filter -A ZT-INPUT -i "$wan" -p udp --dport 546 \
        -m comment --comment 'zt: dhcpv6' -j ACCEPT
    ip6tables -t filter -A ZT-INPUT -i "$wan" -p tcp \
        -m comment --comment 'zt: host only' -j DROP
    ip6tables -t filter -A ZT-INPUT -i "$wan" -p udp \
        -m comment --comment 'zt: host only udp' -j DROP
    ip6tables -t filter -A ZT-INPUT ! -i "$wan" -p tcp \
        -m comment --comment 'zt: tunnel' -j DROP
    ip6tables -t filter -A ZT-INPUT ! -i "$wan" -p udp \
        -m comment --comment 'zt: tunnel udp' -j DROP

    mangle6_count=0
    if ensure_chain_first ip6tables mangle POSTROUTING ZT-POSTROUTING 2>/dev/null; then
        for tunnel in tun+ utun+ vnic+; do
            if ip6tables -t mangle -A ZT-POSTROUTING -o "$tunnel" -p tcp --tcp-flags SYN,RST SYN \
                -m comment --comment 'zt: mss' -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; then
                mangle6_count=$((mangle6_count + 1))
            fi
            if ip6tables -t mangle -A ZT-POSTROUTING -o "$tunnel" -p tcp --tcp-flags SYN,RST SYN \
                -m comment --comment 'zt: mss' -j TCPMSS --set-mss 1220 2>/dev/null; then
                mangle6_count=$((mangle6_count + 1))
            fi
        done
    fi
    if [ "$mangle6_count" -gt 0 ]; then
        printf '%s\n' "$mangle6_count" > "$STATE_DIR/mangle6.ok"
    else
        rm -f "$STATE_DIR/mangle6.ok"
    fi
else
    rm -f "$STATE_DIR/mangle6.ok"
fi
