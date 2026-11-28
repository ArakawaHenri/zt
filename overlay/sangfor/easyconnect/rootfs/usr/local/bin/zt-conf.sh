#!/bin/bash
# Prepare EasyConnect's persistent config directory (/usr/share/sangfor/EasyConnect/resources/conf).
# zt-sangfor-daemon.service runs this script strictly as kasm-user (never root) so symlinks
# inside the persisted directory cannot cross a privilege boundary.
set -eu
shopt -s nullglob
res=/usr/share/sangfor/EasyConnect/resources
conf="$res/conf"
tmp_dir=

# shellcheck disable=SC2329
cleanup() {
    if [ -n "$tmp_dir" ]; then
        rm -rf -- "$tmp_dir"
    fi
}
trap cleanup EXIT

case ${1:-} in
init)
    mkdir -p "$conf"
    # Atomically seed any missing image defaults without overwriting user state or following symlinks.
    for f in "$res"/conf_backup/*; do
        base=$(basename "$f")
        if [ "$base" = "pkg_version.xml" ]; then
            continue
        fi
        if [ -e "$conf/$base" ] || [ -L "$conf/$base" ]; then
            continue
        fi
        tmp_dir=$(mktemp -d "$conf/.zt-seed.XXXXXX")
        cp -rP -- "$f" "$tmp_dir/$base"
        mv -n -- "$tmp_dir/$base" "$conf/$base" 2>/dev/null || true
        rm -rf -- "$tmp_dir"
        tmp_dir=
    done
    # Remove stale Unix socket left by an unclean stop; never delete user configs or certificates.
    rm -f -- "$conf/ECDomainFile"
    # Clients built for non-amd64 hosts cannot pass the vendor's version check.
    ln -fsn /dev/null "$conf/pkg_version.xml"
    ;;
*)
    echo 'usage: zt-conf.sh init' >&2
    exit 2
    ;;
esac
