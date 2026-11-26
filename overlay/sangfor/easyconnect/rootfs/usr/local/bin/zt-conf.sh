#!/bin/bash
# EasyConnect keeps its login state in ~/conf of whoever runs it.
# zt-sangfor.service runs this script as kasm-user (never root) around each
# session so symlinks inside kasm-user-owned directories cannot cross a
# privilege boundary.
set -eu
shopt -s nullglob
res=/usr/share/sangfor/EasyConnect/resources
home=/home/kasm-user

case ${1:-} in
init)
    mkdir -p "$home/conf" "$res/conf"
    for f in "$res"/conf_backup/*; do
        base=$(basename "$f")
        [ -e "$home/conf/$base" ] || cp -rP -- "$f" "$home/conf/$base"
    done
    rm -f "$home/conf/ECDomainFile"
    for f in "$home"/conf/*; do
        ln -sfn "$f" "$res/conf/$(basename "$f")"
    done
    # Clients built for non-amd64 hosts cannot pass the vendor's version check.
    ln -fsn /dev/null "$res/conf/pkg_version.xml"
    ;;
sync)
    cd "$res/conf"
    rm -f pkg_version.xml
    for f in *; do
        [ -r "$f" ] && [ ! -L "$f" ] && [ ECDomainFile != "$f" ] && cp -rP -- "$f" "$home/conf/"
    done
    cd "$home/conf"
    for f in *; do
        [ ! -e "$res/conf/$f" ] && rm -rf -- "$f"
    done
    ;;
*)
    echo 'usage: zt-conf.sh init|sync' >&2
    exit 2
    ;;
esac
