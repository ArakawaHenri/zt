#!/bin/sh
# Unpack a Sangfor vendor .deb into / and run its preinst/postinst maintainer
# scripts with the expected /var/lib/dpkg/info layout, then remove /DEBIAN and
# the temporary archive.
set -eu

deb=$1
dpkg-deb -R "$deb" /
pkg=$(awk -F': *' '/^Package:/ {print $2; exit}' /DEBIAN/control)
[ ! -x /DEBIAN/preinst ] || /DEBIAN/preinst || true
mkdir -p "/var/lib/dpkg/info/$pkg"
for f in /DEBIAN/*; do
    [ -e "$f" ] || continue
    base=$(basename "$f")
    cp "$f" "/var/lib/dpkg/info/$pkg.$base"
    cp "$f" "/var/lib/dpkg/info/$base"
done
"/var/lib/dpkg/info/$pkg.postinst"
for f in /DEBIAN/*; do
    [ -e "$f" ] || continue
    rm -f "/var/lib/dpkg/info/$(basename "$f")"
done
rm -rf /DEBIAN "$deb"
