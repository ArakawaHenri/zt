# Sangfor EasyConnect client (UOS arm64) on zt-base (official ubuntu:24.04 + KasmVNC).
#
# Built directly from the SHA256-verified official Sangfor archive
# (download.sangfor.com.cn) and official Electron 1.8.8 arm64 release
# (github.com/electron/electron) with zero third-party git repositories.
ARG BASE_IMAGE=localhost/zt-base:local

FROM ${BASE_IMAGE}
USER root
ARG DEBIAN_FRONTEND=noninteractive
ARG VPN_DEB_PATH
ARG MIRROR_URL=http://deb.debian.org/debian

# The client is a GTK2 application and Ubuntu Noble no longer ships GTK2, so
# libgtk2.0-0, libdbus-glib and libgconf come from Debian bookworm: verified
# against Debian's own keyring, and pinned below Noble so that they only fill
# the gaps. The bookworm source is removed again with the package lists.
RUN apt-get update \
    && apt-get install -y --no-install-recommends debian-archive-keyring \
    && keyring="$(ls /usr/share/keyrings/debian-archive-keyring.gpg \
                        /usr/share/keyrings/debian-archive-keyring.pgp 2>/dev/null | head -n 1)" \
    && [ -n "$keyring" ] \
    && echo "deb [signed-by=$keyring] ${MIRROR_URL} bookworm main" \
        > /etc/apt/sources.list.d/zt-bookworm.list \
    && printf 'Package: *\nPin: release n=bookworm\nPin-Priority: 100\n' \
        > /etc/apt/preferences.d/zt-bookworm \
    && apt-get update \
    && apt-get install -y --no-install-recommends --no-install-suggests \
        libx11-xcb1 libnss3 libasound2t64 libxtst6 \
        psmisc busybox net-tools libxss1 fonts-wqy-microhei socat \
        libgtk2.0-0 libdbus-glib-1-2 libgconf-2-4 \
    && rm -rf /var/lib/apt/lists/* \
        /etc/apt/sources.list.d/zt-bookworm.list /etc/apt/preferences.d/zt-bookworm

COPY ./rootfs/usr/local/sbin/zt-iptables /usr/local/sbin/zt-iptables
COPY ./install-deb.sh /tmp/install-deb.sh
COPY ./blobs/easyconnect.pkg /tmp/easyconnect.pkg
COPY ./blobs/electron.zip /tmp/electron.zip

# Unpack the official Sangfor EasyConnect package (.zip on arm64 or direct .deb
# on amd64), run its maintainer scripts, replace its bundled Electron binary
# with official Electron 1.8.8, and restore root ownership over system paths.
RUN chmod 0755 /usr/local/sbin/zt-iptables /tmp/install-deb.sh \
    && if [ -n "${VPN_DEB_PATH}" ]; then \
        busybox unzip -p /tmp/easyconnect.pkg "${VPN_DEB_PATH}" > /tmp/vpn.deb; \
        rm -f /tmp/easyconnect.pkg; \
    else \
        mv /tmp/easyconnect.pkg /tmp/vpn.deb; \
    fi \
    && /tmp/install-deb.sh /tmp/vpn.deb \
    && rm -f /tmp/install-deb.sh \
    && for cmd in iptables iptables-save iptables-restore \
                  ip6tables ip6tables-save ip6tables-restore; do \
           ln -snf /usr/local/sbin/zt-iptables "/usr/sbin/$cmd"; \
       done \
    && ln -fs /bin/false /usr/sbin/dmidecode \
    && rm -f /usr/share/sangfor/EasyConnect/resources/conf/easy_connect.json \
    && mv /usr/share/sangfor/EasyConnect/resources/conf /usr/share/sangfor/EasyConnect/resources/conf_backup \
    && busybox unzip -oq /tmp/electron.zip -d /usr/share/sangfor/EasyConnect/ \
    && rm -f /tmp/electron.zip \
    && mv /usr/share/sangfor/EasyConnect/electron /usr/share/sangfor/EasyConnect/EasyConnect \
    && find / -xdev -user 1000 ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' ! -path '/run/*' \
        ! -path '/home/*' ! -path '/usr/share/kasmvnc/*' \
        -exec chown root:root {} + \
    && chmod -R u=rwX,go=rX /usr/share/sangfor \
    && for d in /opt/apps /etc/init /usr/share/applications /usr/share/pixmaps; do \
           [ ! -e "$d" ] || chmod -R a+rX "$d"; \
       done \
    && chmod a+rX /usr/lib/systemd/system/EasyMonitor.service \
    && chmod 1777 /usr/share/sangfor/EasyConnect/resources/logs \
    && install -d -o kasm-user -g kasm-user /usr/share/sangfor/EasyConnect/resources/conf \
    && chmod 6750 /usr/share/sangfor/EasyConnect/resources/bin/CSClient \
                  /usr/share/sangfor/EasyConnect/resources/bin/ECAgent \
                  /usr/share/sangfor/EasyConnect/resources/bin/svpnservice

COPY ./rootfs/ /

RUN chmod 0755 /etc /etc/systemd /etc/systemd/system \
               /etc/systemd/system/EasyMonitor.service.d /etc/zt \
               /usr /usr/bin /usr/local /usr/local/bin /usr/local/sbin \
               /usr/share /usr/share/sangfor /usr/share/sangfor/EasyConnect \
               /usr/share/sangfor/EasyConnect/resources \
               /usr/share/sangfor/EasyConnect/resources/shell \
               /usr/local/bin/zt-init /usr/local/bin/zt-identity \
               /usr/local/bin/zt-net-setup.sh /usr/local/sbin/zt-iptables \
               /usr/bin/xdg-open /usr/local/bin/zt-conf.sh \
               /usr/local/bin/zt-sangfor-daemon.sh /usr/local/bin/zt-sangfor-ui.sh \
               /usr/share/sangfor/EasyConnect/resources/shell/open_browser.sh \
    && [ "$(readlink /usr/sbin/iptables)" = /usr/local/sbin/zt-iptables ] \
    && chmod 0644 /etc/systemd/system/zt-net.service \
                  /etc/systemd/system/zt-sangfor-daemon.service \
                  /etc/systemd/system/zt-sangfor-ui.service \
                  /etc/systemd/system/EasyMonitor.service.d/zt.conf \
                  /etc/zt/state-paths.conf \
    && install -d -o kasm-user -g kasm-user /home/kasm-user/conf \
    && chown -R kasm-user:kasm-user /home/kasm-user \
    && chmod -R o-w /home/kasm-user \
    && systemctl enable zt-net.service zt-sangfor-daemon.service zt-sangfor-ui.service

# PID 1 (zt-init -> systemd) starts as root; desktop and SOCKS units run unprivileged.
USER root
ENTRYPOINT ["/usr/local/bin/zt-init"]
