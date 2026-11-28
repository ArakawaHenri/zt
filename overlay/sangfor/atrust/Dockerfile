# Sangfor aTrust client on zt-base (official ubuntu:24.04 + official KasmVNC).
#
# Built directly from the SHA256-verified official Sangfor aTrust arm64 .deb
# (atrustcdn.sangfor.com) with zero third-party git repositories.
ARG BASE_IMAGE=localhost/zt-base:local

FROM ${BASE_IMAGE} AS shims
USER root
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY ./src/fake-getlogin.c /src/fake-getlogin.c
RUN gcc -shared -fPIC -O2 -o /usr/local/lib/fake-getlogin.so /src/fake-getlogin.c

FROM ${BASE_IMAGE}
USER root
ARG DEBIAN_FRONTEND=noninteractive

# The tray is an Electron application: libnss3, libasound2t64 and libxss1 are
# what it needs beyond a plain GTK3 desktop.
RUN apt-get update && apt-get install -y --no-install-recommends --no-install-suggests \
        libgtk-3-0t64 libgbm1 libnss3 libasound2t64 libxss1 \
        libatk-bridge2.0-0t64 libqt5x11extras5 procps libqt5core5t64 \
        libqt5network5t64 libqt5widgets5t64 libldap2 libproxy1v5 \
        psmisc socat fonts-wqy-microhei \
    && rm -rf /var/lib/apt/lists/*

COPY --from=shims /usr/local/lib/fake-getlogin.so /usr/local/lib/fake-getlogin.so
COPY ./rootfs/usr/bin/loginctl /usr/bin/loginctl
COPY ./rootfs/usr/sbin/sysctl-hook /usr/sbin/sysctl-hook
COPY ./rootfs/usr/local/sbin/zt-iptables /usr/local/sbin/zt-iptables
COPY ./install-deb.sh /tmp/install-deb.sh
COPY ./blobs/atrust.deb /tmp/atrust.deb

# Unpack the official Sangfor aTrust .deb and run its maintainer scripts.
# sysctl-hook, loginctl, and zt-iptables must be in place before postinst runs.
RUN chmod 0755 /usr/bin/loginctl /usr/sbin/sysctl-hook /usr/local/sbin/zt-iptables /tmp/install-deb.sh \
    && mv /usr/sbin/sysctl /usr/sbin/sysctl.real \
    && ln -s /usr/sbin/sysctl-hook /usr/sbin/sysctl \
    && /tmp/install-deb.sh /tmp/atrust.deb \
    && rm -f /tmp/install-deb.sh \
    && ([ ! -e /home/sangfor ] || chown -R sangfor:sangfor /home/sangfor) \
    && ([ ! -d /usr/share/sangfor/.aTrust ] || chmod 1777 /usr/share/sangfor/.aTrust) \
    && ln -fs /bin/false /usr/sbin/dmidecode \
    && chmod a-s /usr/share/sangfor/aTrust/uem/bin/uem_installer \
                 /usr/share/sangfor/aTrust/resources/bin/dmidecode_processor_tool \
    && chmod -R go-w /usr/share/sangfor/aTrust/resources/app

COPY ./rootfs/ /

RUN chmod 0755 /etc /etc/systemd /etc/systemd/system \
               /etc/systemd/system/aTrustDaemon.service.d \
               /etc/systemd/system/eaio_service.service.d \
               /etc/zt /usr /usr/bin /usr/local /usr/local/bin /usr/local/sbin /usr/sbin \
               /usr/local/bin/zt-init /usr/local/bin/zt-identity \
               /usr/local/bin/zt-net-setup.sh /usr/local/sbin/zt-iptables \
               /usr/bin/xdg-open /usr/bin/loginctl /usr/sbin/sysctl-hook \
               /usr/local/bin/zt-sangfor-daemon.sh /usr/local/bin/zt-sangfor-ui.sh \
    && [ "$(readlink /usr/sbin/iptables)" = /usr/local/sbin/zt-iptables ] \
    && chmod 0644 /etc/systemd/system/zt-net.service \
                  /etc/systemd/system/zt-sangfor-daemon.service \
                  /etc/systemd/system/zt-sangfor-ui.service \
                  /etc/systemd/system/aTrustDaemon.service.d/zt.conf \
                  /etc/systemd/system/eaio_service.service.d/zt.conf \
                  /etc/zt/state-paths.conf \
    && chown -R kasm-user:kasm-user /home/kasm-user \
    && chmod -R o-w /home/kasm-user \
    && systemctl enable zt-net.service zt-sangfor-daemon.service zt-sangfor-ui.service

# PID 1 (zt-init -> systemd) starts as root; desktop and SOCKS units run unprivileged.
USER root
ENTRYPOINT ["/usr/local/bin/zt-init"]
