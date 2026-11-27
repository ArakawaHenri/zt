# syntax=docker/dockerfile:1
# Minimal KasmVNC web desktop on official ubuntu:24.04 with systemd as PID 1.
#
# Built directly from Canonical's official ubuntu:24.04 image and the official
# SHA256-verified kasmtech/KasmVNC GitHub release .deb — zero third-party base
# images or git forks.
FROM ubuntu:24.04

USER root
ARG DEBIAN_FRONTEND=noninteractive

COPY ./blobs/kasmvncserver.deb /tmp/kasmvncserver.deb

RUN apt-get update \
    && ln -fs /usr/share/zoneinfo/Etc/UTC /etc/localtime \
    && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus dbus-x11 \
        tzdata locales ca-certificates openssl \
        iproute2 iptables iputils-ping \
        openbox stalonetray wmctrl x11-utils x11-xserver-utils xclip xterm \
        python3 gettext ssl-cert libxfont2 \
    && apt-get install -y --no-install-recommends /tmp/kasmvncserver.deb \
    && rm -f /tmp/kasmvncserver.deb \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i 's/^# *en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen \
    && locale-gen en_US.UTF-8 \
    && sed -i 's/NLIMC/NLMC/g' /etc/xdg/openbox/rc.xml \
    && userdel -r ubuntu 2>/dev/null || true \
    && groupadd -g 1000 kasm-user \
    && useradd -m -u 1000 -g 1000 -G ssl-cert -s /bin/bash kasm-user

COPY ./rootfs/ /

RUN chmod 0755 /usr/local/bin/zt-kasmvnc.sh \
    && chmod 0644 /etc/kasmvnc/kasmvnc.yaml /etc/systemd/system/kasmvnc.service \
                  /etc/zt/openbox/autostart /etc/zt/openbox/menu.xml \
    && install -d -o root -g root -m 0755 /var/lib/zt-state \
    && install -d -o kasm-user -g kasm-user /home/kasm-user/.config/openbox \
    && cp /etc/zt/openbox/autostart /home/kasm-user/.config/openbox/autostart \
    && cp /etc/zt/openbox/menu.xml /home/kasm-user/.config/openbox/menu.xml \
    && chown -R kasm-user:kasm-user /home/kasm-user \
    && chmod 750 /home/kasm-user \
    && chmod -R o-w /home/kasm-user \
    && systemctl mask proc-sys-fs-binfmt_misc.automount proc-sys-fs-binfmt_misc.mount \
    && systemctl enable kasmvnc.service

ENV DISPLAY=:1 \
    HOME=/home/kasm-user \
    LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    TERM=xterm \
    TZ=Etc/UTC

EXPOSE 6901
WORKDIR /home/kasm-user
# PID 1 (systemd) must start as root; individual units drop to kasm-user/nobody with NoNewPrivileges.
USER root
ENTRYPOINT ["/lib/systemd/systemd"]
