# syntax=docker/dockerfile:1
# Qianxin TrustAgent client on zt-base (official ubuntu:24.04 + official KasmVNC).
#
# Built from SHA256-verified official Ubuntu compat libs (libssl1.1 / libevent)
# and the SHA256-pinned TrustAgent .deb mirror (Qianxin has no anonymous public CDN).
ARG BASE_IMAGE

FROM ubuntu:24.04 AS vendor
COPY ./blobs/ /blobs/
RUN dpkg-deb -x /blobs/trustagent.deb /build/ \
    && dpkg-deb -x /blobs/libssl11.deb /extra/ \
    && ([ ! -f /blobs/libevent21.deb ] || dpkg-deb -x /blobs/libevent21.deb /extra/)

FROM ${BASE_IMAGE}
USER root
ARG DEBIAN_FRONTEND=noninteractive

# The client runs on Ubuntu's Qt5 (its bundled arm64 Qt ships an x86-64
# libqsqlite.so and cannot open its own database).
RUN apt-get update && apt-get install -y --no-install-recommends \
        fonts-wqy-microhei \
        libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0 libxcb-xinerama0 libxcb-xinput0 \
        python3-xdg python-is-python3 \
        psmisc zip net-tools dmidecode mousepad udev bind9-dnsutils \
        libqt5core5t64 libqt5gui5 libqt5widgets5 libqt5sql5 libqt5sql5-sqlite \
        libqt5qml5 libqt5quick5 libqt5quickwidgets5 libqt5webchannel5 libqt5websockets5 \
        libqt5webenginecore5 libqt5webenginewidgets5 libqt5svg5 libqt5concurrent5 \
        libsqlite3-dev microsocks \
    && rm -rf /var/lib/apt/lists/*

COPY --from=vendor /build/usr/ /usr/
COPY --from=vendor /build/opt/ /opt/
COPY --from=vendor /extra/usr/ /usr/

COPY ./rootfs/ /

# Initialize TrustAgent directories, permissions, Qt symlinks, CA certificate,
# shared library search paths, and systemd units directly (no third-party repo).
RUN app=/opt/apps/com.qianxin.trustagent \
    && bin="$app/files/bin" \
    && lib="$app/files/lib" \
    && chmod 0755 /usr/local/bin/zt-init /usr/local/bin/zt-net-setup.sh \
                  /usr/bin/nmcli /usr/local/bin/zt-trustagent-routes.sh \
                  /usr/local/bin/zt-vnic-add.sh /usr/local/bin/zt-vnic-remove.sh \
    && chmod 0644 /etc/systemd/system/zt-net.service /etc/systemd/system/zt-socks.service \
                  /etc/systemd/system/trustdservice.service /etc/systemd/system/trustservice.service \
                  /etc/systemd/system/trustservicemgr.service /etc/systemd/system/trustnet.service \
                  /etc/systemd/system/udev-vnic-add@.service /etc/systemd/system/udev-vnic-remove@.service \
                  /etc/udev/rules.d/99-vnic.rules /etc/zt/state-paths.conf \
                  /etc/zt/openbox/menu.xml \
    && install -d -m 1777 /var/log/TrustAgent \
    && install -d -m 1777 /usr/share/trustagent \
    && touch /var/log/trustcore.log && chmod 666 /var/log/trustcore.log \
    && echo 'install_type=user' > /var/log/TrustAgent/install.txt \
    && chmod -R u=rwX,g=rX,o=rX "$app" \
    && chmod +x "$bin/TrustAgent" "$bin/trustdns" "$bin/trustdservice" \
                "$bin/trustservice" "$bin/trustservicemgr" "$bin/trustvnic" \
    && cp "$bin/rootCA.pem" /usr/share/ca-certificates/ztna_server.pem \
    && (grep -q '^ztna_server\.pem$' /etc/ca-certificates.conf 2>/dev/null \
        || echo 'ztna_server.pem' >> /etc/ca-certificates.conf) \
    && update-ca-certificates --fresh \
    && ([ ! -f "$lib/build_qt_ln.sh" ] || /bin/sh "$lib/build_qt_ln.sh") \
    && rm -f "$lib/plugins/sqldrivers/libqsqlite.so" \
    && find "$app/files" -name '*.so*' -printf '%h\n' | sort -u \
        > /etc/ld.so.conf.d/zz-qianxin-trustagent.conf \
    && ldconfig \
    && install -d -o kasm-user -g kasm-user /home/kasm-user/.TrustAgent \
    && cp "$bin/TrustAgentExtra.config" /home/kasm-user/.TrustAgent/TrustAgentExtra.config \
    && cp /etc/zt/openbox/menu.xml /home/kasm-user/.config/openbox/menu.xml \
    && echo 'XTerm*selectToClipboard: true' >> /home/kasm-user/.Xresources \
    && chown -R kasm-user:kasm-user /home/kasm-user \
    && chmod -R o-w /home/kasm-user \
    && systemctl enable trustdservice.service trustservice.service trustservicemgr.service \
                        trustnet.service systemd-udevd.service zt-net.service zt-socks.service

ENV BYPASS_ROUTES=""

# PID 1 (zt-init -> systemd) starts as root; desktop and SOCKS units run unprivileged.
USER root
ENTRYPOINT ["/usr/local/bin/zt-init"]
