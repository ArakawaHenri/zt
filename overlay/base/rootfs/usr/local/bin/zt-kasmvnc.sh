#!/bin/bash
# Start KasmVNC (:1, HTTPS on 6901) and run Openbox in the foreground.
#   ZT_AUTH=0 (default, accept local): loopback-only, passwordless (-disableBasicAuth)
#   ZT_AUTH=1 (accept all): HTTP Basic Auth enforced for kasm_user using VNC_PW
set -eu

export HOME=/home/kasm-user
export DISPLAY=:1

auth=${ZT_AUTH:-0}
case "$auth" in
    0|1) ;;
    *) echo "zt-kasmvnc: invalid ZT_AUTH '$auth' (expected 0 or 1)" >&2; exit 1 ;;
esac

mkdir -p "$HOME/.vnc"
chmod 700 "$HOME/.vnc"

if [ ! -f "$HOME/.vnc/self.pem" ]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$HOME/.vnc/self.pem" -out "$HOME/.vnc/self.pem" \
        -subj '/C=US/ST=VA/L=None/O=None/OU=zt/CN=kasmvnc' >/dev/null 2>&1
    chmod 600 "$HOME/.vnc/self.pem"
fi

rm -f "$HOME/.kasmpasswd"
if [ "$auth" = 1 ]; then
    if [ -z "${VNC_PW:-}" ]; then
        echo 'zt-kasmvnc: VNC_PW is required when ZT_AUTH=1' >&2
        exit 1
    fi
    printf '%s\n%s\n' "$VNC_PW" "$VNC_PW" | kasmvncpasswd -u kasm_user -wo >/dev/null
else
    # KasmVNC's vncserver wrapper checks for ~/.kasmpasswd even with -disableBasicAuth;
    # seed an unused random entry so startup stays non-interactive.
    dummy=$(openssl rand -hex 4)
    printf '%s\n%s\n' "$dummy" "$dummy" | kasmvncpasswd -u kasm_user -wo >/dev/null
fi
chmod 600 "$HOME/.kasmpasswd"

# Clean stale display locks left by an unclean container stop.
vncserver -kill :1 >/dev/null 2>&1 || true
rm -f "$HOME/.vnc/"*.pid /tmp/.X1-lock /tmp/.X11-unix/X1

printf '#!/bin/sh\nexit 0\n' > "$HOME/.vnc/xstartup"
chmod 700 "$HOME/.vnc/xstartup"

vnc_args=(
    :1
    -depth 24
    -geometry 1280x720
    -websocketPort 6901
    -httpd /usr/share/kasmvnc/www
    -sslOnly 1
    -FrameRate=24
    -interface 0.0.0.0
    -BlacklistThreshold=0
    -FreeKeyMappings
    -select-de manual
    -PreferBandwidth
    -DynamicQualityMin=4
    -DynamicQualityMax=7
    -DLP_ClipDelay=0
)
if [ "$auth" = 0 ]; then
    vnc_args+=(-disableBasicAuth)
fi

if [ -f /lib/aarch64-linux-gnu/libgcc_s.so.1 ]; then
    LD_PRELOAD=/lib/aarch64-linux-gnu/libgcc_s.so.1 vncserver "${vnc_args[@]}"
else
    vncserver "${vnc_args[@]}"
fi

for _ in $(seq 30); do
    xdpyinfo -display :1 >/dev/null 2>&1 && break
    sleep 0.5
done

xset -dpms >/dev/null 2>&1 || true
xset s off >/dev/null 2>&1 || true

exec /usr/bin/openbox-session
