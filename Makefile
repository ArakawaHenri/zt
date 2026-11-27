SRC := $(shell find src -type f -name '*.py')
OVERLAY := $(shell find overlay -type f)
SHELL_SCRIPTS := \
	install.sh \
	overlay/base/rootfs/usr/local/bin/zt-kasmvnc.sh \
	overlay/common/rootfs/usr/local/bin/zt-init \
	overlay/common/rootfs/usr/local/bin/zt-net-setup.sh \
	overlay/sangfor/common/install-deb.sh \
	overlay/sangfor/common/rootfs/usr/bin/xdg-open \
	overlay/sangfor/atrust/rootfs/usr/bin/loginctl \
	overlay/sangfor/atrust/rootfs/usr/sbin/sysctl-hook \
	overlay/sangfor/atrust/rootfs/usr/local/bin/zt-sangfor-session.sh \
	overlay/sangfor/easyconnect/rootfs/usr/local/bin/zt-conf.sh \
	overlay/sangfor/easyconnect/rootfs/usr/local/bin/zt-sangfor-session.sh \
	overlay/sangfor/easyconnect/rootfs/usr/share/sangfor/EasyConnect/resources/shell/open_browser.sh \
	overlay/trustagent/rootfs/usr/bin/nmcli \
	overlay/trustagent/rootfs/usr/local/bin/zt-trustagent-routes.sh \
	overlay/trustagent/rootfs/usr/local/bin/zt-vnic-add.sh \
	overlay/trustagent/rootfs/usr/local/bin/zt-vnic-remove.sh

.PHONY: all install test lint clean

all: zt

# Deterministic single-file zipapp executable: src/zt/ and overlay/ bundled together.
zt: $(SRC) tools/mkzt.py $(OVERLAY)
	python3 tools/mkzt.py -o zt

zt.pyz: $(SRC) tools/mkzt.py $(OVERLAY)
	python3 tools/mkzt.py -o zt.pyz

PREFIX ?= /usr/local

install: zt
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 zt $(DESTDIR)$(PREFIX)/bin/zt

lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck $(SHELL_SCRIPTS); \
	else \
		echo "shellcheck not installed, skipping shell lint" >&2; \
	fi

test: zt lint
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -W error -m unittest discover -s tests -v

clean:
	rm -f zt zt.pyz
	find src tests tools -type d -name '__pycache__' -exec rm -rf {} +
