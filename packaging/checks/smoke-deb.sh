#!/usr/bin/env bash
# Install-smoke test for a built .deb. Runs INSIDE a debian:12 container with
# the repository (or at least packaging/) mounted at /work.
# Usage: smoke-deb.sh <path/to/pkg.deb> <package-name> node|gui
set -euo pipefail

DEB_FILE="$1"
PKG_NAME="$2"
KIND="$3"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

apt-get install -y -qq systemd desktop-file-utils >/dev/null 2>&1 || true
apt-get install -y -qq "./$DEB_FILE" >/dev/null

echo "== dpkg status =="
dpkg -s "$PKG_NAME" | grep -E "^(Status|Version|Depends):"

if [ "$KIND" = node ]; then
    echo "== system user =="
    id mintlayer

    echo "== binaries =="
    for bin in node-daemon wallet-rpc-daemon api-web-server \
               api-blockchain-scanner-daemon dns-server wallet-cli \
               wallet-address-generator; do
        test -x "/usr/bin/mintlayer-$bin"
        "/usr/bin/mintlayer-$bin" --help >/dev/null 2>&1
        echo "  ok: mintlayer-$bin --help"
    done

    echo "== systemd units =="
    for unit in /usr/lib/systemd/system/mintlayer-*.service; do
        systemd-analyze verify "$unit"
        echo "  ok: $(basename "$unit")"
    done
    test -f /usr/lib/systemd/system-preset/90-mintlayer.preset
    grep -q "enable mintlayer-node@mainnet.service" \
        /usr/lib/systemd/system-preset/90-mintlayer.preset
    test -f /usr/lib/sysusers.d/mintlayer.conf
    test -f /usr/lib/udev/rules.d/51-mintlayer.rules
    test -f /etc/mintlayer/mainnet/node.env
    test -f /etc/mintlayer/testnet/node.env
    echo "  ok: preset/sysusers/udev/conffiles present"

    echo "== man pages =="
    ls /usr/share/man/man1/mintlayer-*.1.gz >/dev/null
    echo "  ok"
else
    echo "== gui files =="
    test -x /usr/bin/mintlayer-node-gui
    /usr/bin/mintlayer-node-gui --help >/dev/null 2>&1
    echo "  ok: mintlayer-node-gui --help"

    desktop-file-validate /usr/share/applications/mintlayer-node-gui.desktop
    echo "  ok: desktop file valid"

    for size in 64 128 256 512; do
        test -f "/usr/share/icons/hicolor/${size}x${size}/apps/mintlayer-node-gui.png"
    done
    echo "  ok: icons present"

    ls /usr/share/man/man1/mintlayer-node-gui.1.gz >/dev/null
    echo "  ok: man page"
fi

echo "SMOKE OK: $PKG_NAME ($KIND)"
