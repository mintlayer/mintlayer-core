#!/usr/bin/env bash
# Install-smoke test for a built .rpm. Runs INSIDE a fedora:latest container
# with the repository mounted at /work.
# Usage: smoke-rpm.sh <path/to/pkg.rpm> <package-name> node|gui
set -euo pipefail

RPM_FILE="$(readlink -f "$1")"
PKG_NAME="$2"
KIND="$3"

dnf install -y -q systemd desktop-file-utils >/dev/null
dnf install -y -q "$RPM_FILE" >/dev/null

echo "== rpm query =="
rpm -q "$PKG_NAME"
rpm -q --requires "$PKG_NAME" | head -n -2

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
    shopt -s nullglob
    units=(/usr/lib/systemd/system/mintlayer-*.service)
    shopt -u nullglob
    [ ${#units[@]} -gt 0 ] || { echo "ERROR: no mintlayer units installed" >&2; exit 1; }
    for unit in "${units[@]}"; do
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
    # NOTE: the fedora container image installs with tsflags=nodocs, so check
    # the package payload instead of the filesystem (real systems install docs).
    rpm -ql "$PKG_NAME" | grep -q "^/usr/share/man/man1/mintlayer-.*\.1\.gz$"
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

    rpm -ql "$PKG_NAME" | grep -q "^/usr/share/man/man1/mintlayer-node-gui\.1\.gz$"
    echo "  ok: man page"
fi

echo "SMOKE OK: $PKG_NAME ($KIND)"
