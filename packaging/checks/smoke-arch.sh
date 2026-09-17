#!/usr/bin/env bash
# Install-smoke test for a built .pkg.tar.zst. Runs INSIDE an archlinux:base
# container with the repository mounted at /work.
# Usage: smoke-arch.sh <path/to/pkg.pkg.tar.zst> <package-name> node|gui [pkg-arch]
#
# The optional fourth argument is the architecture the package was built for
# (defaults to the container architecture). For a foreign-architecture package
# (the cross-target aarch64 leg reuses the amd64-only Arch image), pacman's
# architecture check is bypassed via IgnoreArch and the binaries are executed
# through the host's qemu binfmt handlers — the same emulation the deb/rpm
# legs use for their arm64 smoke tests.
set -euo pipefail

# Shared binary list (NODE_BINARIES)
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/../common" && pwd)/lib.sh"

PKG_FILE="$(readlink -f "$1")"
PKG_NAME="$2"
KIND="$3"
PKG_ARCH="${4:-$(uname -m)}"

if [ "$PKG_ARCH" != "$(uname -m)" ]; then
    echo "foreign-architecture package ($PKG_ARCH on $(uname -m)): enabling IgnoreArch"
    sed -i "/^\[options\]$/a IgnoreArch = $PKG_ARCH" /etc/pacman.conf
fi

# Sync the databases so the package dependencies resolve from the repos.
pacman -Sy --noconfirm >/dev/null
pacman -U --noconfirm "$PKG_FILE" >/dev/null

echo "== pacman query =="
pacman -Qi "$PKG_NAME"

if [ "$KIND" = node ]; then
    echo "== system user =="
    id mintlayer

    echo "== binaries =="
    for bin in "${NODE_BINARIES[@]}"; do
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
    pacman -Ql "$PKG_NAME" | grep -q "usr/share/man/man1/mintlayer-.*\.1\.gz$"
    echo "  ok"
else
    echo "== gui files =="
    test -x /usr/bin/mintlayer-node-gui
    /usr/bin/mintlayer-node-gui --help >/dev/null 2>&1
    echo "  ok: mintlayer-node-gui --help"

    pacman -S --noconfirm --needed desktop-file-utils >/dev/null
    desktop-file-validate /usr/share/applications/mintlayer-node-gui.desktop

    echo "== icons =="
    for size in 64x64 128x128 256x256 512x512; do
        test -f "/usr/share/icons/hicolor/${size}/apps/mintlayer-node-gui.png"
        echo "  ok: hicolor ${size}"
    done

    echo "== man pages =="
    pacman -Ql "$PKG_NAME" | grep -q "usr/share/man/man1/mintlayer-node-gui\.1\.gz$"
    echo "  ok"
fi

echo "smoke test passed for $PKG_NAME"
