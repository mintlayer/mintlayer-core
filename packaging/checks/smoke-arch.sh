#!/usr/bin/env bash
# Install-smoke test for a built .pkg.tar.zst. Runs INSIDE an archlinux:base
# container with the repository mounted at /work.
# Usage: smoke-arch.sh <path/to/pkg.pkg.tar.zst> <package-name> node|gui [pkg-arch]
#
# The optional fourth argument is the architecture the package was built for
# (defaults to the container architecture). Docker Hub publishes no arm64
# Arch image (library/archlinux and archlinux/archlinux are amd64-only), so a
# foreign-architecture package (the cross-target aarch64 leg reuses the
# amd64-only image) is smoke-tested in a chroot of the Arch Linux ARM rootfs:
# the package and its dependencies are installed by the chroot's pacman and
# its binaries execute through the host's qemu binfmt handlers — the same
# emulation the deb/rpm legs use for their arm64 smoke tests.
set -euo pipefail

CHROOT_DIR=/alarm
# Primary + fallback download locations for the Arch Linux ARM rootfs; the
# env var overrides for local testing (e.g. a pre-downloaded file:// copy).
alarm_rootfs_urls() {
    if [ -n "${ALARM_ROOTFS_URL:-}" ]; then
        printf '%s\n' "$ALARM_ROOTFS_URL"
    else
        printf '%s\n' \
            https://fl.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz \
            https://mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz
    fi
}

# Shared binary list (NODE_BINARIES). Inside the chroot the repo tree is not
# visible; the foreign-arch branch copies lib.sh in next to the script.
if [ "${1:-}" = "--chroot" ]; then
    . /smoke-lib.sh
else
    . "$(cd "$(dirname "${BASH_SOURCE[0]}")/../common" && pwd)/lib.sh"
fi

# Inside the ARM chroot pacman must not drop to its download sandbox user:
# the (emulated) setuid switch fails under the container's seccomp profile.
pacman_cmd() {
    if [ -n "${SMOKE_CHROOT:-}" ]; then
        pacman --disable-sandbox "$@"
    else
        pacman "$@"
    fi
}

main() {
    # Sync the databases so the package dependencies resolve from the repos.
    pacman_cmd -Sy --noconfirm >/dev/null
    pacman_cmd -U --noconfirm "$PKG_FILE" >/dev/null

    echo "== pacman query =="
    pacman_cmd -Qi "$PKG_NAME"

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
        pacman_cmd -Ql "$PKG_NAME" | grep -q "usr/share/man/man1/mintlayer-.*\.1\.gz$"
        echo "  ok"
    else
        echo "== gui files =="
        test -x /usr/bin/mintlayer-node-gui
        "/usr/bin/mintlayer-node-gui" --help >/dev/null 2>&1
        echo "  ok: mintlayer-node-gui --help"

        pacman_cmd -S --noconfirm --needed desktop-file-utils >/dev/null
        desktop-file-validate /usr/share/applications/mintlayer-node-gui.desktop

        echo "== icons =="
        for size in 64x64 128x128 256x256 512x512; do
            test -f "/usr/share/icons/hicolor/${size}/apps/mintlayer-node-gui.png"
            echo "  ok: hicolor ${size}"
        done

        echo "== man pages =="
        pacman_cmd -Ql "$PKG_NAME" | grep -q "usr/share/man/man1/mintlayer-node-gui\.1\.gz$"
        echo "  ok"
    fi

    echo "smoke test passed for $PKG_NAME"
}

# Re-entry mode: the foreign-arch branch below invokes this script inside the
# ARM chroot with `--chroot <pkg-in-chroot> <package-name> node|gui`.
if [ "${1:-}" = "--chroot" ]; then
    shift
    SMOKE_CHROOT=1
    PKG_FILE="$1"
    PKG_NAME="$2"
    KIND="$3"
    main
    exit 0
fi

PKG_FILE="$(readlink -f "$1")"
PKG_NAME="$2"
KIND="$3"
PKG_ARCH="${4:-$(uname -m)}"

if [ "$PKG_ARCH" = "$(uname -m)" ]; then
    main
    exit 0
fi

echo "foreign-architecture package ($PKG_ARCH on $(uname -m)): smoke-testing in an Arch Linux ARM chroot"

# Assemble a native $PKG_ARCH userland. Requires qemu binfmt handlers for the
# architecture to be registered on the runner's kernel (release_linux.yml
# sets them up via docker/setup-qemu-action; the F-flag keeps them working
# inside the chroot).
mkdir -p "$CHROOT_DIR"
rootfs_tar=/tmp/alarm.tar.gz
rc=1
for url in "$(alarm_rootfs_urls)"; do
    echo "downloading ARM rootfs from $url"
    if curl --proto '=https' --tlsv1.2 -sSfL -o "$rootfs_tar" "$url"; then rc=0; break; fi
done
[ "$rc" -eq 0 ] || { echo "ERROR: could not download the Arch Linux ARM rootfs" >&2; exit 1; }
# The rootfs ships device nodes we cannot recreate inside an unprivileged
# container; skip them. Remaining tar warnings are non-fatal.
tar -xzf "$rootfs_tar" -C "$CHROOT_DIR" --exclude='./dev/*' 2>/dev/null || true

# chroot plumbing the rootfs does not ship: DNS resolution and a mount table
# (pacman reads /etc/mtab for its free-space check; /proc is not mounted here,
# so a static copy of the container's table is used).
rm -f "$CHROOT_DIR/etc/resolv.conf"
cp -L /etc/resolv.conf "$CHROOT_DIR/etc/resolv.conf"
rm -f "$CHROOT_DIR/etc/mtab"
cp /proc/self/mounts "$CHROOT_DIR/etc/mtab"

# Initialize the chroot's pacman keyring from the container: gpg inside the
# chroot would run under emulation, and pacman-key's --populate needs
# process substitution (/dev/fd), which requires a mounted /proc the chroot
# does not have. The host container's pacman-key can act on the chroot's
# keyring via --gpgdir once the archlinuxarm keyring is visible to it.
cp "$CHROOT_DIR/usr/share/pacman/keyrings/archlinuxarm.gpg" /usr/share/pacman/keyrings/
pacman-key --gpgdir "$CHROOT_DIR/etc/pacman.d/gnupg" --init >/dev/null
pacman-key --gpgdir "$CHROOT_DIR/etc/pacman.d/gnupg" --populate archlinuxarm >/dev/null

# /work is not visible inside the chroot: copy the script, its lib.sh and the
# package in.
cp "$PKG_FILE" "$CHROOT_DIR/$(basename "$PKG_FILE")"
cp "$0" "$CHROOT_DIR/smoke-arch.sh"
cp "$(cd "$(dirname "$0")/../common" && pwd)/lib.sh" "$CHROOT_DIR/smoke-lib.sh"

chroot "$CHROOT_DIR" /smoke-arch.sh --chroot "/$(basename "$PKG_FILE")" "$PKG_NAME" "$KIND"
rm -f "$CHROOT_DIR/smoke-arch.sh" "$CHROOT_DIR/smoke-lib.sh" "$CHROOT_DIR/$(basename "$PKG_FILE")"
