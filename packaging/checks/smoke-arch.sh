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

usage() {
    echo "Usage: $0 <path/to/pkg.pkg.tar.zst> <package-name> node|gui [pkg-arch]" >&2
    echo "       $0 --chroot <pkg-file-in-chroot> <package-name> node|gui  (internal, called by the foreign-arch branch)" >&2
    exit 64
}

CHROOT_MODE=0
case "${1:-}" in
    --chroot)
        CHROOT_MODE=1
        shift
        [ "$#" -eq 3 ] || usage
        ;;
    *)
        { [ "$#" -eq 3 ] || [ "$#" -eq 4 ]; } || usage
        ;;
esac

# Fail fast on an invalid kind, before any (potentially foreign-arch) setup
# work; main() repeats the check as defense in depth.
case "${3:-}" in
    node|gui) ;;
    *) usage ;;
esac

CHROOT_DIR=/alarm
# Primary + fallback download locations for the Arch Linux ARM rootfs; the
# env var override is for local testing (must be an https:// URL, since the
# download loop only permits https, and it must serve the pinned build unless
# ALARM_ROOTFS_SHA256 is overridden alongside it).
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
if [ "$CHROOT_MODE" = 1 ]; then
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
    case "$KIND" in
        node|gui) ;;
        *)
            echo "ERROR: kind must be 'node' or 'gui', got '$KIND'" >&2
            exit 64
            ;;
    esac

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
        # Capturing first avoids the pipefail SIGPIPE race: grep -q exits at the
        # first match and can kill a still-writing pacman with SIGPIPE, which
        # pipefail turns into a spurious script failure.
        package_file_list="$(pacman_cmd -Ql "$PKG_NAME")"
        grep -q "usr/share/man/man1/mintlayer-.*\.1\.gz$" <<<"$package_file_list"
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
        package_file_list="$(pacman_cmd -Ql "$PKG_NAME")"
        grep -q "usr/share/man/man1/mintlayer-node-gui\.1\.gz$" <<<"$package_file_list"
        echo "  ok"
    fi

    echo "smoke test passed for $PKG_NAME"
}

# Re-entry mode: the foreign-arch branch below invokes this script inside the
# ARM chroot with `--chroot <pkg-in-chroot> <package-name> node|gui`.
if [ "$CHROOT_MODE" = 1 ]; then
    # Enforce the pacman >= 6.1 assumption the rootfs pin documents: fail fast
    # with a clear message instead of an opaque pacman usage error. A
    # functional probe beats grepping help text (help wording is not a stable
    # upstream interface): on pacman >= 6.1 the flag parses and -Sh short-
    # circuits to the sync help with exit 0, needing no database or network.
    probe_out=""
    if ! probe_out="$(pacman --disable-sandbox -Sh 2>&1)"; then
        echo "ERROR: chroot pacman probe failed; if it rejected --disable-sandbox, pacman >= 6.1 is required. Probe output: $probe_out" >&2
        exit 1
    fi
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

if [ "$PKG_ARCH" != aarch64 ]; then
    echo "ERROR: foreign-architecture smoke tests only support aarch64, got '$PKG_ARCH'" >&2
    exit 64
fi
echo "foreign-architecture package ($PKG_ARCH on $(uname -m)): smoke-testing in an Arch Linux ARM chroot"

# Assemble a native $PKG_ARCH userland. Requires qemu binfmt handlers for the
# architecture to be registered on the runner's kernel (release_linux.yml
# sets them up via docker/setup-qemu-action; the F-flag keeps them working
# inside the chroot).
# Best-effort pre-flight: with binfmt_misc mounted, an absent qemu-aarch64
# handler means the chroot's first emulated exec would fail later anyway.
if [ -f /proc/sys/fs/binfmt_misc/status ]; then
    if [ "$(cat /proc/sys/fs/binfmt_misc/status 2>/dev/null || true)" != enabled ]; then
        echo "ERROR: binfmt_misc is mounted but disabled; emulation would fail at the first exec (enable with: echo 1 > /proc/sys/fs/binfmt_misc/status)" >&2
        exit 1
    fi
    binfmt_entries="$(ls /proc/sys/fs/binfmt_misc 2>/dev/null || true)"
    if ! grep -qx qemu-aarch64 <<<"$binfmt_entries"; then
        echo "ERROR: no qemu-aarch64 binfmt handler on this kernel (registered by docker/setup-qemu-action in release_linux.yml)" >&2
        exit 1
    fi
    if [ "$(head -n 1 /proc/sys/fs/binfmt_misc/qemu-aarch64 2>/dev/null || true)" != enabled ] ||
       ! grep -q '^flags:.*F' /proc/sys/fs/binfmt_misc/qemu-aarch64; then
        echo "ERROR: the qemu-aarch64 binfmt handler is disabled or lacks the F (fix-binary) flag; the chroot's first emulated exec would fail" >&2
        exit 1
    fi
else
    echo "WARNING: /proc/sys/fs/binfmt_misc not visible in this container; skipping the qemu-aarch64 pre-flight" >&2
fi

rootfs_tar=/tmp/alarm.tar.gz
# Reclaim the ~1 GB chroot and tarball on every exit path, and remove any
# stale chroot from a previous attempt so results are reproducible.
cleanup() {
    rm -rf -- "$CHROOT_DIR" || true
    [ -z "${rootfs_tar:-}" ] || rm -f -- "$rootfs_tar"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT
rm -rf "$CHROOT_DIR"
mkdir -p "$CHROOT_DIR"
# Pinned to a known-good rootfs build (cross-checked against the mirror's
# published .md5); 'latest' is a mutable rolling artifact fetched over
# transport security only, and its contents are executed as root inside the
# chroot. Bump the hash deliberately (same policy as packaging/images.env)
# whenever upstream rebuilds the rootfs, and re-check that the chroot's
# pacman still supports --disable-sandbox (pacman >= 6.1), which main()
# relies on. These pins live here rather than in packaging/images.env
# because this script is their only consumer; move them there if that
# changes. ALARM_ROOTFS_SHA256 overrides the pin for local testing together
# with ALARM_ROOTFS_URL.
expected_rootfs_sha256="${ALARM_ROOTFS_SHA256:-42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319}"
# The overrides are for local testing; make a CI-level bypass visible in the
# job log.
if [ -n "${ALARM_ROOTFS_SHA256:-}" ]; then
    echo "WARNING: rootfs pin overridden via ALARM_ROOTFS_SHA256; the sha256 check compares against the overridden value, not the known-good pin" >&2
fi
if [ -n "${ALARM_ROOTFS_URL:-}" ]; then
    echo "WARNING: rootfs source overridden via ALARM_ROOTFS_URL; the sha256 is still checked against the known-good pin" >&2
fi
rc=1
while IFS= read -r url; do
    [ -n "$url" ] || continue
    echo "downloading ARM rootfs from $url"
    # A mirror that fails or serves a build other than the pinned one (the
    # mirrors of the rolling 'latest' artifact sync at different times) falls
    # through to the next URL; only a verified download sets rc=0.
    # --retry-max-time bounds the cumulative retry window per URL (--max-time
    # alone applies per attempt), so a throttling mirror cannot eat hours of
    # the CI job budget before the loop falls through to the next URL.
    if curl --proto '=https' --tlsv1.2 --retry 3 --retry-delay 5 \
            --connect-timeout 30 --max-time 1800 --retry-max-time 1800 \
            -sSfL -o "$rootfs_tar" "$url"; then
        computed_rootfs_sha256="$(sha256sum "$rootfs_tar" | awk '{print $1}')"
        if [ "$computed_rootfs_sha256" = "$expected_rootfs_sha256" ]; then
            rc=0
            break
        fi
        # curl exiting 0 means the transfer completed, so this is a complete
        # file that simply is not the pinned build (a truncated transfer makes
        # curl fail and lands in the branch below).
        echo "WARNING: $url served rootfs sha256 $computed_rootfs_sha256, expected $expected_rootfs_sha256 (upstream rebuild?); trying the next mirror" >&2
    else
        echo "WARNING: $url download failed; trying the next mirror" >&2
    fi
    rm -f -- "$rootfs_tar"
done < <(alarm_rootfs_urls)
[ "$rc" -eq 0 ] || { echo "ERROR: could not download an Arch Linux ARM rootfs matching the pinned sha256; if upstream rebuilt ArchLinuxARM-aarch64-latest.tar.gz, update the pin deliberately" >&2; exit 1; }
# The rootfs ships device nodes we cannot recreate inside an unprivileged
# container; skip them. --exclude never causes tar errors, so any non-zero
# exit is a real extraction failure (truncated archive, full disk; GNU tar
# reports per-member extraction failures with exit 2, and its exit 1 is only
# used for --diff/--create divergence), which must fail the smoke test.
tar_rc=0
tar -xzf "$rootfs_tar" -C "$CHROOT_DIR" --exclude='./dev/*' || tar_rc=$?
if [ "$tar_rc" -ne 0 ]; then
    echo "ERROR: failed to extract the Arch Linux ARM rootfs (tar exit code $tar_rc)" >&2
    exit 1
fi

# Recreate the essential device nodes the tar exclusion skipped: main()
# redirects to /dev/null, and pacman hooks and emulated binaries need the
# others. CAP_MKNOD is in Docker's default capability set, so plain mknod
# works even though the container is unprivileged.
mkdir -p "$CHROOT_DIR/dev"
mknod_in_chroot() {
    mknod "$@" || {
        echo "ERROR: could not create chroot device nodes (CAP_MKNOD required; rootless container runtime?)" >&2
        exit 1
    }
}
mknod_in_chroot -m 666 "$CHROOT_DIR/dev/null"    c 1 3
mknod_in_chroot -m 666 "$CHROOT_DIR/dev/zero"    c 1 5
mknod_in_chroot -m 444 "$CHROOT_DIR/dev/random"  c 1 8
mknod_in_chroot -m 444 "$CHROOT_DIR/dev/urandom" c 1 9

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
# The -trusted/-revoked companions are required alongside the keyring:
# --populate applies ownertrust only from <keyring>-trusted; without it
# every imported key lands at unknown trust and pacman refuses packages.
for f in archlinuxarm.gpg archlinuxarm-trusted archlinuxarm-revoked; do
    cp "$CHROOT_DIR/usr/share/pacman/keyrings/$f" /usr/share/pacman/keyrings/
done
pacman-key --gpgdir "$CHROOT_DIR/etc/pacman.d/gnupg" --init >/dev/null
pacman-key --gpgdir "$CHROOT_DIR/etc/pacman.d/gnupg" --populate archlinuxarm

# /work is not visible inside the chroot: copy the script, its lib.sh and the
# package in.
cp "$PKG_FILE" "$CHROOT_DIR/$(basename "$PKG_FILE")"
cp "$0" "$CHROOT_DIR/smoke-arch.sh"
cp "$(cd "$(dirname "$0")/../common" && pwd)/lib.sh" "$CHROOT_DIR/smoke-lib.sh"

chroot_rc=0
chroot "$CHROOT_DIR" /smoke-arch.sh --chroot "/$(basename "$PKG_FILE")" "$PKG_NAME" "$KIND" || chroot_rc=$?
[ "$chroot_rc" -eq 0 ] || exit "$chroot_rc"
