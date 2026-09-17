#!/usr/bin/env bash
# Build the mintlayer-node / mintlayer-node-gui Arch packages (.pkg.tar.zst).
#
# Intended to run inside an archlinux:base container. Arch publishes amd64
# images only, so:
#   * x86_64 target: the container is arch-matched — binaries are stripped,
#     dependencies are resolved from ldd via `pacman -F`, and man pages are
#     generated from the real --help output.
#   * aarch64 target: the same amd64 container repackages the prebuilt
#     binaries cross-target (exactly like the cross-target rpm legs of
#     packaging/test-local.sh): strip is skipped, man pages are stubs and the
#     dependency list falls back to a static map (see FALLBACK_DEPENDS_*).
# Self-provisions its build dependencies.
#
# Usage:
#   build.sh --package node --arch x86_64|aarch64 --version X.Y.Z \
#            --binaries-dir DIR --out DIR
#   build.sh --package gui --arch x86_64|aarch64 --version X.Y.Z \
#            --gui-binary PATH --repo-root DIR --out DIR
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=../common/lib.sh
. "$PKG_ROOT/common/lib.sh"

PACKAGE=""
ARCH=""
VERSION=""
BINARIES_DIR=""
GUI_BINARY=""
OUT_DIR=""
REPO_ROOT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --package) PACKAGE="$2"; shift 2 ;;
        --arch) ARCH="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --binaries-dir) BINARIES_DIR="$2"; shift 2 ;;
        --gui-binary) GUI_BINARY="$2"; shift 2 ;;
        --repo-root) REPO_ROOT="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -n "$PACKAGE" ] && [ -n "$ARCH" ] && [ -n "$VERSION" ] && [ -n "$OUT_DIR" ] ||
    { echo "missing required args (package/arch/version/out)" >&2; exit 2; }
[ -n "$REPO_ROOT" ] || REPO_ROOT="$PKG_ROOT/.."

case "$ARCH" in
    x86_64|aarch64) ;;
    *) echo "invalid --arch: $ARCH (expected x86_64 or aarch64)" >&2; exit 2 ;;
esac

# Sanitize version for Arch (pkgver allows only alphanumerics, dots and
# underscores). Note: pre-release versions (with a '-' suffix) are rejected:
# Arch's vercmp has no '~' equivalent, so '1.4.1_rc1' would sort NEWER than
# '1.4.1' and systems that installed the RC would refuse to upgrade to the
# final release. The deb/rpm builders keep pre-release support ('-' maps to
# '~' there, which sorts before the final release).
if ! validate_version "$VERSION"; then
    echo "$VERSION_FORMAT_ERROR" >&2
    exit 2
fi
case "$VERSION" in
    *-*)
        echo "pre-release versions are not supported for Arch packages: $VERSION" >&2
        exit 2
        ;;
esac
PKGVER="$VERSION"

NATIVE=0
[ "$ARCH" = "$(uname -m)" ] && NATIVE=1

# ---------------------------------------------------------------------------
# Cross-target dependency fallback (aarch64 binaries cannot be ldd'd from the
# amd64 container). Derived from the ldd output of the 1.4.x release binaries
# and verified against `pacman -F`; the GUI additions cover the libraries that
# winit/glutin load with dlopen at runtime (they are not recorded as ELF
# dependencies, but Arch minimal installs may lack them).
# ---------------------------------------------------------------------------
FALLBACK_DEPENDS_NODE=(glibc gcc-libs libdbus libusb systemd-libs)
FALLBACK_DEPENDS_GUI=(libx11 libxcursor libxrandr libxi libxkbcommon wayland libglvnd)

# ---------------------------------------------------------------------------
# Self-provision build dependencies (no-ops when already present)
# ---------------------------------------------------------------------------
pacman -Syu --noconfirm --needed >/dev/null
# imagemagick: only needed when make-icons.sh has to run (GUI package without
# pre-generated icons); hicolor-icon-theme: runtime dependency of the GUI
# package that makepkg verifies. Self-provisioned like the other tools.
pacman -S --noconfirm --needed --asdeps base-devel sudo namcap help2man file \
    binutils imagemagick hicolor-icon-theme >/dev/null

BUILD_USER=builduser
id "$BUILD_USER" >/dev/null 2>&1 || useradd -m "$BUILD_USER"

WORK_DIR="$(mktemp -d /tmp/mintlayer-arch-build.XXXXXX)"
BR="$WORK_DIR/payload"
mkdir -p "$BR/usr/bin"
mkdir -p "$OUT_DIR"

if [ "$PACKAGE" = node ]; then
    [ -n "$BINARIES_DIR" ] || { echo "--binaries-dir required for node" >&2; exit 2; }
    for bin in "${NODE_BINARIES[@]}"; do
        install -m 0755 "$BINARIES_DIR/$bin" "$BR/usr/bin/mintlayer-$bin"
    done

    mkdir -p "$BR/usr/lib/systemd/system"
    for unit in "$PKG_ROOT/common/systemd/"*.service; do
        install -m 0644 "$unit" "$BR/usr/lib/systemd/system/"
    done
    install -D -m 0644 "$PKG_ROOT/common/sysusers/mintlayer.conf" \
        "$BR/usr/lib/sysusers.d/mintlayer.conf"
    install -D -m 0644 "$PKG_ROOT/common/preset/90-mintlayer.preset" \
        "$BR/usr/lib/systemd/system-preset/90-mintlayer.preset"
    install -D -m 0644 "$PKG_ROOT/common/udev/51-mintlayer.rules" \
        "$BR/usr/lib/udev/rules.d/51-mintlayer.rules"

    for chain in mainnet testnet; do
        for env in node.env wallet-rpc.env api-web-server.env \
                   api-blockchain-scanner.env dns-server.env; do
            install -D -m 0644 "$PKG_ROOT/common/env/$env" \
                "$BR/etc/mintlayer/$chain/$env"
        done
    done

    ARTIFACT="Mintlayer_Node_linux_${VERSION}_${ARCH}.pkg.tar.zst"
    PKG_NAME="mintlayer-node"
    PKGBUILD_IN="PKGBUILD-node.in"
else
    [ -n "$GUI_BINARY" ] || { echo "--gui-binary required for gui" >&2; exit 2; }
    install -m 0755 "$GUI_BINARY" "$BR/usr/bin/mintlayer-node-gui"
    if [ -d "$OUT_DIR/assets/icons/usr" ]; then
        # Pre-generated hicolor icon set (shared with the deb/rpm builders)
        cp -r "$OUT_DIR/assets/icons/usr" "$BR/"
    else
        "$PKG_ROOT/make-icons.sh" "$REPO_ROOT/build-tools/assets/node-gui-icon_512.png" "$BR"
    fi
    install -D -m 0644 "$PKG_ROOT/common/applications/mintlayer-node-gui.desktop" \
        "$BR/usr/share/applications/mintlayer-node-gui.desktop"

    ARTIFACT="Mintlayer_Node_GUI_linux_${VERSION}_${ARCH}.pkg.tar.zst"
    PKG_NAME="mintlayer-node-gui"
    PKGBUILD_IN="PKGBUILD-gui.in"
fi

# ---------------------------------------------------------------------------
# Strip binaries as distro packages do — but only when the container arch
# matches the target (see the header comment for the cross-target behavior).
# ---------------------------------------------------------------------------
if [ "$NATIVE" -eq 1 ]; then
    # The if-guard keeps an "already stripped" match failure from tripping
    # errexit (same as the deb builder).
    for binpath in "$BR"/usr/bin/*; do
        if file "$binpath" | grep -q "not stripped"; then
            strip --strip-unneeded "$binpath"
        fi
    done
else
    echo "cross-target build ($(uname -m) container, $ARCH target): skipping strip"
fi

# ---------------------------------------------------------------------------
# Man pages from --help output (stubs in the cross-target case, like rpm)
# ---------------------------------------------------------------------------
gen_man "$BR" "$VERSION" "$NATIVE"

# License file consumed by the payload (also declared via license=('MIT'))
install -D -m 0644 "$REPO_ROOT/LICENSE" "$BR/usr/share/licenses/$PKG_NAME/LICENSE"

# ---------------------------------------------------------------------------
# Dependency list
# ---------------------------------------------------------------------------
if [ "$NATIVE" -eq 1 ]; then
    # Union of the shared libraries across all binaries: keep only soname-
    # shaped tokens (drops the per-binary ldd header lines, absolute
    # interpreter paths and ldd's "statically linked" marker text; the
    # runtime linker belongs to glibc, which every Arch system has).
    LIBS="$(for binpath in "$BR"/usr/bin/*; do ldd "$binpath" 2>/dev/null; done \
        | awk '{print $1}' | grep -E '^[^/]+\.so(\.|$)' | grep -v '^linux-vdso' \
        | sort -u || true)"
    MISSING=0
    DEPENDS=""
    if [ -n "$LIBS" ]; then
        # Download the pacman file database used for the lib -> package lookup
        pacman -Fy --noconfirm >/dev/null
        for lib in $LIBS; do
            # --machinereadable separates fields with NUL bytes; translate
            # them so awk can pick the package name (field 2). A soname can be
            # provided by several packages, and the row order depends on the
            # repo/database layout, so all providers are collected and the
            # choice is made deterministically: the shortest package name
            # (preferring plain runtime packages over longer, more specific
            # variants), ties broken alphabetically.
            providers="$(pacman -F --machinereadable "usr/lib/$lib" 2>/dev/null \
                | tr '\0' '\t' | awk -F'\t' '{print $2}' | sort -u)"
            if [ -z "$providers" ]; then
                echo "ERROR: no Arch package provides usr/lib/$lib" >&2
                MISSING=1
                continue
            fi
            pkg="$(printf '%s\n' "$providers" \
                | awk '{ print length($0), $0 }' | sort -n -k1,1 -k2,2 | head -n1 | cut -d' ' -f2-)"
            if [ "$(printf '%s\n' "$providers" | wc -l)" -gt 1 ]; then
                echo "note: usr/lib/$lib has multiple providers ($(printf '%s' "$providers" | tr '\n' ' ')); using $pkg" >&2
            fi
            DEPENDS="$DEPENDS $pkg"
        done
    fi
    [ "$MISSING" -eq 0 ] || { echo "unresolved shared library dependencies" >&2; exit 1; }
    DEPENDS="$(printf '%s\n' $DEPENDS | sort -u | tr '\n' ' ')"
    echo "resolved depends:$DEPENDS"
else
    DEPENDS="${FALLBACK_DEPENDS_NODE[*]}"
    if [ "$PACKAGE" = gui ]; then
        DEPENDS="$DEPENDS ${FALLBACK_DEPENDS_GUI[*]}"
    fi
    echo "cross-target build: using fallback depends:$DEPENDS"
fi

# makepkg verifies that the declared runtime dependencies resolve and are
# installed, so provision them here (package names are x86_64 repo names,
# which is what the amd64 container's repos provide regardless of the target
# arch being packaged).
[ -n "$DEPENDS" ] || { echo "empty depends list" >&2; exit 1; }
pacman -S --noconfirm --needed --asdeps $DEPENDS >/dev/null

# ---------------------------------------------------------------------------
# Render the PKGBUILD (payload tree is staged next to it; makepkg only
# repackages it). The payload stays root-owned so the packaged files record
# correct root ownership through fakeroot.
# ---------------------------------------------------------------------------
BACKUP=""
if [ "$PACKAGE" = node ]; then
    # Derive the backup list from the staged tree (makepkg requires backup
    # entries without a leading slash).
    while IFS= read -r f; do BACKUP="$BACKUP '$f'"; done < <(cd "$BR" && find etc -type f | sort)
fi

sed -e "s|@PKGVER@|$PKGVER|g" \
    -e "s|@ARCH@|$ARCH|g" \
    -e "s|@DEPENDS@|$DEPENDS|g" \
    -e "s|@BACKUP@|$BACKUP|g" \
    -e "s|@PAYLOAD_DIR@|$BR|g" \
    "$PKG_ROOT/arch/$PKGBUILD_IN" > "$WORK_DIR/PKGBUILD"

if [ "$PACKAGE" = node ]; then
    install -m 0644 "$PKG_ROOT/arch/mintlayer-node.install" "$WORK_DIR/mintlayer-node.install"
fi

# The work directory itself becomes builduser-writable (makepkg creates src/
# and pkg/ in it), but the staged payload stays root-owned: package() copies
# it with cp -a, so the packaged files record correct root ownership through
# fakeroot. The payload only needs to be world-readable, which it is.
chown "$BUILD_USER:$BUILD_USER" "$WORK_DIR"

# ---------------------------------------------------------------------------
# Build. makepkg refuses to run as root, hence the dedicated build user.
# CARCH is pinned to the target arch so that the package name and .PKGINFO
# record the target (for the cross-target aarch64 leg the amd64 host would
# otherwise stamp its own arch, or --ignorearch would produce packages that
# pacman refuses on the real target).
# ---------------------------------------------------------------------------
sudo -H -u "$BUILD_USER" bash -ec "cd '$WORK_DIR' && CARCH='$ARCH' makepkg -f --noconfirm"

BUILT_PKG="$WORK_DIR/${PKG_NAME}-${PKGVER}-1-${ARCH}.pkg.tar.zst"
[ -f "$BUILT_PKG" ] || {
    echo "expected $BUILT_PKG was not produced" >&2
    ls -la "$WORK_DIR" >&2
    exit 1
}
mv "$BUILT_PKG" "$OUT_DIR/$ARTIFACT"

echo "built $OUT_DIR/$ARTIFACT"

# ---------------------------------------------------------------------------
# Lint. namcap always exits 0 (even with errors and even on unreadable
# input), so gate on its output instead of the exit code: any " E: " line is
# an error and fails the build (warnings are allowed).
# ---------------------------------------------------------------------------
namcap_out="$(namcap "$OUT_DIR/$ARTIFACT" 2>&1)"
echo "$namcap_out"
if printf '%s\n' "$namcap_out" | grep -q ' E: '; then
    echo "namcap found errors in $ARTIFACT" >&2
    exit 1
fi
echo "namcap passed for $ARTIFACT (warnings allowed)"

rm -rf "$WORK_DIR"
