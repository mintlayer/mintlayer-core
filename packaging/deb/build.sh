#!/usr/bin/env bash
# Build the mintlayer-node / mintlayer-node-gui Debian packages.
#
# Intended to run inside a debian:12 container (any host arch: use
# `docker run --platform linux/arm64` for arm64), but works on a native
# Debian/Ubuntu host too. Self-provisions its build dependencies.
#
# Usage:
#   build.sh --package node    --version X.Y.Z --debarch amd64 \
#            --binaries-dir DIR --out DIR
#   build.sh --package gui     --version X.Y.Z --debarch amd64 \
#            --gui-binary PATH --repo-root DIR --out DIR
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PACKAGE=""
VERSION=""
DEBARCH=""
BINARIES_DIR=""
GUI_BINARY=""
OUT_DIR=""
REPO_ROOT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --package) PACKAGE="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --debarch) DEBARCH="$2"; shift 2 ;;
        --binaries-dir) BINARIES_DIR="$2"; shift 2 ;;
        --gui-binary) GUI_BINARY="$2"; shift 2 ;;
        --repo-root) REPO_ROOT="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -n "$PACKAGE" ] && [ -n "$VERSION" ] && [ -n "$DEBARCH" ] && [ -n "$OUT_DIR" ] ||
    { echo "missing required args (package/version/debarch/out)" >&2; exit 2; }
[ -n "$REPO_ROOT" ] || REPO_ROOT="$PKG_ROOT/.."

case "$PACKAGE" in
    node) PKG_NAME="mintlayer-node" ;;
    gui)  PKG_NAME="mintlayer-node-gui" ;;
    *) echo "invalid --package: $PACKAGE" >&2; exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Self-provision build dependencies (no-ops when already present)
# ---------------------------------------------------------------------------
NEED_INSTALL=(file help2man)
command -v dpkg-deb >/dev/null || NEED_INSTALL+=(dpkg-dev)
command -v lintian >/dev/null || NEED_INSTALL+=(lintian)
command -v convert >/dev/null || NEED_INSTALL+=(imagemagick)
# Runtime shared libraries referenced by the binaries: dpkg-shlibdeps needs to
# resolve them inside this environment to compute the Depends field.
NEED_INSTALL+=(libdbus-1-3 libusb-1.0-0 libudev1)
if [ "$PACKAGE" = gui ]; then
    NEED_INSTALL+=(libwayland-client0 libxkbcommon0)
fi
if [ ${#NEED_INSTALL[@]} -gt 0 ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "${NEED_INSTALL[@]}" >/dev/null
fi

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------------
# Assemble the package tree
# ---------------------------------------------------------------------------
PKGDIR="$OUT_DIR/build-${PACKAGE}"
rm -rf "$PKGDIR"
mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/usr/bin"

if [ "$PACKAGE" = node ]; then
    [ -n "$BINARIES_DIR" ] || { echo "--binaries-dir required for node" >&2; exit 2; }
    # All daemons + CLI tools, renamed with the mintlayer- prefix
    for bin in node-daemon wallet-rpc-daemon api-web-server \
               api-blockchain-scanner-daemon dns-server wallet-cli \
               wallet-address-generator; do
        cp "$BINARIES_DIR/$bin" "$PKGDIR/usr/bin/mintlayer-$bin"
        chmod 0755 "$PKGDIR/usr/bin/mintlayer-$bin"
    done

    # systemd integration
    mkdir -p "$PKGDIR/usr/lib/systemd/system"
    for unit in "$PKG_ROOT/common/systemd/"*.service; do
        install -m 0644 "$unit" "$PKGDIR/usr/lib/systemd/system/"
    done
    install -D -m 0644 "$PKG_ROOT/common/sysusers/mintlayer.conf" \
        "$PKGDIR/usr/lib/sysusers.d/mintlayer.conf"
    install -D -m 0644 "$PKG_ROOT/common/preset/90-mintlayer.preset" \
        "$PKGDIR/usr/lib/systemd/system-preset/90-mintlayer.preset"

    # udev rules for hardware wallets
    install -D -m 0644 "$PKG_ROOT/common/udev/51-mintlayer.rules" \
        "$PKGDIR/usr/lib/udev/rules.d/51-mintlayer.rules"

    # per-chain environment files (conffiles: anything under /etc is flagged
    # automatically by dpkg-deb)
    for chain in mainnet testnet; do
        for env in node.env wallet-rpc.env api-web-server.env \
                   api-blockchain-scanner.env dns-server.env; do
            install -D -m 0644 "$PKG_ROOT/common/env/$env" \
                "$PKGDIR/etc/mintlayer/$chain/$env"
        done
    done

    BINARY_NAME_PATTERN='mintlayer-*'
    ARTIFACT="Mintlayer_Node_linux_${VERSION}_${DEBARCH}.deb"
else
    [ -n "$GUI_BINARY" ] || { echo "--gui-binary required for gui" >&2; exit 2; }
    cp "$GUI_BINARY" "$PKGDIR/usr/bin/mintlayer-node-gui"
    chmod 0755 "$PKGDIR/usr/bin/mintlayer-node-gui"

    # icons + desktop entry
    if [ -d "$OUT_DIR/assets/icons/usr" ]; then
        # Pre-generated hicolor icon set (shared with the rpm builder)
        cp -r "$OUT_DIR/assets/icons/usr" "$PKGDIR/"
    else
        "$PKG_ROOT/make-icons.sh" "$REPO_ROOT/build-tools/assets/node-gui-icon_512.png" "$PKGDIR"
    fi
    install -D -m 0644 "$PKG_ROOT/common/applications/mintlayer-node-gui.desktop" \
        "$PKGDIR/usr/share/applications/mintlayer-node-gui.desktop"

    ARTIFACT="Mintlayer_Node_GUI_linux_${VERSION}_${DEBARCH}.deb"
fi

# ---------------------------------------------------------------------------
# Documentation: copyright, changelog, man pages
# ---------------------------------------------------------------------------
# The deb version always carries an explicit Debian revision (e.g. 1.4.0-1,
# 1.4.0-rc1-1): without it the package looks "native", which changes lintian's
# changelog-name expectations and dpkg's upgrade ordering.
DEB_VERSION="$VERSION"
case "$DEB_VERSION" in
    *-*) ;;                  # already has a revision
    *)  DEB_VERSION="${DEB_VERSION}-1" ;;
esac

DOC_DIR="$PKGDIR/usr/share/doc/$PKG_NAME"
mkdir -p "$DOC_DIR"
install -m 0644 "$PKG_ROOT/deb/copyright" "$DOC_DIR/copyright"
install -m 0644 "$REPO_ROOT/LICENSE" "$DOC_DIR/LICENSE"

CHANGELOG="$OUT_DIR/changelog.tmp"
sed -e "s/@VERSION@/$DEB_VERSION/g" -e "s/@DATE@/$(date -R)/" \
    "$PKG_ROOT/deb/changelog.in" > "$CHANGELOG"
gzip -n -9 -c "$CHANGELOG" > "$DOC_DIR/changelog.Debian.gz"
rm -f "$CHANGELOG"

# Man pages from --help output (binaries are executable on this host arch)
export LC_ALL=C.UTF-8
MAN_DIR="$PKGDIR/usr/share/man/man1"
mkdir -p "$MAN_DIR"
for binpath in "$PKGDIR"/usr/bin/*; do
    binname="$(basename "$binpath")"
    if "$binpath" --help >/dev/null 2>&1; then
        help2man --no-info --version-string="$VERSION" \
            --name="Part of the Mintlayer node software" \
            "$binpath" > "$MAN_DIR/$binname.1" 2>/dev/null ||
            { echo "warning: help2man failed for $binname, shipping stub" >&2
              printf '.TH %s 1\n.SH NAME\n%s \\- Mintlayer tool\n' "$binname" "$binname" \
                > "$MAN_DIR/$binname.1"; }
    else
        echo "warning: $binname --help not runnable, shipping stub man page" >&2
        printf '.TH %s 1\n.SH NAME\n%s \\- Mintlayer tool\n' "$binname" "$binname" \
            > "$MAN_DIR/$binname.1"
    fi
    gzip -n -9 "$MAN_DIR/$binname.1"
done

# ---------------------------------------------------------------------------
# Verify every binary's shared libraries resolve in this environment.
# Anything "not found" here would also be unresolved at install time, and
# dpkg-shlibdeps would silently miss it from Depends.
# ---------------------------------------------------------------------------
MISSING_LIBS=0
for binpath in "$PKGDIR"/usr/bin/*; do
    if ldd "$binpath" 2>/dev/null | grep -q "not found"; then
        echo "ERROR: unresolved shared libraries in $(basename "$binpath"):" >&2
        ldd "$binpath" | grep "not found" >&2
        MISSING_LIBS=1
    fi
done
[ "$MISSING_LIBS" -eq 0 ] || {
    echo "install the missing libraries in the build environment and retry" >&2
    exit 1
}

# Strip binaries as distro packages do (the unstripped binaries remain
# available in the tar.gz release artifact).
for binpath in "$PKGDIR"/usr/bin/*; do
    file "$binpath" | grep -q "not stripped" && strip --strip-unneeded "$binpath"
done

# ---------------------------------------------------------------------------
# control: compute shared library dependencies with dpkg-shlibdeps
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
SCRATCH="$OUT_DIR/dpkg-shlibdeps-scratch"
mkdir -p "$SCRATCH/debian"
cat > "$SCRATCH/debian/control" <<EOF
Source: mintlayer
Section: utils
Priority: optional
Maintainer: Mintlayer <devs@mintlayer.org>
Standards-Version: 4.6.2

Package: $PKG_NAME
Architecture: any
Depends: \${shlibs:Depends}, \${misc:Depends}
Description: scratch control for dpkg-shlibdeps
 Placeholder used only to satisfy dpkg-shlibdeps.
EOF

SHLIBS=""
( cd "$SCRATCH" && dpkg-shlibdeps -O "$PKGDIR"/usr/bin/* 2>/dev/null ) | \
    grep -o 'shlibs:Depends=.*' | cut -d= -f2- > "$OUT_DIR/shlibs.tmp" || true
SHLIBS="$(cat "$OUT_DIR/shlibs.tmp")"
rm -rf "$SCRATCH" "$OUT_DIR/shlibs.tmp"

INSTALLED_SIZE="$(du -sk --exclude=DEBIAN "$PKGDIR" | cut -f1)"

sed -e "s/@VERSION@/$DEB_VERSION/g" \
    -e "s/@DEBARCH@/$DEBARCH/g" \
    -e "s/@INSTALLED_SIZE@/$INSTALLED_SIZE/g" \
    -e "s/@SHLIBS@/$SHLIBS/g" \
    "$PKG_ROOT/deb/control.in" > "$OUT_DIR/control.full"

# Keep only the stanza for the package being built
awk -v want="$PKG_NAME" '
    /^Package:/ {keep = ($0 ~ "^Package: " want "$")}
    {if (keep) print}
' "$OUT_DIR/control.full" > "$PKGDIR/DEBIAN/control"

# An empty Depends line is invalid: drop it when no shared libs were found
sed -i '/^Depends: *$/d' "$PKGDIR/DEBIAN/control"
rm -f "$OUT_DIR/control.full"

# Maintainer scripts + conffiles list
if [ "$PACKAGE" = node ]; then
    install -m 0755 "$PKG_ROOT/deb/postinst-node" "$PKGDIR/DEBIAN/postinst"
    install -m 0755 "$PKG_ROOT/deb/prerm-node"    "$PKGDIR/DEBIAN/prerm"
    install -m 0755 "$PKG_ROOT/deb/postrm-node"   "$PKGDIR/DEBIAN/postrm"
    ( cd "$PKGDIR" && find etc -type f | sed 's|^|/|' | sort ) > "$PKGDIR/DEBIAN/conffiles"
else
    install -m 0755 "$PKG_ROOT/deb/postinst-gui"  "$PKGDIR/DEBIAN/postinst"
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
dpkg-deb --build --root-owner-group "$PKGDIR" "$OUT_DIR/$ARTIFACT"
rm -rf "$PKGDIR"

echo "built $OUT_DIR/$ARTIFACT"

# ---------------------------------------------------------------------------
# Lint (errors fail; warnings are reported but allowed)
# ---------------------------------------------------------------------------
if ! lintian --fail-on error --info --show-overrides "$OUT_DIR/$ARTIFACT"; then
    echo "lintian FAILED for $ARTIFACT" >&2
    exit 1
fi
echo "lintian passed for $ARTIFACT"
