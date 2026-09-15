#!/usr/bin/env bash
# Build the mintlayer-node / mintlayer-node-gui RPM packages.
#
# Intended to run inside a fedora:latest container (any host arch for x86_64;
# for the aarch64 target no emulation is needed: rpmbuild only repackages the
# prebuilt binaries). Self-provisions its build dependencies.
#
# Usage:
#   build.sh --package node --rpmarch x86_64|aarch64 --version X.Y.Z \
#            --binaries-dir DIR --out DIR
#   build.sh --package gui --rpmarch x86_64|aarch64 --version X.Y.Z \
#            --gui-binary PATH --repo-root DIR --out DIR
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PACKAGE=""
RPMARCH=""
VERSION=""
BINARIES_DIR=""
GUI_BINARY=""
OUT_DIR=""
REPO_ROOT=""

while [ $# -gt 0 ]; do
    case "$1" in
        --package) PACKAGE="$2"; shift 2 ;;
        --rpmarch) RPMARCH="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --binaries-dir) BINARIES_DIR="$2"; shift 2 ;;
        --gui-binary) GUI_BINARY="$2"; shift 2 ;;
        --repo-root) REPO_ROOT="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

[ -n "$PACKAGE" ] && [ -n "$RPMARCH" ] && [ -n "$VERSION" ] && [ -n "$OUT_DIR" ] ||
    { echo "missing required args (package/rpmarch/version/out)" >&2; exit 2; }
[ -n "$REPO_ROOT" ] || REPO_ROOT="$PKG_ROOT/.."

case "$RPMARCH" in
    x86_64) TARGET="x86_64-redhat-linux" ;;
    aarch64) TARGET="aarch64-redhat-linux" ;;
    *) echo "invalid --rpmarch: $RPMARCH" >&2; exit 2 ;;
esac

# Sanitize version for RPM (no dashes; 1.4.0-rc1 -> 1.4.0~rc1).
# NOTE: do not use ${var//-/~} here — bash 5.3+ tilde-expands the replacement
# word, turning '~' into $HOME.
RPM_VERSION="$(printf '%s' "$VERSION" | tr '-' '~')"

# ---------------------------------------------------------------------------
# Self-provision build dependencies (no-ops when already present)
# ---------------------------------------------------------------------------
dnf install -y -q rpm-build systemd-rpm-macros help2man file binutils \
    dbus-libs libusb1 systemd-libs >/dev/null

mkdir -p "$OUT_DIR"
TOPDIR="$OUT_DIR/rpmbuild-$PACKAGE"
rm -rf "$TOPDIR"
mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}
mkdir -p "$TOPDIR/BUILDROOT/mintlayer-node-gui"

# ---------------------------------------------------------------------------
# Assemble the payload (buildroot layout)
# ---------------------------------------------------------------------------
BR="$TOPDIR/BUILDROOT/mintlayer-node-gui"
mkdir -p "$BR/usr/bin"

if [ "$PACKAGE" = node ]; then
    [ -n "$BINARIES_DIR" ] || { echo "--binaries-dir required for node" >&2; exit 2; }
    for bin in node-daemon wallet-rpc-daemon api-web-server \
               api-blockchain-scanner-daemon dns-server wallet-cli \
               wallet-address-generator; do
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

    ARTIFACT="Mintlayer_Node_linux_${VERSION}_${RPMARCH}.rpm"
    SPEC_IN="mintlayer-node.spec.in"
else
    [ -n "$GUI_BINARY" ] || { echo "--gui-binary required for gui" >&2; exit 2; }
    install -m 0755 "$GUI_BINARY" "$BR/usr/bin/mintlayer-node-gui"
    if [ -d "$OUT_DIR/assets/icons/usr" ]; then
        # Pre-generated hicolor icon set (shared with the deb builder)
        cp -r "$OUT_DIR/assets/icons/usr" "$BR/"
    else
        "$PKG_ROOT/make-icons.sh" "$REPO_ROOT/build-tools/assets/node-gui-icon_512.png" "$BR"
    fi
    install -D -m 0644 "$PKG_ROOT/common/applications/mintlayer-node-gui.desktop" \
        "$BR/usr/share/applications/mintlayer-node-gui.desktop"

    ARTIFACT="Mintlayer_Node_GUI_linux_${VERSION}_${RPMARCH}.rpm"
    SPEC_IN="mintlayer-node-gui.spec.in"
fi
SPEC_NAME="${SPEC_IN%.spec.in}.spec"

# ---------------------------------------------------------------------------
# Strip binaries as distro packages do — but only when the container arch
# matches the target: fedora's binutils cannot handle foreign-arch ELF
# ("Unable to recognise the architecture"), so cross-target packages (e.g.
# aarch64 rpms built on an x86_64 runner) ship unstripped.
# ---------------------------------------------------------------------------
HOST_ARCH="$(uname -m)"
if [ "$RPMARCH" = "$HOST_ARCH" ]; then
    for binpath in "$BR"/usr/bin/*; do
        file "$binpath" | grep -q "not stripped" && strip --strip-unneeded "$binpath"
    done
else
    echo "cross-target build ($HOST_ARCH container, $RPMARCH target): skipping strip"
fi

# ---------------------------------------------------------------------------
# Man pages from --help output
# ---------------------------------------------------------------------------
export LC_ALL=C.UTF-8
MAN_DIR="$BR/usr/share/man/man1"
mkdir -p "$MAN_DIR"
for binpath in "$BR"/usr/bin/*; do
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

# License file consumed by the %files %license entry
if [ "$PACKAGE" = node ]; then
    install -D -m 0644 "$REPO_ROOT/LICENSE" "$BR/usr/share/licenses/mintlayer-node/LICENSE"
else
    install -D -m 0644 "$REPO_ROOT/LICENSE" "$BR/usr/share/licenses/mintlayer-node-gui/LICENSE"
fi

# ---------------------------------------------------------------------------
# Spec + sources into the rpmbuild layout
# ---------------------------------------------------------------------------
sed -e "s/@VERSION@/$RPM_VERSION/g" \
    -e "s/@RPM_DATE@/$(date '+%a %b %e %Y')/g" \
    "$PKG_ROOT/rpm/$SPEC_IN" > "$TOPDIR/SPECS/${SPEC_IN%.spec.in}.spec"

install -m 0644 "$PKG_ROOT/common/sysusers/mintlayer.conf" "$TOPDIR/SOURCES/"
install -m 0644 "$PKG_ROOT/common/preset/90-mintlayer.preset" "$TOPDIR/SOURCES/"
install -m 0644 "$REPO_ROOT/LICENSE" "$TOPDIR/SOURCES/"

# ---------------------------------------------------------------------------
# Build. Repackaging of prebuilt binaries only:
#  - no debuginfo (binaries are not stripped here, none exists in buildroot)
#  - strip/objdump disabled so brp scripts never touch foreign-arch ELFs
# ---------------------------------------------------------------------------
rpmbuild -bb \
    --define "_topdir $TOPDIR" \
    --define "debug_package %{nil}" \
    --define "__strip /bin/true" \
    --define "__objdump /bin/true" \
    --define "_buildrootdir $TOPDIR/BUILDROOT.dir" \
    --buildroot "$BR" \
    --target "$TARGET" \
    "$TOPDIR/SPECS/$SPEC_NAME" 2>&1 | sed -n '/^Processing files/,$p' || {
        echo "rpmbuild FAILED; rerun without output filter for details" >&2
        rpmbuild -bb \
            --define "_topdir $TOPDIR" \
            --define "debug_package %{nil}" \
            --define "__strip /bin/true" \
            --define "__objdump /bin/true" \
            --define "_buildrootdir $TOPDIR/BUILDROOT.dir" \
            --buildroot "$BR" \
            --target "$TARGET" \
            "$TOPDIR/SPECS/$SPEC_NAME"
    }

BUILT_RPM="$TOPDIR/RPMS/$RPMARCH/mintlayer-*.${RPMARCH}.rpm"
[ -e $BUILT_RPM ] || { echo "expected rpm not found: $BUILT_RPM" >&2; exit 1; }
mv $BUILT_RPM "$OUT_DIR/$ARTIFACT"
rm -rf "$TOPDIR"

echo "built $OUT_DIR/$ARTIFACT"

# ---------------------------------------------------------------------------
# Lint (errors fail; warnings are reported but allowed)
# ---------------------------------------------------------------------------
dnf install -y -q rpmlint >/dev/null
rpmlint "$OUT_DIR/$ARTIFACT" | tee "$OUT_DIR/rpmlint.log"
RPM_BASE="$(basename "$ARTIFACT" | sed 's/\.rpm$//')"
if grep -qE "^${RPM_BASE}\.[a-z0-9_]+: E:" "$OUT_DIR/rpmlint.log"; then
    echo "rpmlint found errors in $ARTIFACT" >&2
    exit 1
fi
echo "rpmlint passed for $ARTIFACT (warnings allowed)"
