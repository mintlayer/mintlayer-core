#!/usr/bin/env bash
# Local replica of the release packaging pipeline (.github/workflows/release_linux.yml).
#
# Builds (or reuses) the release binaries, then produces and validates all four
# native packages exactly the way CI does: same container images, same scripts,
# same gates. Run this before tagging a release — the tag build should be a
# formality.
#
# Usage:
#   test-local.sh [--quick] [--version X.Y.Z] [--skip-build]
#                 [--binaries-dir x86_64=DIR,aarch64=DIR] [--skip-smoke]
#
#   --quick         amd64/x86_64 only (native containers, no qemu)
#   --skip-build    reuse existing binaries (see --binaries-dir)
#   --skip-smoke    skip the fresh-container install smoke tests
#
# By default binaries are built INSIDE a debian:12 container so their glibc
# matches the package floor — a host build on a newer distro (e.g. Arch,
# glibc 2.38+) would fail the deb builder's ldd gate by design. Use
# --binaries-dir to reuse CI-produced binaries instead.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_ROOT="$REPO_ROOT/packaging"
DIST="$PKG_ROOT/dist"
mkdir -p "$DIST"

# Container image pins, shared with .github/workflows/release_linux.yml.
. "$PKG_ROOT/images.env"
ARCH_IMAGE="${ARCH_IMAGE:-archlinux:base-20260913.0.592969}"

# Shared binary list (NODE_BINARIES)
. "$PKG_ROOT/common/lib.sh"

QUICK=0
SKIP_BUILD=0
SKIP_SMOKE=0
VERSION=""
BINARIES_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --quick) QUICK=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --skip-smoke) SKIP_SMOKE=1; shift ;;
        --version) VERSION="$2"; shift 2 ;;
        --binaries-dir) BINARIES_OVERRIDE="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
echo "=== preflight ==="
command -v docker >/dev/null || { echo "docker not found" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon not reachable" >&2; exit 1; }

# Version: --version wins; else derive from git tags like the workflow does.
if [ -z "$VERSION" ]; then
    VERSION="$(git -C "$REPO_ROOT" describe --tags --abbrev=0 2>/dev/null | sed -e 's/^v//' || true)"
    VERSION="${VERSION:-0.0.0-local}"
fi
echo "version: $VERSION"

# arm64 emulation check (only needed when not --quick)
QEMU_OK=1
if [ "$QUICK" -eq 0 ]; then
    if ! docker run --rm --platform linux/arm64 debian:12 true >/dev/null 2>&1; then
        QEMU_OK=0
        echo "WARNING: arm64 containers unavailable." >&2
        echo "  register qemu binfmt with:" >&2
        echo "    docker run --privileged --rm multiarch/qemu-user-static --reset -p yes" >&2
        echo "  continuing with x86_64/amd64 only." >&2
    fi
fi

echo "pulling container images..."
docker pull -q debian:12 >/dev/null
docker pull -q "$FEDORA_IMAGE" >/dev/null
docker pull -q "$ARCH_IMAGE" >/dev/null

# ---------------------------------------------------------------------------
# Build (or locate) release binaries
# ---------------------------------------------------------------------------
ARCHES=(x86_64)
[ "$QUICK" -eq 0 ] && [ "$QEMU_OK" -eq 1 ] && ARCHES+=(aarch64)

declare -A BIN_DIR
for arch in "${ARCHES[@]}"; do
    BIN_DIR[$arch]="$REPO_ROOT/target/$arch-unknown-linux-gnu/release"
    if [ "$arch" = x86_64 ]; then
        BIN_DIR[$arch]="$REPO_ROOT/target/release"
    fi
done
if [ "$SKIP_BUILD" -eq 1 ]; then
    if [ -n "$BINARIES_OVERRIDE" ]; then
        for pair in ${BINARIES_OVERRIDE//,/ }; do
            [ -n "${pair%%=*}" ] && BIN_DIR[${pair%%=*}]="${pair##*=}"
        done
    fi
    for arch in "${ARCHES[@]}"; do
        test -f "${BIN_DIR[$arch]}/node-daemon" ||
            { echo "no prebuilt binary for $arch at ${BIN_DIR[$arch]}" >&2; exit 1; }
    done
else
    echo "=== cargo build inside debian:12 (glibc floor of the deb) ==="
    # Building inside the deb container guarantees the binaries run on the
    # oldest supported distro. Cargo caches live in named volumes so repeat
    # runs are incremental.
    CONTAINER_PACKAGES="${NODE_BINARIES[*]} node-gui"
    docker run --rm -v "$REPO_ROOT:/work" -w /work \
        -v mintlayer-cargo-home:/usr/local/cargo \
        -e CARGO_TARGET_DIR=/work/target-debian \
        -e CARGO_HOME=/usr/local/cargo \
        -e CONTAINER_PACKAGES="$CONTAINER_PACKAGES" \
        debian:12 bash -ec "
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq build-essential pkg-config git curl \
                libdbus-1-dev libusb-1.0-0-dev libudev-dev >/dev/null
            if ! command -v cargo >/dev/null; then
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal >/dev/null
            fi
            . /usr/local/cargo/env
            cargo build --release --locked --features trezor,ledger \$(printf ' -p %s' \$CONTAINER_PACKAGES)
        "
    BIN_DIR[x86_64]="$REPO_ROOT/target-debian/release"
    # aarch64 container builds would compile the entire workspace under qemu
    # (very slow) — CI is the place for those; require prebuilt binaries here.
    if [ "${ARCHES[*]}" = "x86_64 aarch64" ]; then
        echo "NOTE: skipping local aarch64 binary build (CI does it); " \
             "will fail later if no arm64 binaries exist." >&2
    fi
fi

RESULTS=()
FAILED=0
run_step() { # run_step <label> <cmd...> — records the result, never aborts
    local label="$1"; shift
    echo ""
    echo "=== $label ==="
    if "$@"; then
        RESULTS+=("PASS  $label")
    else
        local rc=$?
        RESULTS+=("FAIL  $label (rc=$rc)")
        FAILED=1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Pre-generate the hicolor icon set once (shared by all builders,
# avoids ImageMagick in the fedora/arch containers)
# ---------------------------------------------------------------------------
if [ ! -d "$DIST/assets/icons/usr/share/icons" ]; then
    run_step "icons" \
        docker run --rm -v "$REPO_ROOT:/work" -w /work debian:12 \
        bash -ec "
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq && apt-get install -y -qq imagemagick >/dev/null
            packaging/make-icons.sh build-tools/assets/node-gui-icon_512.png packaging/dist/assets/icons
        "
fi

# node-gui binary lives in the same target dir as the other binaries
GUI_BIN="${BIN_DIR[${ARCHES[0]}]}/node-gui"
test -f "$GUI_BIN" || { echo "node-gui binary not found at $GUI_BIN" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Packaging matrix: for each arch, deb (in debian:12) + rpm (in the pinned
# $FEDORA_IMAGE)
# ---------------------------------------------------------------------------
declare -A DEBARCH=( [x86_64]=amd64 [aarch64]=arm64 )

for arch in "${ARCHES[@]}"; do
    debarch="${DEBARCH[$arch]}"
    platform=""
    if [ "$arch" != "$(uname -m)" ]; then
        platform="--platform linux/$arch"
    fi

    # Binaries dir as seen from inside the /work-mounted container
    rel_bin_dir="${BIN_DIR[$arch]#"$REPO_ROOT"}"
    CONTAINER_BIN_DIR="/work$rel_bin_dir"

    # --- deb: node ---
    run_step "deb mintlayer-node ($debarch)" \
        docker run --rm $platform -v "$REPO_ROOT:/work" -w /work debian:12 \
        packaging/deb/build.sh --package node --version "$VERSION" \
            --debarch "$debarch" --binaries-dir "$CONTAINER_BIN_DIR" \
            --out /work/packaging/dist

    # --- deb: gui ---
    run_step "deb mintlayer-node-gui ($debarch)" \
        docker run --rm $platform -v "$REPO_ROOT:/work" -w /work debian:12 \
        packaging/deb/build.sh --package gui --version "$VERSION" \
            --debarch "$debarch" --gui-binary "$CONTAINER_BIN_DIR/node-gui" \
            --repo-root /work --out /work/packaging/dist

    # --- rpm: node (repackaging only, cross-target safe without emulation) ---
    run_step "rpm mintlayer-node ($arch)" \
        docker run --rm -v "$REPO_ROOT:/work" -w /work "$FEDORA_IMAGE" \
        packaging/rpm/build.sh --package node --rpmarch "$arch" --version "$VERSION" \
            --binaries-dir "$CONTAINER_BIN_DIR" \
            --out /work/packaging/dist

    # --- rpm: gui ---
    run_step "rpm mintlayer-node-gui ($arch)" \
        docker run --rm -v "$REPO_ROOT:/work" -w /work "$FEDORA_IMAGE" \
        packaging/rpm/build.sh --package gui --rpmarch "$arch" --version "$VERSION" \
            --gui-binary "$CONTAINER_BIN_DIR/node-gui" \
            --repo-root /work --out /work/packaging/dist

    # --- arch pkg: repackaging only; Arch images are amd64-only, so the
    # arm64 leg is cross-targeted from the amd64 container (like rpm) ---
    run_step "pkg mintlayer-node ($arch)" \
        docker run --rm -v "$REPO_ROOT:/work" -w /work "$ARCH_IMAGE" \
        packaging/arch/build.sh --package node --arch "$arch" --version "$VERSION" \
            --binaries-dir "$CONTAINER_BIN_DIR" \
            --out /work/packaging/dist

    run_step "pkg mintlayer-node-gui ($arch)" \
        docker run --rm -v "$REPO_ROOT:/work" -w /work "$ARCH_IMAGE" \
        packaging/arch/build.sh --package gui --arch "$arch" --version "$VERSION" \
            --gui-binary "$CONTAINER_BIN_DIR/node-gui" \
            --repo-root /work --out /work/packaging/dist

    # --- smoke tests in fresh containers ---
    if [ "$SKIP_SMOKE" -eq 0 ]; then
        run_step "smoke deb node ($debarch)" \
            docker run --rm $platform -v "$REPO_ROOT:/work" -w /work debian:12 \
            packaging/checks/smoke-deb.sh packaging/dist/Mintlayer_Node_linux_${VERSION}_${debarch}.deb \
            mintlayer-node node

        run_step "smoke deb gui ($debarch)" \
            docker run --rm $platform -v "$REPO_ROOT:/work" -w /work debian:12 \
            packaging/checks/smoke-deb.sh packaging/dist/Mintlayer_Node_GUI_linux_${VERSION}_${debarch}.deb \
            mintlayer-node-gui gui

        run_step "smoke rpm node ($arch)" \
            docker run --rm -v "$REPO_ROOT:/work" -w /work "$FEDORA_IMAGE" \
            packaging/checks/smoke-rpm.sh packaging/dist/Mintlayer_Node_linux_${VERSION}_${arch}.rpm \
            mintlayer-node node

        run_step "smoke rpm gui ($arch)" \
            docker run --rm -v "$REPO_ROOT:/work" -w /work "$FEDORA_IMAGE" \
            packaging/checks/smoke-rpm.sh packaging/dist/Mintlayer_Node_GUI_linux_${VERSION}_${arch}.rpm \
            mintlayer-node-gui gui

        # The aarch64 leg relies on the qemu binfmt handlers (already required
        # for the deb/rpm arm64 smoke tests) plus smoke-arch.sh's IgnoreArch
        # handling, mirroring the arm64 leg of release_linux.yml.
        run_step "smoke pkg node ($arch)" \
            docker run --rm -v "$REPO_ROOT:/work" -w /work "$ARCH_IMAGE" \
            packaging/checks/smoke-arch.sh packaging/dist/Mintlayer_Node_linux_${VERSION}_${arch}.pkg.tar.zst \
            mintlayer-node node "$arch"

        run_step "smoke pkg gui ($arch)" \
            docker run --rm -v "$REPO_ROOT:/work" -w /work "$ARCH_IMAGE" \
            packaging/checks/smoke-arch.sh packaging/dist/Mintlayer_Node_GUI_linux_${VERSION}_${arch}.pkg.tar.zst \
            mintlayer-node-gui gui "$arch"
    fi
done

# ---------------------------------------------------------------------------
# Artifact-name gate (what release.yml globs)
# ---------------------------------------------------------------------------
TRIPLES=()
for arch in "${ARCHES[@]}"; do TRIPLES+=("${DEBARCH[$arch]}:$arch:$arch"); done
run_step "artifact names" packaging/checks/verify-artifacts.sh "$DIST" "$VERSION" "${TRIPLES[@]}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "================ SUMMARY ($VERSION) ================"
for r in "${RESULTS[@]}"; do
    echo "  $r"
    if [[ "$r" == FAIL* ]]; then
        FAILED=1
    fi
done
echo "===================================================="
if [ "$FAILED" -eq 0 ]; then
    echo "ALL GREEN — safe to tag the release."
    echo "Artifacts in: $DIST"
else
    echo "FAILURES PRESENT — do not tag yet." >&2
    exit 1
fi
