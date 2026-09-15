#!/usr/bin/env bash
# Verify that the produced artifacts match the exact names the release
# workflow globs (release.yml: artifacts: "Mintlayer*/*").
# Usage: verify-artifacts.sh <dist-dir> <version> <arch-pairs...>
#   arch-pairs: list of "debarch:rpmarch" pairs, e.g. amd64:x86_64 arm64:aarch64
set -euo pipefail

DIST_DIR="$1"
VERSION="$2"
shift 2

MISSING=0
for pair in "$@"; do
    DEBARCH="${pair%%:*}"
    RPMARCH="${pair##*:}"

    for f in "Mintlayer_Node_linux_${VERSION}_${DEBARCH}.deb" \
             "Mintlayer_Node_GUI_linux_${VERSION}_${DEBARCH}.deb" \
             "Mintlayer_Node_linux_${VERSION}_${RPMARCH}.rpm" \
             "Mintlayer_Node_GUI_linux_${VERSION}_${RPMARCH}.rpm"; do
        if [ -f "$DIST_DIR/$f" ]; then
            echo "ok:      $f"
        else
            echo "MISSING: $f"
            MISSING=$((MISSING + 1))
        fi
    done
done

[ "$MISSING" -eq 0 ] || {
    echo "$MISSING artifact(s) missing or misnamed" >&2
    exit 1
}
echo "ALL ARTIFACTS OK"
