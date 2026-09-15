#!/usr/bin/env bash
# Generate the hicolor icon set for mintlayer-node-gui from the 512px source.
# Usage: make-icons.sh <src-512.png> <output-dir>
# Produces <output-dir>/usr/share/icons/hicolor/{64,128,256,512}x{...}/apps/mintlayer-node-gui.png
set -euo pipefail

SRC="$1"
OUT="$2"

command -v convert >/dev/null || {
    echo "error: ImageMagick 'convert' not found (install imagemagick)" >&2
    exit 1
}

for size in 512 256 128 64; do
    dir="$OUT/usr/share/icons/hicolor/${size}x${size}/apps"
    mkdir -p "$dir"
    if [ "$size" = 512 ]; then
        cp "$SRC" "$dir/mintlayer-node-gui.png"
    else
        convert "$SRC" -resize "${size}x${size}" "$dir/mintlayer-node-gui.png"
    fi
done

echo "icons generated in $OUT"
