#!/usr/bin/env bash
# Generate the hicolor icon set for mintlayer-node-gui from the 512px source.
# Usage: make-icons.sh <src-512.png> <output-dir>
# Produces <output-dir>/usr/share/icons/hicolor/{64,128,256,512}x{...}/apps/mintlayer-node-gui.png
set -euo pipefail

if [ $# -ne 2 ] || [ ! -f "$1" ]; then
    echo "usage: $0 <src-512.png> <output-dir>" >&2
    exit 1
fi
SRC="$1"
OUT="$2"

if command -v magick >/dev/null 2>&1; then
    CONVERT=(magick)
elif command -v convert >/dev/null 2>&1; then
    CONVERT=(convert)
else
    echo "error: ImageMagick not found (install imagemagick)" >&2
    exit 1
fi

# The 512 entry is a plain copy; refuse an undersized source that would
# produce mismatched/upscaled smaller sizes.
if command -v identify >/dev/null 2>&1; then
    width="$(identify -format '%w' "$SRC" 2>/dev/null || echo 0)"
    [ "${width:-0}" -ge 512 ] || {
        echo "error: $SRC is ${width}px wide, need at least 512" >&2
        exit 1
    }
fi

for size in 512 256 128 64; do
    dir="$OUT/usr/share/icons/hicolor/${size}x${size}/apps"
    mkdir -p "$dir"
    if [ "$size" = 512 ]; then
        cp "$SRC" "$dir/mintlayer-node-gui.png"
    else
        "${CONVERT[@]}" "$SRC" -resize "${size}x${size}" "$dir/mintlayer-node-gui.png"
    fi
done

echo "icons generated in $OUT"
