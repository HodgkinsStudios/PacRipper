#!/usr/bin/env bash
# PacRipper standalone macOS package staging
# Created by Jacob Hodgkins
set -euo pipefail
cd "$(dirname "$0")"

DEST="${1:-dist/PacRipper-macOS}"
ARCHIVE="${2:-dist/PacRipper-macOS-universal.tar.gz}"

if [[ ! -x bin/PacRipper ]]; then
  echo "ERROR: bin/PacRipper is missing. Run ./build_macos.sh first." >&2
  exit 1
fi
if [[ ! -x bin/PacRipperCore ]]; then
  echo "ERROR: bin/PacRipperCore is missing. Run ./build_macos.sh first." >&2
  exit 1
fi

rm -rf "$DEST"
rm -f "$ARCHIVE"
mkdir -p "$DEST/bin" "$(dirname "$ARCHIVE")"

install -m 0755 bin/PacRipper "$DEST/bin/PacRipper"
install -m 0755 bin/PacRipperCore "$DEST/bin/PacRipperCore"

for directory in scripts semantic config docs; do
  if [[ -d "$directory" ]]; then
    cp -R "$directory" "$DEST/$directory"
  fi
done

for file in README.md BUILDING.md CHANGELOG.md LICENSE THIRD_PARTY_NOTICES.md RELEASE_MANIFEST.txt SECURITY.md CITATION.cff; do
  if [[ -f "$file" ]]; then
    cp "$file" "$DEST/$file"
  fi
done

find "$DEST" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$DEST" -type f -name '*.pyc' -delete

tar -czf "$ARCHIVE" -C "$(dirname "$DEST")" "$(basename "$DEST")"

echo "PacRipper standalone macOS package staged at:"
echo "  $DEST"
echo "Archive:"
echo "  $ARCHIVE"
