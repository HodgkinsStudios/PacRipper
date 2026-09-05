#!/usr/bin/env bash
# Created by Jacob Hodgkins
set -euo pipefail
cd "$(dirname "$0")"
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
make -j"$JOBS" all
echo "PacRipper Ubuntu build: PASS"
echo "  bin/PacRipper"
echo "  bin/PacRipperCore"
