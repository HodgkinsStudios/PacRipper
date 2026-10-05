#!/usr/bin/env bash
# PacRipper native macOS universal build
# Created by Jacob Hodgkins
set -euo pipefail
cd "$(dirname "$0")"

CXX_BIN="${CXX:-clang++}"
DEPLOY_TARGET="${MACOSX_DEPLOYMENT_TARGET:-11.0}"
ARCH_LIST="${PACRIPPER_MAC_ARCHS:-x86_64 arm64}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "ERROR: build_macos.sh must be run on macOS." >&2
  exit 1
fi

if ! command -v "$CXX_BIN" >/dev/null 2>&1; then
  echo "ERROR: Apple Clang C++ compiler not found: $CXX_BIN" >&2
  echo "Install the Xcode Command Line Tools with: xcode-select --install" >&2
  exit 1
fi

ARCH_FLAGS=()
for arch in $ARCH_LIST; do
  case "$arch" in
    x86_64|arm64) ARCH_FLAGS+=("-arch" "$arch") ;;
    *)
      echo "ERROR: unsupported macOS architecture: $arch" >&2
      exit 1
      ;;
  esac
done

COMMON_FLAGS=(
  -Isrc
  -O2
  -DNDEBUG
  -std=c++17
  -Wall
  -Wextra
  -Wpedantic
  -Werror
  -stdlib=libc++
  "-mmacosx-version-min=$DEPLOY_TARGET"
)

rm -rf obj/macos
rm -f bin/PacRipper bin/PacRipperCore
mkdir -p obj/macos/core bin

CORE_OBJECTS=()
while IFS= read -r source || [[ -n "$source" ]]; do
  [[ -z "$source" ]] && continue
  object="obj/macos/core/${source#src/}"
  object="${object%.cpp}.o"
  mkdir -p "$(dirname "$object")"
  "$CXX_BIN" "${COMMON_FLAGS[@]}" "${ARCH_FLAGS[@]}" -c "$source" -o "$object"
  CORE_OBJECTS+=("$object")
done < config/core_sources.txt

CORE_MAIN="obj/macos/core/pacripper_core_main.o"
"$CXX_BIN" "${COMMON_FLAGS[@]}" "${ARCH_FLAGS[@]}" -c src/pacripper_core_main.cpp -o "$CORE_MAIN"
"$CXX_BIN" "${COMMON_FLAGS[@]}" "${ARCH_FLAGS[@]}" "${CORE_OBJECTS[@]}" "$CORE_MAIN" -o bin/PacRipperCore

"$CXX_BIN" "${COMMON_FLAGS[@]}" "${ARCH_FLAGS[@]}" src/main.cpp -o bin/PacRipper

EXPECTED_ARCHES=()
for arch in $ARCH_LIST; do EXPECTED_ARCHES+=("$arch"); done
for executable in bin/PacRipper bin/PacRipperCore; do
  actual="$(lipo -archs "$executable")"
  for arch in "${EXPECTED_ARCHES[@]}"; do
    if [[ " $actual " != *" $arch "* ]]; then
      echo "ERROR: $executable is missing required architecture $arch (actual: $actual)" >&2
      exit 1
    fi
  done
done

if [[ "$(./bin/PacRipper --version)" != "PacRipper 1.0" ]]; then
  echo "ERROR: PacRipper macOS launcher smoke test failed." >&2
  exit 1
fi

echo "PacRipper macOS build: PASS"
echo "  bin/PacRipper ($(lipo -archs bin/PacRipper))"
echo "  bin/PacRipperCore ($(lipo -archs bin/PacRipperCore))"
