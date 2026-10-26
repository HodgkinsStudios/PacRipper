# Changelog

## 1.0 — 2026-10-04

First public cross-platform release.

### Core release

- Certified canonical Pac-Man 10-file and Puckman 16-file input profiles.
- Exact physical-file identity validation using filename, size, CRC32, and SHA-256.
- Independent Pac-Man and Puckman source/disassembly outputs.
- Exact full-board reconstruction: Pac-Man 10/10 files and Puckman 16/16 files.
- Completed semantic coverage baseline: 381/381 semantic families, 5,414/5,414 instructions, and 257/257 non-code semantic spans.
- Resource-bounded ZIP/7z extraction with traversal, duplicate-path, file-type, decompression-size, and compression-ratio protections.
- Safe output policy: existing destinations require `--force`; dangerous destinations are always rejected.
- Strict ROM-free distribution and dual-reference audit.
- MIT license, provenance notices, security policy, generated-output legal policy, contribution guidance, and release gates.

### Linux

- Native C++17/GCC build through `build_ubuntu.sh` and the Makefile.
- Strict `-O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror` release build.
- ROM-free Linux release checks in GitHub Actions.

### Windows

- Native MinGW-w64 launcher with Unicode command-line handling.
- Python discovery through `py -3`, `python`, `python3`, or `PACRIPPER_PYTHON`.
- Executable-relative package discovery independent of the current working directory.
- Native 7-Zip preference for reliable Unicode `.7z` handling, with libarchive fallback.
- Static GCC/libstdc++ runtime linkage.
- Dedicated Code::Blocks `Windows Release` targets.
- Standalone Windows package staging and ROM-free runtime validation in GitHub Actions.

### macOS

- Native Apple Clang/libc++ build path.
- Universal `x86_64` + `arm64` Mach-O executables with a macOS 11 deployment target.
- dyld-based executable discovery for reliable packaged launches.
- Dedicated Code::Blocks `macOS Universal Release` targets.
- Standalone permission-preserving macOS package.
- Native macOS runtime tests covering Unicode paths, Python selection, ZIP/7z input, and both architecture slices.

### Docker / OCI

- Multi-stage ROM-free image that rebuilds PacRipper from source.
- Self-contained runtime with Python 3, libarchive, and 7-Zip.
- Non-root bind-mount workflow for distribution-independent Linux usage.
- Docker/Podman documentation including SELinux bind-mount guidance.
- Native `linux/amd64` and `linux/arm64` build/runtime validation.
- Public GHCR multi-architecture image with provenance/SBOM metadata.
