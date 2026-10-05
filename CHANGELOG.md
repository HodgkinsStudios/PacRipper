# Changelog

## Unreleased — Docker/OCI distribution

- Added a multi-stage ROM-free Docker image that compiles PacRipper from source.
- Added a self-contained Debian runtime with Python 3, libarchive, and 7-Zip support.
- Added host bind-mount usage that works across Docker/Podman-capable Linux distributions.
- Added non-root host-user, Unicode-path, synthetic ZIP, and synthetic 7z container runtime tests.
- Added a strict `.dockerignore` that excludes ROM/archive/generated-output payloads and checked-in native binaries from the build context.
- Added GitHub Actions validation plus multi-architecture `linux/amd64` and `linux/arm64` publication to GHCR.
- Switched multi-architecture publication from QEMU compilation to native x86-64 and ARM64 GitHub runners, with native runtime tests for both architectures before the final manifest is created.

## Unreleased — macOS port

- Added a native Apple Clang/libc++ build path for macOS.
- Added universal `x86_64` + `arm64` Mach-O binaries with a macOS 11 deployment target.
- Added dyld-based executable discovery so packaged launches do not depend on `argv[0]` or the current working directory.
- Added dedicated Code::Blocks `macOS Universal Release` targets.
- Added ROM-free macOS runtime tests covering Unicode paths, explicit Python selection, synthetic ZIP/7z input, and universal slices.
- Added `package_macos.sh` and a permission-preserving universal macOS tarball.
- Added a GitHub Actions macOS gate that validates the source tree and staged package before publishing `PacRipper-macOS-Universal`.

## Unreleased — Windows port

- Completed the native Windows/MinGW launcher path with Unicode command-line handling.
- Added Windows Python discovery for `py -3`, `python`, `python3`, and `PACRIPPER_PYTHON`.
- Made executable-relative package discovery reliable when PacRipper is launched from another working directory.
- Prefer native 7-Zip on Windows for reliable Unicode `.7z` handling, with libarchive fallback.
- Hardened the MinGW batch build with strict warnings and static GCC/libstdc++ runtime linkage.
- Added dedicated Code::Blocks `Windows Release` targets.
- Added GitHub Actions Windows build/runtime gates with synthetic ZIP/7z and Unicode-path tests.
- Added `package_windows.bat` and CI validation/publication of a self-contained standalone Windows package.

## V1.0 — 2026-09-01

First public release.

- Certified independent Pac-Man and Puckman source/disassembly outputs.
- Pac-Man canonical self-contained 10-file `.7z` input support.
- Puckman canonical self-contained 16-file `.zip` input support.
- Exact independent full-board reconstruction: Pac-Man 10/10 and Puckman 16/16 files.
- Strict ROM-free distribution audit.
- Public terminology cleanup and release-oriented source naming.
- Size + CRC32 + SHA-256 physical-ROM identity validation.
- Resource-bounded ZIP/7z extraction with traversal and duplicate-path protection.
- Safe output policy: existing destinations require `--force`; dangerous destinations are always refused.
- Generated-output legal notice distinguishing PacRipper's software license from user ROMs and ROM-derived output.
- MIT license, provenance/third-party notices, security policy, and formal release-build gates.
- GitHub repository preparation: ROM-free CI workflow, issue/PR templates, `.gitattributes`, cache cleanup, and repository contribution guards.
