# Changelog

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
