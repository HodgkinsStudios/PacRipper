# PacRipper 1.0 Release Checklist

PacRipper 1.0 is considered ready for public release when every applicable gate below has passed.

- [x] `VERSION` contains `1.0`.
- [x] CLI `PacRipper --version` returns `PacRipper 1.0`.
- [x] `make release-check` succeeds from a clean Linux tree.
- [x] Release identifiers and CLI version are aligned at 1.0.
- [x] Windows MinGW CI builds and verifies the version of source and staged-package executables.
- [x] macOS CI builds universal `x86_64` + `arm64` binaries and verifies the staged package version.
- [x] Docker CI builds and verifies the CLI version natively on `linux/amd64`.
- [x] Docker CI builds and verifies the CLI version natively on `linux/arm64`.
- [x] GHCR publication produces a multi-platform manifest containing both architectures.
- [x] Anonymous GHCR manifest access succeeds after logout.
- [x] Pac-Man direct canonical input certification passes.
- [x] Pac-Man SjASMPlus round trip passes with 0 errors / 0 warnings.
- [x] Pac-Man reconstructs 10/10 physical files, 25,376/25,376 bytes exact.
- [x] Puckman direct canonical input certification passes.
- [x] Puckman SjASMPlus round trip passes with 0 errors / 0 warnings.
- [x] Puckman reconstructs 16/16 physical files, 25,376/25,376 bytes exact.
- [x] Dual-reference strict ROM-free audit passes.
- [x] Public source tree omits standalone runtime test and release-lint scripts.
- [x] No generated binaries, user ROM archives, generated disassembly trees, object files, or caches are committed unintentionally.
- [x] `LICENSE`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `CHANGELOG.md`, citation metadata, and legal-output documentation are present.
