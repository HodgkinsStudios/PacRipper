# PacRipper V1.0 Release Checklist

A public release is accepted only when all of these gates pass:

- [ ] `make release-check` succeeds from a clean Linux tree.
- [ ] Windows MinGW CI builds and passes `scripts/test_windows_runtime.py` from both the source tree and staged Windows package.
- [ ] macOS CI builds universal `x86_64` + `arm64` binaries and passes `scripts/test_macos_runtime.py` from both the source tree and staged macOS package.
- [ ] Docker CI builds from source and passes `scripts/test_docker_runtime.py` with non-root bind mounts plus synthetic ZIP/7z input.
- [ ] GHCR publication produces a multi-platform manifest containing both `linux/amd64` and `linux/arm64`.
- [ ] Pac-Man direct `pacman.7z` run succeeds from a fresh package extraction.
- [ ] Pac-Man `program/pacman.asm` assembles with SjASMPlus with 0 errors / 0 warnings.
- [ ] Pac-Man reconstructs 10/10 physical files, 25,376/25,376 bytes exact.
- [ ] Puckman direct `puckman.zip` run succeeds independently.
- [ ] Puckman `program/puckman.asm` assembles with SjASMPlus with 0 errors / 0 warnings.
- [ ] Puckman reconstructs 16/16 physical files, 25,376/25,376 bytes exact.
- [ ] `scripts/strict_rom_free_audit.py` passes against both external canonical references.
- [ ] Public terminology audit passes.
- [ ] No user ROM archive, generated disassembly tree, cache, object file, or test payload is packaged unintentionally.
- [ ] `LICENSE`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `CHANGELOG.md`, and legal-output documentation are present.
- [ ] Shipping permissions are normalized (755 executables/scripts; 644 source/docs/configuration).
- [ ] Published release artifact SHA-256 values are recorded (including the permission-preserving macOS tarball).
