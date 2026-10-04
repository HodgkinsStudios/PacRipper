# PacRipper V1.0 Release Contents

**Created by Jacob Hodgkins**

This package is intentionally ROM-free. It contains the PacRipper C++ source, deterministic dual-variant release scripts and semantic metadata, Code::Blocks/command-line build files for Linux, Windows, and macOS, documentation, licensing/provenance/security files, and the checked-in PacRipper Linux executables. Native Windows and universal macOS packages are built and validated by GitHub Actions rather than committed as binary copies.

It does **not** contain:

- any of the 10 canonical Pac-Man ROM/PROM payload files;
- any of the 16 canonical Puckman ROM/PROM payload files;
- either user's input archive;
- a pre-generated Pac-Man or Puckman disassembly/output tree;
- PacRipper's unrelated later runtime/frontend research implementation.

Exact ROM filenames, expected sizes, CRC32 values, SHA-256 hashes, program hashes, addresses and other validation metadata necessarily appear in source so PacRipper can identify the two certified inputs without copying their payloads.

The release also includes `LICENSE`, `THIRD_PARTY_NOTICES.md`, `SECURITY.md`, `CHANGELOG.md`, and generated-output legal policy documentation.
