# PacRipper 1.0 Release Contents

**Created by Jacob Hodgkins**

The PacRipper 1.0 repository is intentionally ROM-free and source-first.

It contains:

- C++17 source for `PacRipper` and `PacRipperCore`
- deterministic Pac-Man/Puckman release scripts and semantic metadata
- Code::Blocks projects/workspace
- Linux, Windows, and macOS build scripts
- Windows and macOS standalone package scripts
- Docker/OCI build and native amd64/arm64 publication workflow
- ROM-free runtime, archive-safety, metadata, and release tests
- release/certification documentation
- MIT licensing, third-party notices, security policy, citation metadata, and contribution guidance

Generated native binaries are **not committed** to the source repository. Linux binaries are rebuilt locally/CI; Windows and macOS packages are produced by GitHub Actions; Docker images are published to GHCR.

The repository contains no canonical Pac-Man/Puckman ROM/PROM payloads and no pre-generated complete disassembly tree.
