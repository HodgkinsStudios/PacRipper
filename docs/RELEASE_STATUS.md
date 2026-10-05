# PacRipper 1.0 Release Status

**Created by Jacob Hodgkins**

Status: **PUBLIC RELEASE — CERTIFIED**

Release date: **2026-10-04**

## Version

All public release metadata is normalized to:

```text
PacRipper 1.0
```

The canonical version is stored in `VERSION`, and `make release-check` includes a metadata audit that rejects stale 1.0 release metadata.

## Platform validation

| Platform | Status | Validation |
| --- | --- | --- |
| Linux | **PASS** | Strict C++17 release build and ROM-free release gates |
| Windows | **PASS** | Native MinGW build, runtime tests, Unicode ZIP/7z coverage, standalone package |
| macOS | **PASS** | Universal x86_64 + arm64 build, runtime tests, standalone package |
| Docker linux/amd64 | **PASS** | Native build and ROM-free runtime suite |
| Docker linux/arm64 | **PASS** | Native ARM64 build and ROM-free runtime suite |
| GHCR manifest | **PASS** | Multi-architecture manifest plus anonymous pull verification |

## Pac-Man certification

- Direct canonical `pacman.7z` input: **PASS**
- Semantic families: **381/381**
- Z80 instructions: **5,414/5,414**
- Semantic data spans: **257/257**
- SjASMPlus 1.24.0: **0 errors / 0 warnings**
- Program: **16,384/16,384 bytes exact**
- Physical board set: **10/10 files, 25,376/25,376 bytes exact**
- Program SHA-256: `e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77`

## Puckman certification

- Direct canonical `puckman.zip` input: **PASS**
- Semantic families: **381/381**
- Z80 instructions: **5,414/5,414**
- Semantic data spans: **257/257**
- SjASMPlus 1.24.0: **0 errors / 0 warnings**
- Program: **16,384/16,384 bytes exact**
- Physical board set: **16/16 files, 25,376/25,376 bytes exact**
- Program SHA-256: `de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef`

## ROM-free certification

The distributable repository contains no canonical ROM/PROM payload, reconstructed board image, user archive, generated complete disassembly tree, or meaningful canonical ROM sequence in checked-in release artifacts.

Exact dual-reference round-trip checks remain offline release gates because the canonical ROM/PROM references are intentionally absent from public CI.
