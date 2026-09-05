# PacRipper V1.0 Release Status

**Created by Jacob Hodgkins**

Status: **PUBLIC RELEASE — CERTIFIED on Linux**

Certification date: 2026-09-01

## Build and safety

- Strict C++17 build with `-O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror`: **PASS**.
- Python script syntax compilation: **PASS**.
- Public terminology audit: **PASS**.
- Synthetic archive/output safety suite: **PASS**.
- Existing output without `--force`: **refused and existing data preserved**.
- Safe existing output with `--force`: **deliberate replacement PASS**.
- `PacRipper --version`: **1.0.0**.

## Pac-Man certification

- Direct canonical `pacman.7z` input: **PASS**.
- Semantic families: **381/381**.
- Z80 instructions: **5,414/5,414**.
- Semantic data spans: **257/257**.
- SjASMPlus 1.24.0: **0 errors / 0 warnings**.
- Program: **16,384/16,384 bytes exact**.
- Physical board set: **10/10 files, 25,376/25,376 bytes exact**.
- Program SHA-256: `e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77`.

## Puckman certification

- Direct canonical `puckman.zip` input: **PASS**.
- Semantic families: **381/381**.
- Z80 instructions: **5,414/5,414**.
- Semantic data spans: **257/257**.
- SjASMPlus 1.24.0: **0 errors / 0 warnings**.
- Program: **16,384/16,384 bytes exact**.
- Physical board set: **16/16 files, 25,376/25,376 bytes exact**.
- Program SHA-256: `de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef`.

## ROM-free certification

Dual-reference strict ROM-free audit against the external canonical Pac-Man and Puckman sets: **PASS**.

The distributable contains no canonical ROM/PROM payload, generated program ASM, reconstructed board image, nested ROM archive, reconstructive ROM literal block, or meaningful canonical ROM sequence in the shipping binaries.

## Platform note

The supplied prebuilt executables and this certification were produced on Linux. Windows/MinGW and Code::Blocks build files are included, but a Windows binary is not labeled certified until the same release suite is executed on Windows.
