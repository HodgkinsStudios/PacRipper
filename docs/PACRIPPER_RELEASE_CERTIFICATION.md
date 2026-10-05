# PacRipper 1.0 Dual-Variant Release Certification

**Created by Jacob Hodgkins**

## Scope

PacRipper 1.0 is locked to exactly two certified Pac-Man-family board identities: canonical Pac-Man and canonical Puckman. The public interface remains:

```text
PacRipper [--force] <input-rom.7z|.zip> <output-folder>
```

Variant selection is automatic from exact extracted member manifests authenticated by filename, size, CRC32, and SHA-256. Unsupported or altered sets are rejected.

## Independent source requirement

Each supported input produces a standalone source/disassembly tree that can rebuild its own original board set without the other variant. Pac-Man emits only `program/pacman.asm`; Puckman emits only `program/puckman.asm`. Each release also contains its own structured non-program sources and `verification/build_complete_rom_set.py`.

## Shared semantic coverage

Both certified outputs reproduce:

- semantic code families: **381/381 COMPLETE**;
- Z80 instructions: **5,414/5,414 COMPLETE**;
- semantic data spans: **257/257 COMPLETE**;
- program source accounting: **16,384/16,384 bytes**;
- unresolved source ownership at release boundary: **0**.

## Pac-Man certification

Input authority: self-contained canonical 10-file board set, preferred container `pacman.7z`.

External SjASMPlus 1.24.0 result for `program/pacman.asm`: **0 errors / 0 warnings**, 16,384 bytes.

Program SHA-256:

`e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77`

The generated Pac-Man tree's own rebuild helper reconstructs **10/10 physical files / 25,376/25,376 bytes exact**.

## Puckman certification

Input authority: self-contained canonical 16-file Puckman board set, certified container `puckman.zip`.

External SjASMPlus 1.24.0 result for `program/puckman.asm`: **0 errors / 0 warnings**, 16,384 bytes.

Program SHA-256:

`de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef`

The generated Puckman tree's own rebuild helper reconstructs **16/16 physical files / 25,376/25,376 bytes exact**. The generated Puckman output has no dependency on a Pac-Man output tree or `pacman.asm`.

## Source-driven variant semantics

Both variants use the common recovered address-space model, but variant bytes are read from the actual normalized input. The known executable variant at `$3020` therefore emits/executes `CP $30` for Pac-Man and `CP $40` for Puckman. Puckman's physical split, text/liveness overlay and graphics differences are represented by the Puckman release itself rather than borrowed from Pac-Man.

## Build, safety, and ROM-free gates

All C++ translation units must compile under `-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror`. `scripts/test_archive_safety.py` must pass, including archive resource limits and safe-output replacement behavior. The package's strict ROM-free audit is run against both canonical archives and must report no ROM/PROM payloads or derived binary copies. A final release is accepted only after a fresh extraction repeats both independent PacRipper → ASM → SjASMPlus → physical-board round trips.
