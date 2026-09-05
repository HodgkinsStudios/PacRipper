# PacRipper V1.0 Strict ROM-Free Release Audit

**Created by Jacob Hodgkins**

PacRipper's distributable project is intentionally separated from both user-supplied canonical ROM sets. It contains no pre-generated `pacman.asm` or `puckman.asm`, reconstructed ROM images, graphics/PROM payloads, ROM test fixtures, nested ROM archives, or cached reconstruction output.

## Runtime-derived proof policy

The public variant detector authenticates every required physical input file by filename, exact size, CRC32, and SHA-256 before analysis. Analysis consumes the authenticated user bytes at runtime. Structural/semantic relationships are checked without storing a copy of either ROM set in PacRipper.

## Dual-reference audit command

For release certification, provide both canonical sets only as external references:

```bash
python3 scripts/strict_rom_free_audit.py . /path/to/pacman.7z /path/to/puckman.zip
```

The verifier rejects complete reference files, generated ASM/ROM/PROM/archive artifacts, nested compressed payloads, historical raw-byte proof idioms, meaningful high-entropy ROM subsequences, reconstructive source literal blocks, encoded ROM payloads and standard compressed copies.

The certified V1.0 audit covers **26 physical reference files across 2 canonical sets**. Metadata such as names, sizes, CRC/SHA hashes, opcodes, addresses and semantic identifiers is intentionally permitted because those values are not ROM payload copies.

## Functional regression requirement

ROM-free certification is paired with independent round-trip certification:

- Pac-Man: 381/381 families, 5,414/5,414 instructions, 257/257 data spans, `pacman.asm` external assembly, **10/10 files / 25,376/25,376 bytes exact**;
- Puckman: 381/381 families, 5,414/5,414 instructions, 257/257 data spans, `puckman.asm` external assembly, **16/16 files / 25,376/25,376 bytes exact**.
