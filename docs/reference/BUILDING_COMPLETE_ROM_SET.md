# Building the Complete Pac-Man ROM/PROM Set

**Created by Jacob Hodgkins**

This release has a proven full round-trip path from the recovered source representations back to the complete active 10-file Pac-Man board set. The Z80 program must be assembled by an independent external Z80 assembler; this project does not provide or substitute its own assembler.

## 1. Assemble the human-readable Z80 program

Using SjASMPlus from the release root:

```bash
mkdir -p build
sjasmplus --raw=build/pacman_program.bin program/pacman.asm
```

The output must be exactly **16,384 bytes** and have SHA-256:

`e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77`

Check with:

```bash
stat -c '%s bytes' build/pacman_program.bin
sha256sum build/pacman_program.bin
```

## 2. Build all ten physical board files

The supplied helper takes that independently assembled 16-KiB program image, splits it into the four program ROMs, and reconstructs the six graphics/color/audio ROM/PROM files from this release's structured source data:

```bash
python3 verification/build_complete_rom_set.py . build/pacman_program.bin build/pacman_romset
```

It writes:

- `pacman.6e` — 4096 bytes
- `pacman.6f` — 4096 bytes
- `pacman.6h` — 4096 bytes
- `pacman.6j` — 4096 bytes
- `pacman.5e` — 4096 bytes
- `pacman.5f` — 4096 bytes
- `82s123.7f` — 32 bytes
- `82s126.4a` — 256 bytes
- `82s126.1m` — 256 bytes
- `82s126.3m` — 256 bytes

Total: **25,376 bytes**.

## 3. Optional byte-exact certification against a canonical set

If you legally possess a canonical Pac-Man ROM folder, 7z, or ZIP, use:

```bash
python3 verification/build_complete_rom_set.py . build/pacman_program.bin build/pacman_romset --canonical /path/to/pacman.7z
```

A certified result ends with:

```text
canonical_round_trip=PASS 10/10 files 25376/25376 bytes exact
```

You may additionally run the source-only complete-board verifiers:

```bash
python3 verification/verify_human_semantics.py . --require-complete
python3 verification/verify_complete_board_export.py . /path/to/pacman.7z
```

## What this proves

The program ROMs are not reconstructed by copying hidden ROM bytes: `program/pacman.asm` is accepted by an independent Z80 assembler and produces the certified program image. The six non-program devices are rebuilt from the decoded/sourceified graphics, palette, lookup, waveform, and timing/control source data. Together these paths reproduce the complete active board denominator byte-for-byte.
