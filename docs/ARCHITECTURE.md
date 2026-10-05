# PacRipper 1.0 Architecture

**Created by Jacob Hodgkins**

```text
PacRipper [--force] <pacman.7z|puckman.zip> <output-folder>
        |
        v
safe temporary archive extraction
        |
        v
exact variant detector / VariantProfile
        |
        +-- Pac-Man physical map: 10 files
        +-- Puckman physical map: 16 files
        |
        v
normalized logical board image
  16-KiB program + 8-KiB graphics + PROM roles
        |
        v
shared PacRipperCore analysis / recovery machinery
        |
        +-- source-driven variant bytes and semantic/liveness overlays
        +-- graphics/PROM recovery
        |
        v
variant-specific self-contained source tree
        |
        +-- Pac-Man: program/pacman.asm + 10-file map/rebuilder
        +-- Puckman: program/puckman.asm + 16-file map/rebuilder
        |
        v
independent source verifier / external-assembler round trip
```

`PacRipper` is the public two-argument front end. `PacRipperCore` is a private helper containing the recovered program/resource analysis machinery.

## Variant boundary

Variant detection happens before analysis. It uses the exact certified physical member manifests (name, size, CRC32, SHA-256). Unsupported, altered, or mixed sets are rejected rather than guessed. Physical layouts are normalized before reaching the shared decompiler so the large recovered semantic engine is not duplicated.

The normalized representation does not erase variant truth: the analyzer consumes the actual normalized bytes, and the release builder applies the detected variant's physical mapping and semantic/liveness metadata. Puckman therefore emits its actual `$3020` `CP $40` instruction and Puckman data descriptors, while Pac-Man independently emits `CP $30` and its own data/liveness representation.

## Independence guarantee

Generated releases share no cross-variant source dependency. A Puckman output does not require `pacman.asm`, the Pac-Man output directory, or Pac-Man ROM files. A Pac-Man output does not require any Puckman source or ROM files. Each output contains its own assembly source, structured non-program sources, physical layout manifest and rebuild/verification helper.

## ROM-free boundary

Input archives live only outside the distributable and in temporary extraction during a run. PacRipper writes source/semantic representations to the destination, never copied raw input board files. `scripts/strict_rom_free_audit.py` accepts both canonical reference archives at audit time and rejects accidental payload inclusion from either supported set.
