# PacRipper V1.0 Output Compatibility

**Created by Jacob Hodgkins**

Pac-Man preserves the certified single-source model: `program/pacman.asm` remains both the human-readable disassembly and exact reconstruction source, and the complete generated tree rebuilds the canonical 10-file board set byte-for-byte.

Puckman extends that model rather than sharing Pac-Man's generated source. It independently emits `program/puckman.asm`, its own variant/physical manifests and its own complete-board rebuild helper. Its generated tree rebuilds the canonical 16-file Puckman set byte-for-byte without requiring the Pac-Man output.

Both variants use the same semantic completeness gates (381 families, 5,414 instructions, 257 data spans) and the same public-source portability cleanup. Literal whole-tree parity between Pac-Man and Puckman is neither required nor desirable: variant-specific instructions, data liveness, graphics and physical chip mappings remain distinct.

Certified external round trips:

- Pac-Man: SjASMPlus 1.24.0, 0 errors / 0 warnings, **10/10 / 25,376 bytes exact**;
- Puckman: SjASMPlus 1.24.0, 0 errors / 0 warnings, **16/16 / 25,376 bytes exact**.
