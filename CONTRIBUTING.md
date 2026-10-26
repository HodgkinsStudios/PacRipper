# Contributing to PacRipper

PacRipper is deliberately strict about exact reconstruction, ROM-free distribution, and safe handling of user archives.

Before proposing a source change:

1. Run `make release-check`.
2. Do not add ROM/PROM bytes, generated disassembly output, reconstructed ROMs, or copyrighted test fixtures to the repository.
3. Use only synthetic fixtures for locally maintained archive/security checks.
4. For changes affecting supported ROM profiles or reconstruction, independently run both canonical variants, verify the resulting assembler and physical-file round trips, and rerun `scripts/strict_rom_free_audit.py` with external lawful references.
5. Preserve the generated-output legal boundary and safe-output protections.

Bug reports should use hashes and minimal synthetic reproductions rather than attaching copyrighted ROM payloads publicly.
