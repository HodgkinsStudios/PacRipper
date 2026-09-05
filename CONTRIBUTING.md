# Contributing to PacRipper

PacRipper is deliberately strict about exact reconstruction, ROM-free distribution, and safe handling of user archives.

Before proposing a source change:

1. Run `make release-check`.
2. Do not add ROM/PROM bytes, generated disassembly output, reconstructed ROMs, or copyrighted test fixtures to the repository.
3. Use synthetic fixtures for archive/security tests.
4. For changes affecting supported ROM profiles or reconstruction, independently certify both canonical variants with `scripts/test_certified_variants.py` and rerun the dual-reference strict ROM-free audit.
5. Preserve the generated-output legal boundary and safe-output protections.

Bug reports should use hashes and minimal synthetic reproductions rather than attaching copyrighted ROM payloads publicly.
