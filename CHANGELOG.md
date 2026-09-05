# Changelog

## V1.0 — 2026-09-01

First public release.

- Certified independent Pac-Man and Puckman source/disassembly outputs.
- Pac-Man canonical self-contained 10-file `.7z` input support.
- Puckman canonical self-contained 16-file `.zip` input support.
- Exact independent full-board reconstruction: Pac-Man 10/10 and Puckman 16/16 files.
- Strict ROM-free distribution audit.
- Public terminology cleanup and release-oriented source naming.
- Size + CRC32 + SHA-256 physical-ROM identity validation.
- Resource-bounded ZIP/7z extraction with traversal and duplicate-path protection.
- Safe output policy: existing destinations require `--force`; dangerous destinations are always refused.
- Generated-output legal notice distinguishing PacRipper's software license from user ROMs and ROM-derived output.
- MIT license, provenance/third-party notices, security policy, and formal release-build gates.
- GitHub repository preparation: ROM-free CI workflow, issue/PR templates, `.gitattributes`, cache cleanup, and repository contribution guards.
