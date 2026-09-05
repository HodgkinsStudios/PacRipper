# Canonical Puckman Input — PacRipper V1.0

**Created by Jacob Hodgkins**

PacRipper V1.0 supports the certified self-contained 16-file Puckman board set supplied as `puckman.zip`. Detection is based on exact member names, sizes, CRC32 values, and SHA-256 hashes rather than the archive filename.

The physical set contains eight 2-KiB program ROMs, four 2-KiB graphics ROMs, and four PROMs, totaling **25,376 bytes**. PacRipper authenticates all sixteen physical files before analysis, normalizes them into the common Pac-Man-family logical address space, and then emits a Puckman-specific standalone release whose exact program source is `program/puckman.asm`.

The certified normalized program SHA-256 is:

`de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef`

External SjASMPlus 1.24.0 assembly succeeds with 0 errors and 0 warnings. The generated Puckman tree's own rebuild helper reconstructs all **16/16 original physical files, 25,376/25,376 bytes exact**, without any dependency on a Pac-Man disassembly or ROM set.
