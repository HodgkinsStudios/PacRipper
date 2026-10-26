# Full Round-Trip Rebuild Certification

**Created by Jacob Hodgkins**  
**Certified:** 2026-08-30

## Result

The Pac-Man full-board disassembly/source-recovery package has completed the external-assembler round-trip gate.

- Human-readable Z80 source: `program/pacman.asm`
- Independent external assembler used for certification: **SjASMPlus**
- Assembled program size: **16,384 / 16,384 bytes**
- Assembled program SHA-256: `e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77`
- Program ROM banks reproduced: **4 / 4 exact**
- Graphics ROMs reproduced from structured source: **2 / 2 exact**
- Color PROMs reproduced from structured source: **2 / 2 exact**
- Audio/control PROMs reproduced from structured source: **2 / 2 exact**
- Complete active board set: **10 / 10 files exact**
- Complete active board bytes: **25,376 / 25,376 exact**

The final rebuilt files were independently compared byte-for-byte with the separately supplied canonical set and all ten matched.

## Certified file SHA-256 values

```text
fe1c3234df345855d30728637f361f79472cabfe2a892a7567c63eaf31a4217b  pacman.6e
09a723c9f84790e9019633e37761cfa4e9d7ab6db14f6fdb12738f51fec11065  pacman.6f
69347409739b64ed9d9b19713de0bc66627bd137687de649796b9d2ef88ed8e6  pacman.6h
03ee523c210e87fb8dd1d925b092ad269fdd753b5b7a20b3757b0ceee5f18679  pacman.6j
8d9a86c97fe94b1fd010b139672c330e3b257ba59b0d8df7a821592e30a77b4b  pacman.5e
49c8f656cb8ea1ae02fb64a2c09df98e7f06a034b43c6c8240032df417c6d36f  pacman.5f
48fe0b01d68e3d702019ca715f7266c8e3261c769509b281720f53ca0a1cc8fb  82s123.7f
ef8f7a3b0c10f787d9cc1cbc5cc266fcc1afadb24c3b4d610fe252b9c3df1d76  82s126.4a
8e723ad91e46ef1a186b2ed3c99a8bf1c571786bc7ceae2b367cbfc80857a394  82s126.1m
8c34002652e587aa19a77bff9040d870af18b4b2fe5c5f0ed962899386e0e751  82s126.3m
```

## Scope wording

A technically accurate release statement is: **the package recovers the complete active Pac-Man board ROM/PROM source representations and can rebuild the complete canonical 10-file set byte-for-byte; the Z80 program rebuild is independently assembler-certified with SjASMPlus.**

No raw canonical ROM/PROM payload files are required to be distributed with this source release. Canonical files are only needed when a user wants to perform an independent byte-comparison certification.
