# Canonical Pac-Man Input — PacRipper V1.0

**Created by Jacob Hodgkins**

PacRipper V1.0 uses the self-contained **10-file Pac-Man board set** as its canonical input authority. The certified reference container is `pacman.7z`; canonical identity is the extracted board content, not 7z compression metadata.

PacRipper authenticates each physical chip by filename, exact size, CRC32, and SHA-256.

## Required board members

| File | Size | CRC32 | SHA-256 | Role |
|---|---:|---:|---|---|
| `pacman.6e` | 4096 | `C1E6AB10` | `fe1c3234df345855d30728637f361f79472cabfe2a892a7567c63eaf31a4217b` | Program |
| `pacman.6f` | 4096 | `1A6FB2D4` | `09a723c9f84790e9019633e37761cfa4e9d7ab6db14f6fdb12738f51fec11065` | Program |
| `pacman.6h` | 4096 | `BCDD1BEB` | `69347409739b64ed9d9b19713de0bc66627bd137687de649796b9d2ef88ed8e6` | Program |
| `pacman.6j` | 4096 | `817D94E3` | `03ee523c210e87fb8dd1d925b092ad269fdd753b5b7a20b3757b0ceee5f18679` | Program |
| `pacman.5e` | 4096 | `0C944964` | `8d9a86c97fe94b1fd010b139672c330e3b257ba59b0d8df7a821592e30a77b4b` | Character graphics |
| `pacman.5f` | 4096 | `958FEDF9` | `49c8f656cb8ea1ae02fb64a2c09df98e7f06a034b43c6c8240032df417c6d36f` | Sprite graphics |
| `82s123.7f` | 32 | `2FC650BD` | `48fe0b01d68e3d702019ca715f7266c8e3261c769509b281720f53ca0a1cc8fb` | Palette PROM |
| `82s126.4a` | 256 | `3EB3A8E4` | `ef8f7a3b0c10f787d9cc1cbc5cc266fcc1afadb24c3b4d610fe252b9c3df1d76` | Color lookup PROM |
| `82s126.1m` | 256 | `A9CC86BF` | `8e723ad91e46ef1a186b2ed3c99a8bf1c571786bc7ceae2b367cbfc80857a394` | Waveform PROM |
| `82s126.3m` | 256 | `77245B66` | `8c34002652e587aa19a77bff9040d870af18b4b2fe5c5f0ed962899386e0e751` | Sound timing/control PROM |

Total: **10 files / 25,376 bytes**.

PacRipper accepts this set directly as `.7z` and also accepts a self-contained ZIP containing the same ten authenticated members. Split-set parent resolution and other Pac-Man-family revisions beyond the separately certified Puckman profile are intentionally outside V1.0.
