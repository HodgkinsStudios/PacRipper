# PacRipper 1.0

**Created by Jacob Hodgkins**

[![Release Check](https://github.com/HodgkinsStudios/PacRipper/actions/workflows/release-check.yml/badge.svg)](https://github.com/HodgkinsStudios/PacRipper/actions/workflows/release-check.yml)
[![Docker Image](https://github.com/HodgkinsStudios/PacRipper/actions/workflows/docker-image.yml/badge.svg)](https://github.com/HodgkinsStudios/PacRipper/actions/workflows/docker-image.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

PacRipper is a ROM-free C++17 command-line research and reconstruction tool for two certified Pac-Man-family arcade board sets: canonical **Pac-Man** and canonical **Puckman**. It validates the supplied physical ROM/PROM set, analyzes the board program and resources, and produces a standalone human-readable source/disassembly package with exact-board reconstruction tooling.

PacRipper stands for **Pac**kage **R**om **I**nteractive **P**arser & **P**rogrammable **E**ngineering **R**econstructor.

## Release

Current public release: **1.0**

```text
PacRipper 1.0
```

PacRipper 1.0 supports:

| Platform | Release path |
| --- | --- |
| Linux | Native C++17/GCC build |
| Windows | Native MinGW-w64 build and standalone package |
| macOS | Universal Intel + Apple Silicon build |
| Other Linux distributions | Docker/Podman image for linux/amd64 and linux/arm64 |

The public Docker image is:

```text
ghcr.io/hodgkinsstudios/pacripper:1.0
```

The `latest` tag points to the current 1.0 image.

## Supported inputs

PacRipper 1.0 intentionally accepts exactly two certified board identities:

- **Pac-Man** — canonical self-contained 10-file board set. The reference container is `pacman.7z`; an equivalent ZIP or 7z containing the same ten physical files is accepted.
- **Puckman** — canonical self-contained 16-file board set. The reference container is `puckman.zip`.

Every required physical file is authenticated by **filename + exact size + CRC32 + SHA-256**. Archive filenames alone are not trusted. Other revisions, hacks, split parent/clone combinations, altered files, and mixed sets are rejected.

PacRipper does **not** include either ROM set.

## Native usage

Build on Linux:

```bash
./build_ubuntu.sh
```

Build on macOS:

```bash
./build_macos.sh
```

Build on Windows with MinGW-w64:

```bat
build_windows_mingw.bat
```

Then run:

```text
PacRipper [--force] <input-rom.7z|.zip> <output-folder>
```

Examples:

```bash
./bin/PacRipper ~/roms/pacman.7z ~/PacMan_Disassembly
./bin/PacRipper ~/roms/puckman.zip ~/Puckman_Disassembly
```

Windows:

```bat
bin\PacRipper.exe "C:\ROMs\pacman.7z" "C:\PacRipper Output\PacMan_Disassembly"
bin\PacRipper.exe "C:\ROMs\puckman.zip" "C:\PacRipper Output\Puckman_Disassembly"
```

Check the version with:

```bash
./bin/PacRipper --version
```

which returns:

```text
PacRipper 1.0
```

## Docker / Podman

Docker provides the easiest distribution-independent Linux path:

```bash
docker pull ghcr.io/hodgkinsstudios/pacripper:1.0

mkdir -p PacMan_Disassembly

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" \
  ghcr.io/hodgkinsstudios/pacripper:1.0 \
  /work/pacman.7z /work/PacMan_Disassembly
```

The image is published and runtime-tested natively on both **linux/amd64** and **linux/arm64**. It contains PacRipper, Python 3, libarchive, 7-Zip, and the required C++ runtime libraries; it contains no ROM/PROM payloads.

Podman users can replace `docker` with `podman`. On SELinux-enforcing hosts such as Fedora/RHEL, use `-v "$PWD:/work:Z"`.

## Output safety

PacRipper refuses to replace an existing output destination unless `--force` is explicitly supplied:

```bash
./bin/PacRipper --force ~/roms/pacman.7z ~/PacMan_Disassembly
```

`--force` never disables destructive-path protections. PacRipper refuses filesystem roots, the user's home directory itself, PacRipper's application tree/ancestors, the current working directory/ancestors, symlink destinations, and destinations that would contain or delete the input archive.

Input archives are treated as untrusted. ZIP/7z handling enforces member-count, member-size, total-expanded-size, duplicate-path, traversal, file-type, and compression-ratio protections. See `docs/ARCHIVE_AND_OUTPUT_SAFETY.md`.

## Independent outputs

Pac-Man produces:

```text
program/pacman.asm
```

and independently reconstructs **10/10 physical files, 25,376/25,376 bytes exact**.

Puckman produces:

```text
program/puckman.asm
```

and independently reconstructs **16/16 physical files, 25,376/25,376 bytes exact**.

The Puckman output does not depend on `pacman.asm`, a Pac-Man output tree, or the Pac-Man ROM set. Both generated trees include structured graphics/PROM sources, semantic documentation, manifests, verification tools, rebuild helpers, and a generated legal notice for ROM-derived output.

## Certified round trips

Pac-Man certification:

- SjASMPlus 1.24.0: **0 errors / 0 warnings**
- 16 KiB program SHA-256: `e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77`
- physical board reconstruction: **10/10 files exact**

Puckman certification:

- SjASMPlus 1.24.0: **0 errors / 0 warnings**
- 16 KiB program SHA-256: `de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef`
- physical board reconstruction: **16/16 files exact**

Shared semantic coverage:

- **381/381** semantic families
- **5,414/5,414** Z80 instructions
- **257/257** non-code semantic spans

Exact ROM round-trip certification uses lawfully supplied external reference sets and is intentionally not performed in public CI.

## Release verification

Run the ROM-free local release gate:

```bash
make release-check
```

Public GitHub Actions additionally validate:

- Linux native release build
- Windows MinGW build and standalone package
- macOS universal Intel/Apple Silicon build and standalone package
- Docker source build and runtime tests
- native Docker AMD64 runtime
- native Docker ARM64 runtime
- public multi-architecture GHCR manifest

For release certification with external references:

```bash
python3 scripts/test_certified_variants.py /path/to/pacman.7z /path/to/puckman.zip /path/to/sjasmplus
python3 scripts/strict_rom_free_audit.py . /path/to/pacman.7z /path/to/puckman.zip
```

## Documentation

- [Building and packaging](BUILDING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Archive and output safety](docs/ARCHIVE_AND_OUTPUT_SAFETY.md)
- [Release certification](docs/PACRIPPER_RELEASE_CERTIFICATION.md)
- [Release status](docs/V1_0_RELEASE_STATUS.md)
- [ROM-free release audit](docs/ROM_FREE_RELEASE_AUDIT.md)
- [Legal and generated-output policy](docs/LEGAL_AND_OUTPUT_POLICY.md)
- [Contributing](CONTRIBUTING.md)
- [Security](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License and legal boundary

PacRipper's original software and project documentation are released under the **MIT License**. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.

The MIT License does not grant rights to user-supplied ROM/PROM data or ROM-derived generated output. Users are responsible for ensuring their possession and use of ROM data is lawful in their jurisdiction.

PacRipper is an independent research/reconstruction utility and is not affiliated with, sponsored by, authorized by, or endorsed by Bandai Namco Entertainment or other rights holders. Pac-Man/Puckman names and related trademarks belong to their respective owners.

**Do not upload ROM/PROM files, reconstructed ROMs, ROM byte dumps, or generated complete disassembly trees to public issues or pull requests.**
