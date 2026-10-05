# Publishing PacRipper 1.0 on GitHub

**Created by Jacob Hodgkins**

PacRipper 1.0 is a ROM-free public source repository. Do not commit or upload Pac-Man/Puckman ROM/PROM files, reconstructed ROMs, generated complete disassembly trees, or ROM byte dumps.

## Release identity

- Version: `1.0`
- Git tag: `v1.0`
- Release title: `PacRipper 1.0`
- Docker image: `ghcr.io/hodgkinsstudios/pacripper:1.0`

The top-level `VERSION` file, CLI `--version` output, citation metadata, Docker image label, release documentation, and versioned container tag must all remain synchronized at `1.0`.

## Before publishing

Run the ROM-free local release gates:

```bash
make release-check
```

For changes affecting supported profiles, reconstruction, or generated output, also run:

```bash
python3 scripts/test_certified_variants.py /path/to/pacman.7z /path/to/puckman.zip /path/to/sjasmplus
python3 scripts/strict_rom_free_audit.py . /path/to/pacman.7z /path/to/puckman.zip
```

Public CI must be green for:

- Linux native release checks
- Windows MinGW build/runtime/package checks
- macOS universal build/runtime/package checks
- Docker source/runtime checks
- native linux/amd64 container runtime
- native linux/arm64 container runtime
- GHCR multi-architecture manifest publication

## Tagging the release

From a clean, fully verified `main` branch:

```bash
git checkout main
git pull --ff-only
git tag -a v1.0 -m "PacRipper 1.0"
git push origin v1.0
```

Create a GitHub Release for `v1.0` titled **PacRipper 1.0**.

Native Windows and macOS packages are produced by GitHub Actions. Linux binaries are built from source rather than committed to the repository. The public Docker/OCI image is published to GHCR for both linux/amd64 and linux/arm64.

## ROM-free policy

Public GitHub Actions do not download or contain copyrighted ROM/PROM reference sets. Exact Pac-Man/Puckman round-trip certification remains an offline maintainer release gate using lawfully supplied external references.

Do not attach copyrighted ROM/PROM data or generated complete disassembly trees to public releases, issues, or pull requests.
