# Publishing PacRipper V1.0 on GitHub

PacRipper V1.0 is prepared as a ROM-free source repository. Do not commit or upload Pac-Man/Puckman ROM/PROM files, reconstructed ROMs, generated complete disassembly trees, or ROM byte dumps.

## Suggested repository metadata

- Repository name: `PacRipper`
- Description: `ROM-free Pac-Man/Puck Man research and reconstruction tool producing human-readable, byte-exact rebuildable source.`
- Initial release tag: `v1.0.0`
- Release title: `PacRipper V1.0`

## First push

From the extracted `PacRipper_V1.0` directory:

```bash
git init
git add .
git commit -m "PacRipper V1.0 public release"
git branch -M main
git remote add origin <your-github-repository-url>
git push -u origin main
```

Then create and push the release tag:

```bash
git tag -a v1.0.0 -m "PacRipper V1.0"
git push origin v1.0.0
```

Create a GitHub Release for `v1.0.0`. The Git repository itself already contains the certified Linux binaries. You may also attach the public-release ZIP as a convenience source/release package.

## CI scope

`.github/workflows/release-check.yml` intentionally performs only ROM-free checks. It does not download, contain, or reconstruct copyrighted ROM inputs. Exact Pac-Man/Puckman round-trip certification remains an offline maintainer release gate using lawfully supplied external references.

## Before every release

Run:

```bash
make release-check
```

For changes affecting supported profiles or reconstruction, also run the certified variant round trips and strict dual-reference ROM-free audit documented in `RELEASE_MANIFEST.txt` and `CONTRIBUTING.md`.
