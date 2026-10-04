# PacRipper V1.0

**Created by Jacob Hodgkins**

PacRipper is a ROM-free command-line research/reconstruction tool that produces complete human-readable source/disassembly packages from two certified Pac-Man-family arcade board sets: canonical **Pac-Man** and canonical **Puckman**.

PacRipper stands for **Pac**kage **R**om **I**nteractive **P**arser & **P**rogrammable **E**ngineering **R**econstructor.

## Supported inputs

V1.0 intentionally supports exactly two canonical identities:

- **Pac-Man** — self-contained 10-file board set; canonical/reference container `pacman.7z`. An equivalent ZIP or 7z containing the same ten physical files is accepted.
- **Puckman** — canonical self-contained 16-file board set; certified/reference container `puckman.zip`.

Other revisions, hacks, split parent/clone combinations, and mixed sets are deliberately rejected. PacRipper authenticates every required physical chip by **filename + exact size + CRC32 + SHA-256**; archive filenames alone are not trusted.

## Usage

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

PacRipper refuses to replace an existing output destination by default. To deliberately replace a safe existing destination:

```bash
./bin/PacRipper --force ~/roms/pacman.7z ~/PacMan_Disassembly
```

`--force` does **not** disable destructive-path protections. Filesystem roots, the user's home directory itself, PacRipper's application tree/ancestors, the current working directory/ancestors, symlink destinations, and destinations that would contain/delete the input archive are always refused.

Check the installed version with:

```bash
./bin/PacRipper --version
```

## Independent source outputs

Pac-Man produces:

```text
program/pacman.asm
```

and independently reconstructs the original **10/10 physical files, 25,376/25,376 bytes exact**.

Puckman produces:

```text
program/puckman.asm
```

and independently reconstructs the original **16/16 physical files, 25,376/25,376 bytes exact**. The Puckman output does not require `pacman.asm`, a Pac-Man output tree, or the Pac-Man ROM set.

Both generated trees include structured graphics/PROM sources, manifests, semantic documentation, verification tools, rebuild helpers, and a generated `LEGAL_NOTICE.md` explaining the copyright/license boundary for ROM-derived output.

## Certified external SjASMPlus round trips

Pac-Man:

- `program/pacman.asm`: SjASMPlus 1.24.0, **0 errors / 0 warnings**;
- 16-KiB program SHA-256: `e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77`;
- full physical board reconstruction: **10/10 files exact**.

Puckman:

- `program/puckman.asm`: SjASMPlus 1.24.0, **0 errors / 0 warnings**;
- 16-KiB program SHA-256: `de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef`;
- full physical board reconstruction: **16/16 files exact**.

Both outputs retain the completed semantic coverage baseline: **381/381 semantic families, 5,414/5,414 instructions, and 257/257 non-code semantic spans**.

## Archive safety

User archives are treated as untrusted input. V1.0 rejects unsafe paths, case-insensitive duplicate paths, non-regular 7z members, excessive member counts, oversized members, excessive total decompressed size, and unsafe ZIP compression ratios. Current conservative limits are documented in `docs/ARCHIVE_AND_OUTPUT_SAFETY.md` and tested by `scripts/test_archive_safety.py`.

## Requirements

Runtime:

- Python 3;
- the PacRipper package kept intact (`bin`, `scripts`, `semantic`, and supporting metadata);
- one supported user-supplied ROM set.

ZIP input uses Python's standard library. On Windows, 7z input prefers an installed 7-Zip executable and automatically checks PATH plus the normal `Program Files\7-Zip` locations; libarchive remains a fallback. Linux/macOS retain libarchive-first behavior. PacRipper does not bundle Python, 7-Zip, or libarchive.

The Windows launcher supports the standard Python `py -3` launcher, `python`, `python3`, or an explicit `PACRIPPER_PYTHON` path. Windows input/output paths are read from the Unicode command line, so non-ASCII paths are supported.

Ubuntu/Linux build:

```bash
./build_ubuntu.sh
```

Strict public-release build gate:

```bash
make release-check
```

Native Windows/MinGW support is included and continuously built on GitHub Actions. Build with `build_windows_mingw.bat` or choose the `Windows Release` targets in the Code::Blocks workspace. Run `package_windows.bat` after building to stage a self-contained `dist\PacRipper-Windows` package containing the executables plus the runtime scripts, semantic data, configuration, documentation, and notices. The Windows CI gate builds both executables, runs synthetic ZIP/7z archive tests, verifies launcher behavior from an unrelated working directory, exercises non-ASCII Windows paths, and reruns the runtime suite from the staged standalone package before publishing it as an artifact. Exact Pac-Man/Puckman round-trip certification still requires lawfully supplied external ROM references and therefore is not performed in public CI. See `BUILDING.md`.

## ROM-free distribution

PacRipper itself contains no Pac-Man/Puckman ROM or PROM payloads and no pre-generated disassembly tree. The input archive is processed in a temporary working directory and is not copied into the PacRipper release or generated source tree.

Repeat the strict dual-reference audit with user-owned reference sets:

```bash
python3 scripts/strict_rom_free_audit.py . /path/to/pacman.7z /path/to/puckman.zip
```

## License and legal boundary

PacRipper's original software and project documentation are released under the **MIT License**. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.

The MIT License does not grant rights to user-supplied ROM/PROM data or ROM-derived generated output. See `docs/LEGAL_AND_OUTPUT_POLICY.md`. Users are responsible for ensuring their possession and use of ROM data is lawful in their jurisdiction.

PacRipper is an independent research/reconstruction utility and is not affiliated with, sponsored by, authorized by, or endorsed by Bandai Namco Entertainment or other rights holders. Pac-Man/Puckman names and related trademarks belong to their respective owners.

## Release verification

See:

- `docs/PACRIPPER_RELEASE_CERTIFICATION.md`
- `docs/ROM_FREE_RELEASE_AUDIT.md`
- `docs/ARCHIVE_AND_OUTPUT_SAFETY.md`
- `docs/RELEASE_CHECKLIST.md`
- `CHANGELOG.md`
- `CITATION.cff`

## GitHub repository checks

The repository includes a ROM-free GitHub Actions workflow at `.github/workflows/release-check.yml`. Linux runs the strict C++ release build, Python syntax checks, public terminology audit, synthetic archive/output safety tests, and repository artifact guard. Windows separately builds the native MinGW executables and runs the Windows runtime smoke suite, including synthetic ZIP/7z and Unicode-path coverage. Neither job uses or downloads copyrighted ROM data.

The exact Pac-Man and Puckman reconstruction certifications cannot run in public CI because PacRipper intentionally does not distribute the required ROM/PROM inputs. Maintainers perform those release-only checks locally with lawfully supplied external references using `scripts/test_certified_variants.py`, followed by `scripts/strict_rom_free_audit.py` against both supported reference sets.

Please do not upload ROM/PROM files, reconstructed ROMs, ROM byte dumps, or generated complete disassembly trees in issues or pull requests.
