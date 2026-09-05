# Building PacRipper V1.0

**Created by Jacob Hodgkins**

PacRipper contains two C++17 executables:

- `PacRipper` — public CLI/orchestration entry point.
- `PacRipperCore` — private program/resource analysis helper invoked by PacRipper.

The same binaries support both certified inputs (`pacman.7z` and `puckman.zip`).

## Ubuntu / GCC

Normal optimized build:

```bash
./build_ubuntu.sh
```

or:

```bash
make -j$(nproc)
```

Executables are written to `bin/`.

## Strict release build

The public release gate compiles every C++ translation unit with:

```text
-std=c++17 -O2 -DNDEBUG -Wall -Wextra -Wpedantic -Werror
```

Run:

```bash
make release-check
```

This performs a clean strict build, Python syntax compilation, public terminology verification, and synthetic archive/output safety tests.

For the complete dual-ROM certification, additionally run:

```bash
python3 scripts/test_certified_variants.py /path/to/pacman.7z /path/to/puckman.zip /path/to/sjasmplus
python3 scripts/strict_rom_free_audit.py . /path/to/pacman.7z /path/to/puckman.zip
```

## Code::Blocks

Open `PacRipper.workspace` and build the workspace. `PacRipper` depends on `PacRipperCore`, so both targets are produced. The projects use C++17 and `-lstdc++fs` for compatibility with older GCC/MinGW toolchains.

## Windows / MinGW

```bat
build_windows_mingw.bat
```

This is intended to produce `bin\PacRipper.exe` and `bin\PacRipperCore.exe`. Python 3 must be available as `python`/`python3` or through `PACRIPPER_PYTHON`. For `.7z` input, PacRipper uses host libarchive when available or an installed 7-Zip command as a fallback.

The V1.0 package's supplied prebuilt binaries and release certification are Linux builds. Build and execute the same certification suite on Windows before labeling separately distributed Windows binaries as certified.

## Runtime layout

Keep these directories together:

```text
PacRipper/
  bin/
  scripts/
  semantic/
```

The front end locates `scripts/pacripper_pipeline.py` relative to the executable/project directory and fails explicitly if the package is incomplete.
