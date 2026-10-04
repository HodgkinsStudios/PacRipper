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

Open `PacRipper.workspace`. On Linux, build the normal `Release` targets. On Windows, select the `Windows Release` target for both projects; `PacRipper` depends on `PacRipperCore`, so both executables are produced. The Windows targets use C++17, MinGW-w64, static libgcc/libstdc++ runtime linkage, and `-lstdc++fs` for compatibility with older MinGW toolchains.

## Windows / MinGW

Requirements:

- Windows 10/11;
- MinGW-w64 / GCC with C++17 support (the Code::Blocks MinGW toolchain is supported);
- Python 3;
- 7-Zip for direct `.7z` input unless a compatible libarchive DLL is installed.

From a normal Command Prompt or a Code::Blocks MinGW terminal:

```bat
build_windows_mingw.bat
```

This produces:

```text
bin\PacRipper.exe
bin\PacRipperCore.exe
```

The batch build is strict (`-Wall -Wextra -Wpedantic -Werror`) and links the MinGW libgcc/libstdc++ runtimes statically so a normal user does not need MinGW runtime DLLs beside PacRipper. If `g++` is not on PATH, set `MINGW_CXX` to the full `g++.exe` path before running the script.

The Windows launcher accepts Python through `py -3`, `python`, `python3`, or `PACRIPPER_PYTHON`. It resolves PacRipper's package root from the executable location rather than the current working directory and preserves Unicode input/output paths.

For `.7z` input on Windows, PacRipper prefers the native 7-Zip executable found on PATH or under the standard Program Files installation directories. ZIP input remains dependency-free.

To stage a portable Windows folder after a successful build:

```bat
package_windows.bat
```

The default output is `dist\PacRipper-Windows`. You can also pass a custom destination as the first argument. Keep the staged folder intact when distributing or running PacRipper; the frontend locates its Python pipeline relative to the package.

The public GitHub Actions Windows job builds both executables and runs `scripts/test_windows_runtime.py`, which verifies the launcher, synthetic ZIP/7z extraction, explicit Python selection, unrelated working directories, and non-ASCII paths. It then stages `dist\PacRipper-Windows` and runs the same runtime suite from that clean package before publishing the package as the `PacRipper-Windows-MinGW` artifact. The exact Pac-Man/Puckman reconstruction tests remain local release checks because copyrighted ROM references are intentionally absent from public CI.

## Runtime layout

Keep these directories together:

```text
PacRipper/
  bin/
  scripts/
  semantic/
```

The front end locates `scripts/pacripper_pipeline.py` relative to the executable/project directory and fails explicitly if the package is incomplete.
