# Building PacRipper 1.0

**Created by Jacob Hodgkins**

PacRipper 1.0 contains two C++17 executables:

- `PacRipper` — public CLI/orchestration entry point.
- `PacRipperCore` — private program/resource analysis helper invoked by PacRipper.

The same binaries support both certified inputs (`pacman.7z` and `puckman.zip`). The canonical release version is stored in the top-level `VERSION` file.

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

This performs a clean strict build, Python syntax compilation, and a CLI version smoke check. Full runtime and ROM-based regression tests are not bundled with the public source tree.

For a dual-reference ROM-free release audit, run:

```bash
python3 scripts/strict_rom_free_audit.py . /path/to/pacman.7z /path/to/puckman.zip
```

Independent round-trip certification additionally requires locally running PacRipper against both lawfully held ROM sets, assembling the generated Z80 sources with SjASMPlus, and comparing the rebuilt physical files.

## Code::Blocks

Open `PacRipper.workspace`. On Linux, build the normal `Release` targets. On Windows, select the `Windows Release` target for both projects. On macOS, select `macOS Universal Release` for both projects. `PacRipper` depends on `PacRipperCore`, so both executables are produced. The Windows targets use C++17, MinGW-w64, static libgcc/libstdc++ runtime linkage, and `-lstdc++fs` for compatibility with older MinGW toolchains. The macOS targets use Apple Clang/libc++, a macOS 11 deployment target, and produce universal `x86_64` + `arm64` Mach-O binaries.

## macOS / Apple Clang

Requirements:

- macOS 11 or newer;
- Xcode Command Line Tools / Apple Clang with C++17 support;
- Python 3;
- 7-Zip/`7zz` only if the system libarchive cannot read a supplied `.7z` archive.

Build the universal Intel + Apple Silicon binaries with:

```bash
chmod +x build_macos.sh package_macos.sh
./build_macos.sh
```

This produces:

```text
bin/PacRipper
bin/PacRipperCore
```

By default each executable contains both `x86_64` and `arm64` slices and targets macOS 11+. The build is strict (`-Wall -Wextra -Wpedantic -Werror`) and uses the platform C++ runtime (`libc++`), so no GNU `libstdc++fs` compatibility library is linked. `MACOSX_DEPLOYMENT_TARGET` may be set to a newer minimum version. `PACRIPPER_MAC_ARCHS` may be overridden for developer-only single-architecture builds, but the public CI package is always validated as universal.

The macOS launcher asks dyld for the actual executable path rather than trusting `argv[0]`. That lets a staged package locate `scripts/pacripper_pipeline.py` correctly when launched from another working directory, through a symlink/PATH entry, or from a path containing non-ASCII characters.

To stage the complete runtime and create the distributable archive:

```bash
./package_macos.sh
```

The default staged folder is `dist/PacRipper-macOS`; the default archive is `dist/PacRipper-macOS-universal.tar.gz`. The tarball is used so executable permission bits survive artifact/download handling.

The public GitHub Actions macOS job builds both universal binaries, checks their architecture slices and CLI version, and verifies the staged package starts before publishing the `PacRipper-macOS-Universal` artifact. Copyrighted Pac-Man/Puckman ROM inputs are not uploaded to public CI.

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

The public GitHub Actions Windows job builds both executables, checks the CLI version, and checks that the staged `dist\PacRipper-Windows` package starts before publishing the `PacRipper-Windows-MinGW` artifact. Full extraction and ROM-based certification remain offline maintainer responsibilities; copyrighted references are absent from public CI.

## Docker / OCI

The Docker image is intended to provide a consistent PacRipper runtime on Linux distributions that are not built natively by this repository. A host only needs Docker Engine, Docker Desktop, or a compatible Podman installation.

Build locally:

```bash
docker build -t pacripper:local .
```

Verify the image:

```bash
docker run --rm pacripper:local --version
docker run --rm pacripper:local --version
```

The image uses a multi-stage Debian build. The build stage compiles both C++17 executables from source with the same strict warning policy used by the release build. The runtime stage contains only the PacRipper runtime tree plus Python 3, libarchive, 7-Zip, and the required GNU C++ runtime libraries. Repository `bin/` files are excluded from the Docker build context and are rebuilt inside the image.

Normal usage with a host directory mounted at `/work`:

```bash
mkdir -p PacMan_Disassembly
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" \
  ghcr.io/hodgkinsstudios/pacripper:latest \
  /work/pacman.7z /work/PacMan_Disassembly
```

Using `--user` keeps generated files owned by the invoking Linux user instead of root. On SELinux-enforcing hosts, use `-v "$PWD:/work:Z"`. Podman users can use the same arguments with `podman run`.

CI checks the Docker image's version entrypoint. On pushes to `main`, CI builds `linux/amd64` on a native x86-64 runner and `linux/arm64` on GitHub's native ARM64 Linux runner. Each architecture is published separately with provenance/SBOM metadata, then a final manifest job combines them into the public multi-architecture tags. Full archive and runtime regression suites are not included in public CI:

```text
ghcr.io/hodgkinsstudios/pacripper:latest
ghcr.io/hodgkinsstudios/pacripper:1.0
```

The Docker build context explicitly excludes ROM archives, generated assembly, local outputs, native prebuilt binaries, and build caches.

## Runtime layout

Keep these directories together:

```text
PacRipper/
  bin/
  scripts/
  semantic/
```

The front end locates `scripts/pacripper_pipeline.py` relative to the executable/project directory and fails explicitly if the package is incomplete. On macOS, the true Mach-O path is obtained from dyld so package discovery does not depend on the current working directory or the textual value of `argv[0]`.
