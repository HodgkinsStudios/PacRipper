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

The public GitHub Actions macOS job builds both universal binaries and runs `scripts/test_macos_runtime.py`. The test suite verifies both architecture slices, launcher package discovery from an unrelated working directory, explicit `PACRIPPER_PYTHON` selection, Unicode paths, synthetic ZIP extraction, and synthetic 7z extraction. The same suite is rerun against the staged package before the tarball is published as the `PacRipper-macOS-Universal` artifact. Copyrighted Pac-Man/Puckman ROM inputs are not uploaded to public CI.

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

## Docker / OCI

The Docker image is intended to provide a consistent PacRipper runtime on Linux distributions that are not built natively by this repository. A host only needs Docker Engine, Docker Desktop, or a compatible Podman installation.

Build locally:

```bash
docker build -t pacripper:local .
```

Verify the image:

```bash
docker run --rm pacripper:local --version
PACRIPPER_DOCKER_IMAGE=pacripper:local python3 scripts/test_docker_runtime.py
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

The CI Docker runtime suite validates the version entrypoint, package completeness, non-root bind mounts, non-ASCII paths, synthetic ZIP input, and synthetic 7z input. On pushes to `main`, CI builds and tests `linux/amd64` on a native x86-64 runner and `linux/arm64` on GitHub's native ARM64 Linux runner. Each architecture is published separately with provenance/SBOM metadata, then a final manifest job combines them into the public multi-architecture tags. This avoids slow QEMU compilation for the large C++ core and validates both architectures natively before publication:

```text
ghcr.io/hodgkinsstudios/pacripper:latest
ghcr.io/hodgkinsstudios/pacripper:1.0
ghcr.io/hodgkinsstudios/pacripper:1.0.0
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
