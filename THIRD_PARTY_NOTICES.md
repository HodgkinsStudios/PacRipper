# Third-Party and Provenance Notices

**PacRipper 1.0 — Created by Jacob Hodgkins**

## PacRipper source

PacRipper and its project documentation are original work by Jacob Hodgkins and are released under the MIT License in `LICENSE`.

The files under `src/reference/pacemu/` were adapted from `PacmanArcadeEmulator_InputConfigGamepadPass`, an earlier parent project also created and owned entirely by Jacob Hodgkins. They are therefore included under the same PacRipper MIT License; they are not third-party code.

## External tools and libraries

PacRipper does not bundle the following optional/external software:

- Python 3 — used by the orchestration and verification scripts.
- libarchive — optionally loaded from the host system for `.7z` input.
- 7-Zip (`7z`, `7zz`, or `7zr`) — optional fallback for `.7z` input when host libarchive support is unavailable.
- SjASMPlus — used for independent release certification of the generated Z80 source; it is not bundled with PacRipper.
- Code::Blocks, GCC/G++, and MinGW — optional build tools and not part of the PacRipper distribution.

Each external project remains subject to its own license and terms.

## ROMs and generated output

PacRipper contains no Pac-Man or Puckman ROM/PROM payloads. User-supplied ROMs and ROM-derived generated output are not relicensed by the PacRipper MIT License. See `docs/LEGAL_AND_OUTPUT_POLICY.md`.
