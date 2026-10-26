#!/usr/bin/env python3
"""Build the complete active Pac-Man 10-file ROM/PROM set from an PacRipper release.

Created by Jacob Hodgkins.

This tool is deliberately NOT a Z80 assembler. Assemble program/pacman.asm with an
independent external assembler such as SjASMPlus, then provide the resulting exact 16-KiB
program image here. The six graphics/color/audio ROM/PROM files are reconstructed from
the release's structured source representations.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import sys
from pathlib import Path

PROGRAM_NAMES = ["pacman.6e", "pacman.6f", "pacman.6h", "pacman.6j"]
PROGRAM_SIZE = 0x4000
BANK_SIZE = 0x1000
EXPECTED_PROGRAM_SHA256 = "e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_verifier(export_root: Path):
    verifier_path = export_root / "verification" / "verify_complete_board_export.py"
    if not verifier_path.is_file():
        # Source-tree mode: this script and the verifier are siblings under scripts/.
        verifier_path = Path(__file__).resolve().with_name("verify_complete_board_export.py")
    spec = importlib.util.spec_from_file_location("pacripper_complete_board_verifier", verifier_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to import verifier: {verifier_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Build Pac-Man's complete 10-file active ROM/PROM set from release source data"
    )
    ap.add_argument("export_root", type=Path, help="root of the PacRipper disassembly release")
    ap.add_argument("program_bin", type=Path, help="16-KiB binary assembled externally from program/pacman.asm")
    ap.add_argument("out_dir", type=Path, help="directory to receive the ten rebuilt ROM/PROM files")
    ap.add_argument("--canonical", type=Path, help="optional canonical Pac-Man ROM folder/7z/ZIP for byte-exact comparison")
    args = ap.parse_args()

    root = args.export_root.resolve()
    program_path = args.program_bin.resolve()
    out = args.out_dir.resolve()
    verifier = load_verifier(root)

    program = program_path.read_bytes()
    if len(program) != PROGRAM_SIZE:
        raise SystemExit(f"FAIL: externally assembled program is {len(program)} bytes; expected {PROGRAM_SIZE}")
    program_hash = sha256(program)
    if program_hash != EXPECTED_PROGRAM_SHA256:
        raise SystemExit(
            "FAIL: externally assembled program SHA-256 does not match the certified Pac-Man image\n"
            f"  actual:   {program_hash}\n"
            f"  expected: {EXPECTED_PROGRAM_SHA256}"
        )

    rebuilt = {}
    for i, name in enumerate(PROGRAM_NAMES):
        rebuilt[name] = program[i * BANK_SIZE:(i + 1) * BANK_SIZE]

    rebuilt["pacman.5e"] = verifier.rebuild_graphics_map(root / "graphics" / "character_map.csv", 256 * 64)
    rebuilt["pacman.5f"] = verifier.rebuild_graphics_map(root / "graphics" / "sprite_map.csv", 64 * 256)
    rebuilt["82s123.7f"] = verifier.rebuild_palette(root / "color" / "palette_source.csv")
    rebuilt["82s126.4a"] = verifier.rebuild_nibble_table(root / "color" / "color_lookup_source.csv", "palette_index")
    rebuilt["82s126.1m"] = verifier.rebuild_nibble_table(root / "audio" / "waveform_source.csv", "sample_nibble")
    rebuilt["82s126.3m"] = verifier.rebuild_nibble_table(root / "audio" / "timing_prom_source.csv", "control_nibble")

    out.mkdir(parents=True, exist_ok=True)
    for name in verifier.ACTIVE_FILES:
        data = rebuilt[name]
        expected_size = verifier.EXPECTED_SIZES[name]
        if len(data) != expected_size:
            raise SystemExit(f"FAIL: {name} rebuilt to {len(data)} bytes; expected {expected_size}")
        (out / name).write_bytes(data)
        print(f"{name}: {len(data)} bytes sha256={sha256(data)}")

    total = sum(len(rebuilt[name]) for name in verifier.ACTIVE_FILES)
    print(f"active_files={len(verifier.ACTIVE_FILES)}/10 total_bytes={total}/25376")
    print(f"external_program_sha256={program_hash} PASS")

    if args.canonical:
        canonical = verifier.load_canonical(args.canonical.resolve())
        failures = []
        for name in verifier.ACTIVE_FILES:
            if rebuilt[name] != canonical[name]:
                failures.append(name)
        if failures:
            print("canonical_round_trip=FAIL mismatches=" + ",".join(failures), file=sys.stderr)
            return 1
        print("canonical_round_trip=PASS 10/10 files 25376/25376 bytes exact")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
