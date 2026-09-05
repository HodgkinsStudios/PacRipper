#!/usr/bin/env python3
# Created by Jacob Hodgkins
"""Run PacRipper V1.0's two independent certified source round trips.

Usage:
  python3 scripts/test_certified_variants.py <pacman.7z> <puckman.zip> <sjasmplus>
"""
from __future__ import annotations
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED = {
    "pacman": {
        "input_index": 1,
        "asm": "program/pacman.asm",
        "sha": "e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77",
        "files": 10,
    },
    "puckman": {
        "input_index": 2,
        "asm": "program/puckman.asm",
        "sha": "de87b3024a309377f5cf438455ed7f37a7aa8b5db5da5189f9b8240f90057cef",
        "files": 16,
    },
}

def run(cmd, cwd=None):
    print("+", " ".join(map(str, cmd)), flush=True)
    subprocess.run([str(x) for x in cmd], cwd=cwd, check=True)

def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__.strip())
        return 2
    root = Path(__file__).resolve().parent.parent
    exe = root / "bin" / ("PacRipper.exe" if sys.platform.startswith("win") else "PacRipper")
    sjasm = Path(sys.argv[3]).resolve()
    if not exe.is_file() or not sjasm.is_file():
        raise SystemExit("PacRipper or SjASMPlus executable not found")

    with tempfile.TemporaryDirectory(prefix="PacRipper-V1.0-cert-") as td:
        temp = Path(td)
        for variant, spec in EXPECTED.items():
            canonical = Path(sys.argv[spec["input_index"]]).resolve()
            out = temp / f"{variant}_source"
            program = temp / f"{variant}_program.bin"
            romset = temp / f"{variant}_romset"
            run([exe, canonical, out], cwd=root)
            asm = out / spec["asm"]
            if not asm.is_file():
                raise SystemExit(f"{variant}: missing independent source {spec['asm']}")
            other = out / ("program/puckman.asm" if variant == "pacman" else "program/pacman.asm")
            if other.exists():
                raise SystemExit(f"{variant}: cross-variant assembly source unexpectedly present: {other}")
            run([sjasm, f"--raw={program}", asm], cwd=out)
            digest = hashlib.sha256(program.read_bytes()).hexdigest()
            if digest != spec["sha"]:
                raise SystemExit(f"{variant}: program SHA mismatch: {digest}")
            run([sys.executable, out / "verification/build_complete_rom_set.py", out, program, romset, "--canonical", canonical], cwd=out)
            physical = [p for p in romset.iterdir() if p.is_file()]
            if len(physical) != spec["files"]:
                raise SystemExit(f"{variant}: physical file count mismatch: {len(physical)}")
            print(f"{variant}: INDEPENDENT ROUND TRIP PASS ({spec['files']}/{spec['files']} files)")
    print("PacRipper V1.0 certified dual-variant round trip: PASS")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
