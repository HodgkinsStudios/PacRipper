#!/usr/bin/env python3
"""PacRipper public disassembly pipeline.
Created by Jacob Hodgkins.

The input ROM archive is extracted only into a temporary working directory. No raw
canonical ROM/PROM payload is copied into the PacRipper distribution.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from archive_support import safe_extract_archive
from variant_support import detect_directory, prepare_core_directory

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent.resolve()


def run(cmd: list[str]) -> None:
    shown = " ".join(str(x) for x in cmd)
    proc = subprocess.run(cmd, cwd=ROOT)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {shown}")


def _contains(parent: Path, child: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolved_anchor(path: Path) -> Path:
    anchor = path.anchor
    return Path(anchor).resolve() if anchor else path


def validate_output_destination(output: Path, archive: Path, force: bool) -> Path:
    """Fail closed on accidental destructive destinations.

    Existing output is never replaced unless --force is supplied. Even with --force,
    PacRipper refuses filesystem roots, the user's home directory, the PacRipper
    application tree (and its ancestors), the current working directory (and its
    ancestors), an output containing the input archive, and symbolic-link outputs.
    """
    expanded = output.expanduser()
    if expanded.exists() and expanded.is_symlink():
        raise ValueError("refusing symbolic-link output destination")
    resolved = expanded.resolve(strict=False)
    archive = archive.resolve(strict=True)
    home = Path.home().resolve()
    cwd = Path.cwd().resolve()
    anchor = _resolved_anchor(resolved)

    if resolved == anchor:
        raise ValueError(f"refusing filesystem-root output destination: {resolved}")
    if resolved == home:
        raise ValueError(f"refusing user-home output destination: {resolved}")
    if resolved == ROOT:
        raise ValueError(f"refusing PacRipper application directory as output: {resolved}")
    if resolved == cwd:
        raise ValueError(f"refusing current working directory as output: {resolved}")

    # A forced recursive replacement of an ancestor would delete the protected tree.
    for protected, label in ((ROOT, "PacRipper application"), (cwd, "current working"), (home, "user home")):
        if _contains(resolved, protected):
            raise ValueError(f"refusing output that is an ancestor of the {label} directory: {resolved}")

    if _contains(resolved, archive):
        raise ValueError("refusing output destination that contains the input ROM archive")

    if resolved.exists() and not force:
        raise ValueError(
            f"output already exists: {resolved}. Refusing to replace it without --force"
        )
    return resolved


def replace_output(source: Path, output: Path, force: bool) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not force:
        raise ValueError(f"output already exists: {output}. Use --force to replace it")
    if output.exists() and output.is_symlink():
        raise ValueError("refusing symbolic-link output destination")

    # Stage on the destination filesystem, then rename into place. The randomly named
    # staging path avoids deleting a user's coincidentally named *.tmp file.
    staged = Path(tempfile.mkdtemp(prefix=f".{output.name}.PacRipper-stage-", dir=output.parent))
    try:
        staged.rmdir()
        shutil.copytree(source, staged)
        if output.exists():
            if output.is_dir():
                shutil.rmtree(output)
            else:
                output.unlink()
        staged.rename(output)
    except Exception:
        if staged.exists():
            if staged.is_dir():
                shutil.rmtree(staged, ignore_errors=True)
            else:
                staged.unlink(missing_ok=True)
        raise


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="PacRipper",
        description="Generate a complete deterministic Pac-Man or Puckman board disassembly from a supported ROM archive.",
    )
    ap.add_argument("--force", action="store_true", help="deliberately replace an existing safe output path")
    ap.add_argument("input_archive", type=Path, help="canonical pacman.7z/Pac-Man or puckman.zip/Puckman archive")
    ap.add_argument("output_folder", type=Path, help="destination for the complete clean disassembly")
    args = ap.parse_args()

    archive = args.input_archive.expanduser().resolve()
    if not archive.is_file():
        raise ValueError(f"input archive does not exist or is not a file: {archive}")
    output = validate_output_destination(args.output_folder, archive, args.force)
    core = ROOT / "bin" / ("PacRipperCore.exe" if os.name == "nt" else "PacRipperCore")
    if not core.is_file():
        raise RuntimeError(f"PacRipperCore is not built: {core}")

    with tempfile.TemporaryDirectory(prefix="PacRipper-") as temp_name:
        work = Path(temp_name)
        rom_dir = work / "rom"
        board = work / "complete_board"
        semantic = work / "human_semantic"
        public = work / "public"

        print(f"PacRipper: reading {archive}")
        safe_extract_archive(archive, rom_dir)
        profile, files = detect_directory(rom_dir)
        core_dir = prepare_core_directory(rom_dir, work / "core_rom", profile, files)
        print(f"PacRipper: detected canonical variant: {profile.title}")

        if profile.key == "pacman":
            run([sys.executable, str(ROOT / "scripts" / "complete_board_recovery.py"), str(core_dir), str(board)])
        else:
            run([sys.executable, str(ROOT / "scripts" / "complete_puckman_board_recovery.py"), str(core_dir), str(rom_dir), str(board)])
        run([sys.executable, str(ROOT / "scripts" / "pacman_human_semantics.py"), str(ROOT), str(board), str(semantic)])
        run([sys.executable, str(ROOT / "scripts" / "prepare_public_output.py"), str(semantic), str(public)])
        run([sys.executable, str(ROOT / "scripts" / "verify_human_semantic_release.py"), str(public), "--require-complete"])
        verifier = ROOT / "scripts" / ("verify_complete_board_export.py" if profile.key == "pacman" else "verify_variant_board_export.py")
        run([sys.executable, str(verifier), str(public), str(rom_dir)])

        for cache in list(public.rglob("__pycache__")):
            shutil.rmtree(cache, ignore_errors=True)
        replace_output(public, output, args.force)

    print("PacRipper: PASS")
    print(f"Variant: {profile.title}")
    print(f"Complete disassembly: {output}")
    print(f"Independent round-trip source verification: PASS ({len(profile.expected)}/{len(profile.expected)} board files, 25,376/25,376 bytes)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"PacRipper error: {exc}", file=sys.stderr)
        raise SystemExit(1)
