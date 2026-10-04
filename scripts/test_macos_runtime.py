#!/usr/bin/env python3
"""macOS runtime smoke tests for PacRipper.
Created by Jacob Hodgkins.

These tests are ROM-free. They verify the native macOS launcher, executable-relative
package discovery, universal-architecture binaries, Python selection, Unicode paths,
ZIP extraction, and 7z extraction using synthetic data.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from archive_support import _find_7z_executable, safe_extract_archive

ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "bin" / "PacRipper"
CORE = ROOT / "bin" / "PacRipperCore"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run_checked(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout}"
        )
    return proc


def expect_canonical_rejection(
    archive: Path,
    output: Path,
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> None:
    proc = subprocess.run(
        [str(EXE), str(archive), str(output)],
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        errors="replace",
    )
    require(proc.returncode != 0, "synthetic archive unexpectedly succeeded")
    require(
        "unsupported canonical ROM set" in proc.stdout,
        "launcher did not reach canonical ROM validation:\n" + proc.stdout,
    )
    require(not output.exists(), "failed synthetic run created an output tree")


def require_universal_binary(path: Path) -> None:
    lipo = shutil.which("lipo")
    require(lipo is not None, "lipo is required for macOS architecture validation")
    result = run_checked([lipo, "-archs", str(path)], cwd=ROOT)
    arches = set(result.stdout.split())
    require(
        {"x86_64", "arm64"}.issubset(arches),
        f"{path.name} is not a universal x86_64+arm64 binary: {result.stdout.strip()}",
    )


def main() -> int:
    if sys.platform != "darwin":
        print("macOS runtime smoke test: SKIP (not macOS)")
        return 0

    require(EXE.is_file(), f"PacRipper macOS executable is missing: {EXE}")
    require(CORE.is_file(), f"PacRipperCore macOS executable is missing: {CORE}")
    require(os.access(EXE, os.X_OK), f"PacRipper is not executable: {EXE}")
    require(os.access(CORE, os.X_OK), f"PacRipperCore is not executable: {CORE}")

    version = run_checked([str(EXE), "--version"], cwd=ROOT)
    require(version.stdout.strip() == "PacRipper 1.0.0", "unexpected --version output")

    if os.environ.get("PACRIPPER_EXPECT_UNIVERSAL") == "1":
        require_universal_binary(EXE)
        require_universal_binary(CORE)

    seven = _find_7z_executable()
    require(seven is not None, "7-Zip/7zz was not found; macOS .7z runtime coverage is required")

    with tempfile.TemporaryDirectory(prefix="PacRipper-macOS-") as tmp_name:
        temp = Path(tmp_name)
        unicode_dir = temp / "unicode-é-漢字"
        unicode_dir.mkdir()
        payload = unicode_dir / "synthetic payload.txt"
        payload.write_bytes(b"PacRipper synthetic macOS archive test\n")

        zip_path = unicode_dir / "synthetic input.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(payload, arcname=payload.name)

        zip_extract = unicode_dir / "zip extracted"
        safe_extract_archive(zip_path, zip_extract)
        require(
            (zip_extract / payload.name).read_bytes() == payload.read_bytes(),
            "ZIP extraction did not preserve synthetic payload",
        )

        seven_path = unicode_dir / "synthetic input.7z"
        proc = subprocess.run(
            [seven, "a", "-t7z", str(seven_path), payload.name],
            cwd=unicode_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            errors="replace",
        )
        require(proc.returncode == 0, "unable to create synthetic 7z fixture:\n" + proc.stdout)

        seven_extract = unicode_dir / "7z extracted"
        safe_extract_archive(seven_path, seven_extract)
        require(
            (seven_extract / payload.name).read_bytes() == payload.read_bytes(),
            "7z extraction did not preserve synthetic payload",
        )

        unrelated_cwd = temp / "unrelated cwd"
        unrelated_cwd.mkdir()

        # The executable must locate ../scripts from its actual macOS executable path,
        # not from argv[0] or the process current working directory.
        expect_canonical_rejection(
            zip_path,
            unicode_dir / "output from zip",
            cwd=unrelated_cwd,
        )
        expect_canonical_rejection(
            seven_path,
            unicode_dir / "output from 7z",
            cwd=unrelated_cwd,
        )

        explicit_env = os.environ.copy()
        explicit_env["PACRIPPER_PYTHON"] = sys.executable
        expect_canonical_rejection(
            zip_path,
            unicode_dir / "output explicit python",
            cwd=unrelated_cwd,
            env=explicit_env,
        )

    print("PacRipper macOS runtime smoke test: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as exc:
        print(f"PacRipper macOS runtime smoke test: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
