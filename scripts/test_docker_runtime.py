#!/usr/bin/env python3
"""ROM-free Docker/OCI runtime smoke tests for PacRipper.
Created by Jacob Hodgkins.

The suite validates the built image without copyrighted ROM data. It checks the
container entrypoint, non-root bind mounts, Unicode paths, ZIP and 7z handling,
and that synthetic inputs reach PacRipper's canonical-ROM validation layer.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

IMAGE = os.environ.get("PACRIPPER_DOCKER_IMAGE", "pacripper:ci")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        errors="replace",
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stdout}"
        )
    return proc


def docker_prefix(temp: Path) -> list[str]:
    prefix = ["docker", "run", "--rm"]
    if hasattr(os, "getuid") and hasattr(os, "getgid"):
        prefix += ["--user", f"{os.getuid()}:{os.getgid()}"]
    prefix += ["-v", f"{temp}:/work", "-w", "/work", IMAGE]
    return prefix


def expect_canonical_rejection(temp: Path, archive_name: str, output_name: str) -> None:
    proc = run(
        docker_prefix(temp) + [f"/work/{archive_name}", f"/work/{output_name}"],
        check=False,
    )
    require(proc.returncode != 0, "synthetic archive unexpectedly succeeded")
    require(
        "unsupported canonical ROM set" in proc.stdout,
        "container did not reach canonical ROM validation:\n" + proc.stdout,
    )
    require(
        not (temp / output_name).exists(),
        "failed synthetic container run created an output tree",
    )


def main() -> int:
    require(sys.platform.startswith("linux"), "Docker smoke test is intended for Linux CI")
    require(shutil.which("docker") is not None, "docker CLI was not found")

    version = run(["docker", "run", "--rm", IMAGE, "--version"])
    require(version.stdout.strip() == "PacRipper 1.0.0", "unexpected container version output")

    package_check = run(
        [
            "docker", "run", "--rm", "--entrypoint", "/bin/sh", IMAGE, "-c",
            "test -x /opt/pacripper/bin/PacRipper && "
            "test -x /opt/pacripper/bin/PacRipperCore && "
            "test -f /opt/pacripper/scripts/pacripper_pipeline.py && "
            "test -f /opt/pacripper/semantic/family_semantics.json && "
            "python3 --version && "
            "(7z i >/dev/null 2>&1 || 7zz i >/dev/null 2>&1)"
        ]
    )
    require(package_check.returncode == 0, "container runtime package is incomplete")

    with tempfile.TemporaryDirectory(prefix="PacRipper-Docker-") as tmp_name:
        temp = Path(tmp_name)
        unicode_dir = temp / "unicode-é-漢字"
        unicode_dir.mkdir()
        payload = unicode_dir / "synthetic payload.txt"
        payload.write_bytes(b"PacRipper synthetic Docker archive test\n")

        zip_path = unicode_dir / "synthetic input.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(payload, arcname=payload.name)

        # Create the 7z fixture with the image's own runtime tool so the host only
        # needs Docker/Podman-compatible Docker CLI support.
        seven = run(
            [
                "docker", "run", "--rm",
                "--entrypoint", "/bin/sh",
                "-v", f"{unicode_dir}:/work",
                "-w", "/work",
                IMAGE,
                "-c",
                "if command -v 7z >/dev/null 2>&1; then "
                "7z a -t7z 'synthetic input.7z' 'synthetic payload.txt' >/dev/null; "
                "else 7zz a -t7z 'synthetic input.7z' 'synthetic payload.txt' >/dev/null; fi",
            ]
        )
        require(seven.returncode == 0, "unable to create synthetic 7z fixture")
        seven_path = unicode_dir / "synthetic input.7z"
        require(seven_path.is_file(), "synthetic 7z fixture was not created")

        expect_canonical_rejection(
            unicode_dir,
            zip_path.name,
            "output from zip",
        )
        expect_canonical_rejection(
            unicode_dir,
            seven_path.name,
            "output from 7z",
        )

    print("PacRipper Docker runtime smoke test: PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError) as exc:
        print(f"PacRipper Docker runtime smoke test: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
