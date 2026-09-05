#!/usr/bin/env python3
"""Synthetic archive/output safety regression tests for PacRipper V1.0.
Created by Jacob Hodgkins. No copyrighted ROM data is used by this test.
"""
from __future__ import annotations

import importlib.util
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

from archive_support import MAX_ARCHIVE_MEMBERS, MAX_MEMBER_BYTES, read_archive_members


def expect_failure(label, fn):
    try:
        fn()
    except (ValueError, RuntimeError, OSError):
        print(f"{label}: PASS")
        return
    raise SystemExit(f"{label}: FAIL (unsafe input was accepted)")


def load_pipeline_module():
    spec = importlib.util.spec_from_file_location("pacripper_pipeline_for_test", ROOT / "scripts" / "pacripper_pipeline.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="PacRipper-safety-") as td:
        t = Path(td)

        traversal = t / "traversal.zip"
        with zipfile.ZipFile(traversal, "w") as zf:
            zf.writestr("../escape.bin", b"x")
        expect_failure("archive traversal rejection", lambda: read_archive_members(traversal))

        duplicate = t / "duplicate.zip"
        with zipfile.ZipFile(duplicate, "w") as zf:
            zf.writestr("ROM.bin", b"a")
            zf.writestr("rom.BIN", b"b")
        expect_failure("case-fold duplicate rejection", lambda: read_archive_members(duplicate))

        oversize = t / "oversize.zip"
        with zipfile.ZipFile(oversize, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("large.bin", b"A" * (MAX_MEMBER_BYTES + 1))
        expect_failure("oversize member rejection", lambda: read_archive_members(oversize))

        too_many = t / "too_many.zip"
        with zipfile.ZipFile(too_many, "w") as zf:
            for i in range(MAX_ARCHIVE_MEMBERS + 1):
                zf.writestr(f"f{i:03d}.bin", b"x")
        expect_failure("member-count rejection", lambda: read_archive_members(too_many))

        total_limit = t / "total_limit.zip"
        with zipfile.ZipFile(total_limit, "w", compression=zipfile.ZIP_STORED) as zf:
            block = bytes(range(256)) * 256
            for i in range(17):
                zf.writestr(f"block{i:02d}.bin", block)
        expect_failure("total decompressed-size rejection", lambda: read_archive_members(total_limit))

        option_name = t / "option_name.zip"
        with zipfile.ZipFile(option_name, "w") as zf:
            zf.writestr("-so", b"x")
        expect_failure("option-like member rejection", lambda: read_archive_members(option_name))

        pipeline = load_pipeline_module()
        archive = t / "input.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("synthetic.bin", b"not a ROM")

        existing = t / "existing"
        existing.mkdir()
        (existing / "KEEP_ME.txt").write_text("keep")
        expect_failure(
            "existing output requires --force",
            lambda: pipeline.validate_output_destination(existing, archive, False),
        )
        if (existing / "KEEP_ME.txt").read_text() != "keep":
            raise SystemExit("existing output test modified user data")

        expect_failure(
            "filesystem root always refused",
            lambda: pipeline.validate_output_destination(Path(Path.cwd().anchor), archive, True),
        )
        expect_failure(
            "user home always refused",
            lambda: pipeline.validate_output_destination(Path.home(), archive, True),
        )
        expect_failure(
            "application tree always refused",
            lambda: pipeline.validate_output_destination(ROOT, archive, True),
        )

        safe = t / "safe_existing"
        safe.mkdir()
        resolved = pipeline.validate_output_destination(safe, archive, True)
        if resolved != safe.resolve():
            raise SystemExit("safe forced output did not resolve as expected")
        print("safe --force destination acceptance: PASS")

    print("PacRipper archive/output safety tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
