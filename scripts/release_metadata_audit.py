#!/usr/bin/env python3
"""Public-release metadata audit for PacRipper 1.0.
Created by Jacob Hodgkins.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

EXPECTED_VERSION = "1.0"
SELF = Path(__file__).resolve()
SKIP_DIRS = {".git", "bin", "dist", "obj", "__pycache__"}
TEXT_SUFFIXES = {
    "", ".bat", ".cff", ".cpp", ".h", ".json", ".md", ".py", ".sh", ".txt", ".yml", ".yaml"
}

LEGACY_PATCH_VERSION = EXPECTED_VERSION + ".0"
LEGACY_V_PREFIX = "V" + EXPECTED_VERSION

FORBIDDEN = (
    (re.compile(rf"(?<!\\d){re.escape(LEGACY_PATCH_VERSION)}(?!\\d)"), "legacy patch-level project version"),
    (re.compile(rf"\\bv{re.escape(LEGACY_PATCH_VERSION)}\\b", re.IGNORECASE), "legacy patch-level release tag"),
    (re.compile(rf"\\b{re.escape(LEGACY_V_PREFIX)}\\b"), "legacy V-prefixed project version"),
    (re.compile(r"\\bUnreleased\\b", re.IGNORECASE), "unfinished release wording"),
)

REQUIRED_MARKERS = {
    "README.md": ("# PacRipper 1.0", "Current public release: **1.0**"),
    "CITATION.cff": ('version: "1.0"', "date-released: 2026-10-04"),
    "Dockerfile": ('org.opencontainers.image.version="1.0"',),
    "src/main.cpp": ('kVersion = "1.0"',),
    ".github/workflows/docker-image.yml": ('"${IMAGE_NAME}:1.0"',),
}


def iter_text_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.resolve() == SELF:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        yield path


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    errors: list[str] = []

    version_file = root / "VERSION"
    if not version_file.is_file():
        errors.append("VERSION file is missing")
    elif version_file.read_text(encoding="utf-8").strip() != EXPECTED_VERSION:
        errors.append(f"VERSION must contain exactly {EXPECTED_VERSION}")

    for rel, markers in REQUIRED_MARKERS.items():
        path = root / rel
        if not path.is_file():
            errors.append(f"required release metadata file is missing: {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                errors.append(f"{rel}: missing release marker {marker!r}")

    for path in iter_text_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(root)
        for pattern, description in FORBIDDEN:
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"{rel}:{line}: {description}")

    for rel in ("bin/PacRipper", "bin/PacRipperCore"):
        tracked = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--error-unmatch", rel],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if tracked.returncode == 0:
            errors.append(f"generated binary is tracked by Git: {rel}")

    if errors:
        print("PacRipper 1.0 release metadata audit: FAIL")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("PacRipper 1.0 release metadata audit: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
