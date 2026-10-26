#!/usr/bin/env python3
# Created by Jacob Hodgkins
"""Strict release audit for accidental supported ROM/PROM payload inclusion.

Usage:
  python3 scripts/strict_rom_free_audit.py <project-root> <canonical-rom-archive-or-dir> [more-reference-archives...]

The reference ROM set is read only for comparison and is never copied into the
project. The audit rejects complete ROM files, generated disassembly/rebuild
artifacts, nested archive payloads, known historical raw-byte proof idioms,
meaningful raw binary subsequences, straightforward compressed copies, and
long encoded payloads that decode to meaningful ROM subsequences.
"""

from __future__ import annotations

import base64
import bz2
import gzip
import hashlib
import lzma
import math
import re
import sys
import zlib
from collections import Counter
from pathlib import Path

from archive_support import archive_kind, read_archive_members

PROFILES = {
    "pacman": (
        "pacman.6e", "pacman.6f", "pacman.6h", "pacman.6j",
        "pacman.5e", "pacman.5f", "82s123.7f", "82s126.4a",
        "82s126.1m", "82s126.3m",
    ),
    "puckman": (
        "pm1_prg1.6e", "pm1_prg2.6k", "pm1_prg3.6f", "pm1_prg4.6m",
        "pm1_prg5.6h", "pm1_prg6.6n", "pm1_prg7.6j", "pm1_prg8.6p",
        "pm1_chg1.5e", "pm1_chg2.5h", "pm1_chg3.5f", "pm1_chg4.5j",
        "pm1-1.7f", "pm1-4.4a", "pm1-3.1m", "pm1-2.3m",
    ),
}
FORBIDDEN_SUFFIXES = {
    ".asm", ".rom", ".prom", ".img", ".dump", ".hex",
    ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz",
}
TEXT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".h", ".hpp", ".py", ".md", ".txt",
    ".csv", ".json", ".sh", ".bat", ".cbp", ".workspace",
}
RAW_SIGNATURE_PATTERNS = (
    r"\bbytesAt\s*\(", r"\bbytes18\s*\(", r"\bexactBytes\s*\(",
    r"\bexpectedDirectionBytes\b", r"\bwords\s*\(\s*rom\s*,",
    r"(?:rom|program)\s*\[\s*0x[0-9A-Fa-f]+\s*\]\s*==\s*0x[0-9A-Fa-f]{1,2}",
)
ARCHIVE_MAGICS = (
    b"PK\x03\x04", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07",
    b"\x1f\x8b\x08", b"BZh", b"\xfd7zXZ\x00",
)


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def load_reference(path: Path) -> dict[str, bytes]:
    if path.is_dir():
        by_base = {q.name.lower(): q.read_bytes() for q in path.iterdir() if q.is_file()}
    elif archive_kind(path) in ("zip", "7z"):
        by_base = {Path(n).name.lower(): data for n, data in read_archive_members(path)}
    else:
        raise SystemExit(f"Unsupported reference container: {path}")

    matches = []
    for profile, names in PROFILES.items():
        if all(name.lower() in by_base for name in names):
            matches.append((profile, names))
    if len(matches) != 1:
        raise SystemExit(f"Reference must contain exactly one supported canonical set; matches={len(matches)}: {path}")

    profile, names = matches[0]
    return {f"{profile}:{name}": by_base[name.lower()] for name in names}


def informative_windows(refs: dict[str, bytes], width: int = 8):
    index: dict[bytes, list[tuple[str, int]]] = {}
    for name, data in refs.items():
        for off in range(0, len(data) - width + 1):
            w = data[off:off + width]
            if len(set(w)) < 4 or entropy(w) < 1.8:
                continue
            index.setdefault(w, []).append((name, off))
    return index


def meaningful_raw_hits(blob: bytes, index, refs, width: int = 8):
    hits = []
    for off in range(0, len(blob) - width + 1):
        w = blob[off:off + width]
        matches = index.get(w)
        if not matches:
            continue
        for name, roff in matches:
            ref = refs[name]
            if roff and off and ref[roff - 1] == blob[off - 1]:
                continue
            length = width
            while roff + length < len(ref) and off + length < len(blob) and ref[roff + length] == blob[off + length]:
                length += 1
            hits.append((name, roff, off, length))
    return hits


def source_literal_hits(text: str, refs: dict[str, bytes]):
    hits = []
    for m in re.finditer(r"\{([^{}]{0,6000})\}", text, re.S):
        body = m.group(1)
        tokens = re.findall(r"(?<![\w$])(?:0x([0-9A-Fa-f]{1,4})|([0-9]{1,5}))(?![\w])", body)
        values = [int(h, 16) if h else int(d) for h, d in tokens]
        if len(values) >= 12 and all(v <= 0xFF for v in values):
            seq = bytes(values)
            if len(set(seq)) >= 6 and entropy(seq) >= 2.5:
                for name, ref in refs.items():
                    pos = ref.find(seq)
                    if pos >= 0:
                        hits.append((m.start(), "byte-list", name, pos, len(seq)))
        if len(values) >= 6 and any(v > 0xFF for v in values) and all(v <= 0xFFFF for v in values):
            seq = b"".join(bytes((v & 0xFF, (v >> 8) & 0xFF)) for v in values)
            if len(set(seq)) >= 6 and entropy(seq) >= 2.5:
                for name, ref in refs.items():
                    pos = ref.find(seq)
                    if pos >= 0:
                        hits.append((m.start(), "little-endian word-list", name, pos, len(seq)))
    return hits


def compressed_forms(data: bytes):
    forms = []
    for level in (1, 6, 9):
        forms.append((f"zlib-{level}", zlib.compress(data, level)))
        forms.append((f"gzip-{level}", gzip.compress(data, compresslevel=level, mtime=0)))
    forms.append(("bz2", bz2.compress(data)))
    forms.append(("lzma", lzma.compress(data)))
    return forms


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__.strip())
        return 2
    root = Path(sys.argv[1]).resolve()
    refs: dict[str, bytes] = {}
    for arg in sys.argv[2:]:
        loaded = load_reference(Path(arg).resolve())
        overlap = set(refs).intersection(loaded)
        if overlap:
            raise SystemExit("Duplicate canonical reference profile supplied: " + ", ".join(sorted(overlap)))
        refs.update(loaded)
    ref_hashes = {hashlib.sha256(data).hexdigest(): name for name, data in refs.items()}
    window_index = informative_windows(refs, 8)
    failures: list[str] = []
    scanned = 0

    files = [p for p in root.rglob("*") if p.is_file() and "obj" not in p.parts and "__pycache__" not in p.parts]
    for p in files:
        scanned += 1
        rel = p.relative_to(root).as_posix()
        low = rel.lower()
        data = p.read_bytes()

        if p.suffix.lower() in FORBIDDEN_SUFFIXES:
            failures.append(f"forbidden release artifact: {rel}")
        if any(tag in low for tag in ("reconstructed_rom", "rebuilt_rom", "rom_cache", "test_fixture")):
            failures.append(f"forbidden cached/test artifact name: {rel}")

        digest = hashlib.sha256(data).hexdigest()
        if digest in ref_hashes:
            failures.append(f"complete ROM/PROM payload: {rel} == {ref_hashes[digest]}")

        if any(data.startswith(magic) for magic in ARCHIVE_MAGICS):
            failures.append(f"nested archive/compressed payload: {rel}")

        is_text = p.suffix.lower() in TEXT_SUFFIXES
        if is_text:
            text = data.decode("utf-8", errors="ignore")
            if rel != "scripts/strict_rom_free_audit.py":
                for pattern in RAW_SIGNATURE_PATTERNS:
                    if re.search(pattern, text):
                        failures.append(f"historical raw-byte signature idiom in {rel}: /{pattern}/")
            for at, kind, name, roff, length in source_literal_hits(text, refs):
                line = text.count("\n", 0, at) + 1
                failures.append(f"ROM-derived {kind} in {rel}:{line}: {name}+0x{roff:X}, {length} bytes")
            for token in re.findall(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{64,}={0,2})(?![A-Za-z0-9+/])", text):
                try:
                    decoded = base64.b64decode(token, validate=True)
                except Exception:
                    continue
                if meaningful_raw_hits(decoded, window_index, refs):
                    failures.append(f"base64 payload decodes to ROM-derived bytes: {rel}")
                    break
        else:
            hits = meaningful_raw_hits(data, window_index, refs)
            if hits:
                name, roff, off, length = max(hits, key=lambda h: h[3])
                failures.append(f"meaningful raw ROM sequence in {rel}: {name}+0x{roff:X} at file+0x{off:X}, {length} bytes")

    # Straightforward compressed-copy search, including binaries and text blobs.
    haystacks = [(p.relative_to(root).as_posix(), p.read_bytes()) for p in files]
    for name, ref in refs.items():
        for encoding, payload in compressed_forms(ref):
            if len(payload) < 16:
                continue
            for rel, data in haystacks:
                if payload in data:
                    failures.append(f"compressed ROM/PROM copy in {rel}: {name} ({encoding})")

    print(f"Strict ROM-free audit: {'FAIL' if failures else 'PASS'}")
    print(f"project_files_scanned={scanned}")
    print(f"canonical_reference_files={len(refs)}")
    print(f"canonical_reference_sets={len(sys.argv) - 2}")
    print("raw_binary_window=8 bytes (informative/high-entropy windows only)")
    print("source_literal_threshold=12 bytes or 6 little-endian words")
    if failures:
        for item in failures:
            print("FAIL:", item)
        return 1
    print("complete_rom_payloads=0")
    print("generated_asm_or_rom_artifacts=0")
    print("nested_archive_payloads=0")
    print("historical_expected_byte_signatures=0")
    print("meaningful_raw_binary_rom_sequences=0")
    print("rom_derived_source_literal_blocks=0")
    print("encoded_or_standard_compressed_rom_copies=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
