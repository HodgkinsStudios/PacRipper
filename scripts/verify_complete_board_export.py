#!/usr/bin/env python3
"""Independent verifier for PacRipper complete-board recovery exports.
Created by Jacob Hodgkins.

This verifier deliberately does not import PacRipper C++ code.  It rebuilds every
active canonical Pac-Man board ROM/PROM from the exported machine-readable source
representations and compares the result byte-for-byte with a user-supplied ROM set.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from archive_support import archive_kind, read_archive_members

ACTIVE_FILES = [
    "pacman.6e", "pacman.6f", "pacman.6h", "pacman.6j",
    "pacman.5e", "pacman.5f", "82s123.7f", "82s126.4a",
    "82s126.1m", "82s126.3m",
]
EXPECTED_SIZES = {
    "pacman.6e": 4096, "pacman.6f": 4096, "pacman.6h": 4096, "pacman.6j": 4096,
    "pacman.5e": 4096, "pacman.5f": 4096, "82s123.7f": 32, "82s126.4a": 256,
    "82s126.1m": 256, "82s126.3m": 256,
}
PROGRAM_FILES = ["pacman.6e", "pacman.6f", "pacman.6h", "pacman.6j"]
HEX_BYTE = re.compile(r"\$([0-9A-Fa-f]{2})(?=\s*(?:,|;|$))")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_archive_members(path: Path) -> Dict[str, bytes]:
    by_base: Dict[str, List[Tuple[str, bytes]]] = {}
    for member_name, data in read_archive_members(path):
        base = Path(member_name).name
        if base in ACTIVE_FILES:
            by_base.setdefault(base, []).append((member_name, data))
    out: Dict[str, bytes] = {}
    for name in ACTIVE_FILES:
        rows = by_base.get(name, [])
        if len(rows) != 1:
            raise ValueError(f"canonical input {name}: expected exactly one archive member, found {len(rows)}")
        out[name] = rows[0][1]
    return out


def load_canonical(path: Path) -> Dict[str, bytes]:
    if path.is_file() and archive_kind(path) in ("zip", "7z"):
        out = _load_archive_members(path)
    elif path.is_dir():
        out = {}
        for name in ACTIVE_FILES:
            matches = [p for p in path.rglob(name) if p.is_file()]
            if len(matches) != 1:
                raise ValueError(f"canonical input {name}: expected exactly one file under folder, found {len(matches)}")
            out[name] = matches[0].read_bytes()
    else:
        raise ValueError(f"ROM input is neither a directory nor a ZIP/7z archive: {path}")
    for name, expected in EXPECTED_SIZES.items():
        actual = len(out[name])
        if actual != expected:
            raise ValueError(f"canonical input {name}: expected {expected} bytes, found {actual}")
    return out


def rebuild_program(export_root: Path) -> Dict[str, bytes]:
    """Reconstruct the 16-KiB program directly from the single readable pacman.asm.

    Instruction bytes come from the machine-readable @INSN markers attached to
    the emitted Z80 mnemonics. Data bytes come from the actual DB operands. The
    deeper readable-source verifier separately proves that every mnemonic/operand
    and marker agrees with the canonical instruction and reconstruction ledgers.
    """
    asm = export_root / "program" / "pacman.asm"
    blob = bytearray(0x4000)
    covered = set()
    for raw in asm.read_text(encoding="utf-8").splitlines():
        im = INSN_MARKER.search(raw)
        if im:
            pc = int(im.group(1), 16)
            data = bytes(int(x, 16) for x in im.group(2).split())
            for off, b in enumerate(data):
                addr = pc + off
                if not (0 <= addr < 0x4000) or addr in covered:
                    raise ValueError(f"program/pacman.asm duplicate/out-of-range instruction byte at ${addr:04X}")
                blob[addr] = b
                covered.add(addr)
            continue
        dm = DATA_MARKER.search(raw)
        if dm:
            addr = int(dm.group(1), 16)
            source = raw.split(";", 1)[0].strip()
            sm = DB_SOURCE.match(source)
            if not sm:
                raise ValueError(f"program/pacman.asm @DATA ${addr:04X} is not an explicit DB source line")
            body = sm.group(1)
            data = bytes(int(m.group(1), 16) for m in HEX_TOKEN.finditer(body))
            token_count = len([x for x in body.split(",") if x.strip()])
            if not data or len(data) != token_count:
                raise ValueError(f"program/pacman.asm @DATA ${addr:04X} contains a non-byte DB token")
            for off, b in enumerate(data):
                a = addr + off
                if not (0 <= a < 0x4000) or a in covered:
                    raise ValueError(f"program/pacman.asm duplicate/out-of-range data byte at ${a:04X}")
                blob[a] = b
                covered.add(a)
    if len(covered) != 0x4000:
        raise ValueError(f"program/pacman.asm rebuilt {len(covered)} bytes, expected 16384")
    return {name: bytes(blob[i*0x1000:(i+1)*0x1000]) for i, name in enumerate(PROGRAM_FILES)}



INSN_MARKER = re.compile(r";\s*@INSN\s+\$([0-9A-Fa-f]{4})\s+BYTES=([0-9A-Fa-f ]+)\s*$")
DATA_MARKER = re.compile(r";\s*@DATA\s+\$([0-9A-Fa-f]{4})\s+OWNER=([A-Za-z0-9_]+)\s*$")
LABEL_LINE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*):\s*$")
DB_SOURCE = re.compile(r"^\s*DB\s+(.+?)\s*$", re.IGNORECASE)
HEX_TOKEN = re.compile(r"\$([0-9A-Fa-f]{2})(?=\s*(?:,|$))")


def _norm_operand(text: str) -> str:
    return re.sub(r"\s+", "", text).upper()


def verify_readable_disassembly(export_root: Path) -> List[str]:
    asm_path = export_root / "program" / "pacman.asm"
    instruction_path = export_root / "program" / "instruction_ledger.csv"
    reconstruction_path = export_root / "program" / "reconstruction_ledger.csv"
    provenance_path = export_root / "program" / "provenance_ledger.csv"

    asm_lines = asm_path.read_text(encoding="utf-8").splitlines()

    # First scan: attach labels to the next emitted source record. The exporter places
    # labels immediately before either an @INSN or @DATA record (comments may intervene).
    labels: Dict[str, int] = {}
    pending_labels: List[str] = []
    for raw in asm_lines:
        lm = LABEL_LINE.match(raw)
        if lm:
            pending_labels.append(lm.group(1))
            continue
        im = INSN_MARKER.search(raw)
        dm = DATA_MARKER.search(raw)
        if im or dm:
            addr = int((im or dm).group(1), 16)
            for label in pending_labels:
                if label in labels:
                    raise ValueError(f"program/pacman.asm duplicate label {label}")
                labels[label] = addr
            pending_labels.clear()
    if pending_labels:
        raise ValueError("program/pacman.asm has dangling labels without emitted source records")

    with instruction_path.open(newline="", encoding="utf-8") as f:
        canonical_rows = list(csv.DictReader(f))
    if len(canonical_rows) != 5414:
        raise ValueError(f"program/instruction_ledger.csv expected 5414 rows, found {len(canonical_rows)}")
    canonical_rows_by_pc: Dict[int, Dict[str, str]] = {}
    canonical_bytes: Dict[int, bytes] = {}
    for r in canonical_rows:
        pc = int(r["pc"].replace("$", ""), 16)
        data = bytes(int(x, 16) for x in r["bytes"].split() if x)
        if pc in canonical_bytes:
            raise ValueError(f"instruction ledger duplicate pc ${pc:04X}")
        canonical_rows_by_pc[pc] = r
        canonical_bytes[pc] = data

    markers: Dict[int, bytes] = {}
    source_texts: Dict[int, str] = {}
    data_records: List[Tuple[int, bytes, str]] = []
    for line_no, raw in enumerate(asm_lines, 1):
        im = INSN_MARKER.search(raw)
        if im:
            pc = int(im.group(1), 16)
            data = bytes(int(x, 16) for x in im.group(2).split())
            if pc in markers:
                raise ValueError(f"program/pacman.asm duplicate @INSN marker at ${pc:04X}")
            source_text = raw.split(";", 1)[0].strip()
            if not source_text or source_text.upper().startswith("DB ") or " DB " in (" " + source_text.upper() + " "):
                raise ValueError(f"program/pacman.asm @INSN ${pc:04X} is not emitted as a Z80 mnemonic")
            markers[pc] = data
            source_texts[pc] = source_text
            continue
        dm = DATA_MARKER.search(raw)
        if dm:
            addr = int(dm.group(1), 16)
            owner = dm.group(2)
            source = raw.split(";", 1)[0].strip()
            sm = DB_SOURCE.match(source)
            if not sm:
                raise ValueError(f"program/pacman.asm @DATA ${addr:04X} is not an explicit DB source line")
            body = sm.group(1)
            data = bytes(int(m.group(1), 16) for m in HEX_TOKEN.finditer(body))
            # Require the parser to account for every comma-separated DB token.
            token_count = len([x for x in body.split(",") if x.strip()])
            if not data or len(data) != token_count:
                raise ValueError(f"program/pacman.asm @DATA ${addr:04X} contains a non-byte DB token")
            data_records.append((addr, data, owner))

    if set(markers) != set(canonical_bytes):
        missing = sorted(set(canonical_bytes) - set(markers))
        extra = sorted(set(markers) - set(canonical_bytes))
        raise ValueError(f"human disassembly instruction-start mismatch missing={len(missing)} extra={len(extra)}")
    for pc, expected in canonical_bytes.items():
        if markers[pc] != expected:
            raise ValueError(f"human disassembly @INSN bytes differ from canonical instruction ledger at ${pc:04X}")

        # Verify the actual mnemonic/operand text, resolving exporter-generated symbolic
        # control-flow labels back to their canonical numeric destinations.
        source = source_texts[pc]
        parts = source.split(None, 1)
        actual_mnemonic = parts[0].upper()
        actual_operands = parts[1].strip() if len(parts) > 1 else ""
        row = canonical_rows_by_pc[pc]
        expected_mnemonic = row["mnemonic"].upper()
        expected_operands = row["operands"].strip()
        if actual_mnemonic != expected_mnemonic:
            raise ValueError(f"human disassembly mnemonic mismatch at ${pc:04X}: {actual_mnemonic} != {expected_mnemonic}")

        if actual_mnemonic in {"CALL", "JP", "JR", "DJNZ", "RST"}:
            width = 2 if actual_mnemonic == "RST" else 4
            def replace_label(match: re.Match[str]) -> str:
                label = match.group(0)
                target = labels.get(label)
                return f"${target:0{width}X}" if target is not None else label
            actual_operands = re.sub(r"[A-Za-z_][A-Za-z0-9_]*", replace_label, actual_operands)
        if _norm_operand(actual_operands) != _norm_operand(expected_operands):
            raise ValueError(
                f"human disassembly operand mismatch at ${pc:04X}: {actual_operands!r} != {expected_operands!r}"
            )

    with reconstruction_path.open(newline="", encoding="utf-8") as f:
        reconstruction = list(csv.DictReader(f))
    if len(reconstruction) != 0x4000:
        raise ValueError(f"program/reconstruction_ledger.csv expected 16384 rows, found {len(reconstruction)}")
    by_addr = {int(r["address"].replace("$", ""), 16): r for r in reconstruction}

    # Build a complete 16-KiB image from the readable source records. Instruction bytes
    # come from the @INSN record after the source text has been proven equal to the
    # canonical instruction ledger; data bytes come from the actual DB operands.
    readable_blob = bytearray(0x4000)
    covered = set()
    marked_bytes = 0
    for pc, data in markers.items():
        for off, b in enumerate(data):
            addr = pc + off
            if addr in covered:
                raise ValueError(f"human disassembly duplicate source ownership at ${addr:04X}")
            r = by_addr.get(addr)
            if r is None or r["owner_kind"] != "CanonicalInstruction":
                raise ValueError(f"human disassembly instruction byte lacks final code ownership at ${addr:04X}")
            if int(r["emitted_byte"].replace("$", ""), 16) != b:
                raise ValueError(f"human disassembly byte differs from final reconstruction ledger at ${addr:04X}")
            readable_blob[addr] = b
            covered.add(addr)
            marked_bytes += 1

    data_bytes = 0
    for start, data, owner in data_records:
        for off, b in enumerate(data):
            addr = start + off
            if not (0 <= addr < 0x4000):
                raise ValueError(f"human disassembly data extends out of program range at ${addr:04X}")
            if addr in covered:
                raise ValueError(f"human disassembly duplicate source ownership at ${addr:04X}")
            r = by_addr.get(addr)
            if r is None or r["owner_kind"] == "CanonicalInstruction":
                raise ValueError(f"human disassembly DB overlaps canonical instruction at ${addr:04X}")
            if r["owner_kind"] != owner:
                raise ValueError(f"human disassembly @DATA owner mismatch at ${addr:04X}: {owner} != {r['owner_kind']}")
            if int(r["emitted_byte"].replace("$", ""), 16) != b:
                raise ValueError(f"human disassembly DB byte differs from final reconstruction ledger at ${addr:04X}")
            readable_blob[addr] = b
            covered.add(addr)
            data_bytes += 1

    ledger_code_bytes = sum(1 for r in reconstruction if r["owner_kind"] == "CanonicalInstruction")
    if marked_bytes != ledger_code_bytes:
        raise ValueError(f"human disassembly code-byte coverage {marked_bytes}/{ledger_code_bytes}")
    if len(covered) != 0x4000:
        raise ValueError(f"human disassembly total byte coverage {len(covered)}/16384")
    final_blob = bytes(int(by_addr[a]["emitted_byte"].replace("$", ""), 16) for a in range(0x4000))
    if bytes(readable_blob) != final_blob:
        raise ValueError("human disassembly complete readable-source image differs from final reconstruction ledger")

    with provenance_path.open(newline="", encoding="utf-8") as f:
        provenance = list(csv.DictReader(f))
    if len(provenance) != 0x4000:
        raise ValueError(f"program/provenance_ledger.csv expected 16384 rows, found {len(provenance)}")
    unresolved = sum(1 for r in provenance if r.get("resolved") != "1")
    if unresolved:
        raise ValueError(f"final release provenance has {unresolved} unresolved program bytes")
    forbidden_history_fields = [name for name in (provenance[0].keys() if provenance else []) if name.startswith("historical_")]
    if forbidden_history_fields:
        raise ValueError("final release provenance must not embed deprecated internal-analysis columns: " + ",".join(forbidden_history_fields))
    if any("unresolved" in (r.get("closure_primary", "") + " " + r.get("provenance", "")).lower() for r in provenance):
        raise ValueError("final release provenance contains stale unresolved wording in current-reference fields")

    return [
        f"human_disassembly_instructions={len(markers)}/5414 PASS",
        f"human_disassembly_instruction_bytes={marked_bytes}/{ledger_code_bytes} PASS",
        f"human_disassembly_data_bytes={data_bytes}/{0x4000-ledger_code_bytes} PASS",
        "human_disassembly_source_text_vs_canonical_ledger=PASS",
        f"human_disassembly_total_bytes={len(covered)}/16384 PASS",
        f"human_disassembly_program_sha256={sha256(bytes(readable_blob))} PASS",
        "human_disassembly_mnemonic_emission=PASS",
        "final_release_provenance_unresolved=0/16384 PASS",
    ]

def _set_msb_bit(buf: bytearray, byte_offset: int, bit_from_msb: int, value: int) -> None:
    if not (0 <= byte_offset < len(buf)):
        raise ValueError(f"ROM byte offset out of range: {byte_offset}")
    if not (0 <= bit_from_msb <= 7):
        raise ValueError(f"bit_from_msb out of range: {bit_from_msb}")
    mask = 1 << (7 - bit_from_msb)
    if value:
        buf[byte_offset] |= mask
    else:
        buf[byte_offset] &= (~mask) & 0xFF


def rebuild_graphics_map(path: Path, expected_rows: int) -> bytes:
    out = bytearray(4096)
    seen_bits = set()
    rows = 0
    with path.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows += 1
            pixel = int(r["pixel"])
            if not (0 <= pixel <= 3):
                raise ValueError(f"{path}: pixel outside 2-bpp range")
            pairs = [
                (int(r["msb_rom_byte"]), int(r["msb_bit_from_msb"]), (pixel >> 1) & 1),
                (int(r["lsb_rom_byte"]), int(r["lsb_bit_from_msb"]), pixel & 1),
            ]
            for byte_offset, bit_from_msb, value in pairs:
                key = (byte_offset, bit_from_msb)
                if key in seen_bits:
                    raise ValueError(f"{path}: duplicate source-bit ownership {key}")
                seen_bits.add(key)
                _set_msb_bit(out, byte_offset, bit_from_msb, value)
    if rows != expected_rows:
        raise ValueError(f"{path}: expected {expected_rows} pixel rows, found {rows}")
    if len(seen_bits) != 4096 * 8:
        raise ValueError(f"{path}: expected 32768 uniquely owned bits, found {len(seen_bits)}")
    return bytes(out)


def rebuild_palette(path: Path) -> bytes:
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))
    if len(rows) != 32:
        raise ValueError(f"{path}: expected 32 entries, found {len(rows)}")
    out = bytearray(32)
    seen = set()
    for r in rows:
        idx = int(r["index"])
        if idx in seen or not (0 <= idx < 32):
            raise ValueError(f"{path}: invalid/duplicate palette index {idx}")
        seen.add(idx)
        value = 0
        for bit in range(8):
            b = int(r[f"bit{bit}"])
            if b not in (0, 1):
                raise ValueError(f"{path}: bit{bit} must be 0/1")
            value |= b << bit
        out[idx] = value
    return bytes(out)


def rebuild_nibble_table(path: Path, value_field: str) -> bytes:
    rows = list(csv.DictReader(path.open(newline="", encoding="utf-8")))
    if len(rows) != 256:
        raise ValueError(f"{path}: expected 256 entries, found {len(rows)}")
    out = bytearray(256)
    seen = set()
    for r in rows:
        address = int(r["address"])
        if address in seen or not (0 <= address < 256):
            raise ValueError(f"{path}: invalid/duplicate address {address}")
        seen.add(address)
        low = int(r[value_field])
        high = int(r["serialized_upper_nibble"])
        if not (0 <= low <= 15 and 0 <= high <= 15):
            raise ValueError(f"{path}: nibble outside 0..15 at address {address}")
        out[address] = low | (high << 4)
    return bytes(out)


def rebuild_all(export_root: Path) -> Dict[str, bytes]:
    result = rebuild_program(export_root)
    result["pacman.5e"] = rebuild_graphics_map(export_root / "graphics" / "character_map.csv", 256 * 64)
    result["pacman.5f"] = rebuild_graphics_map(export_root / "graphics" / "sprite_map.csv", 64 * 256)
    result["82s123.7f"] = rebuild_palette(export_root / "color" / "palette_source.csv")
    result["82s126.4a"] = rebuild_nibble_table(export_root / "color" / "color_lookup_source.csv", "palette_index")
    result["82s126.1m"] = rebuild_nibble_table(export_root / "audio" / "waveform_source.csv", "sample_nibble")
    result["82s126.3m"] = rebuild_nibble_table(export_root / "audio" / "timing_prom_source.csv", "control_nibble")
    return result


def verify(export_root: Path, rom_path: Path) -> Tuple[bool, List[str]]:
    canonical = load_canonical(rom_path)
    rebuilt = rebuild_all(export_root)
    disassembly_lines = verify_readable_disassembly(export_root)
    lines: List[str] = []
    ok = True
    total = 0
    for name in ACTIVE_FILES:
        expected = canonical[name]
        actual = rebuilt[name]
        total += len(expected)
        match = actual == expected
        ok &= match
        lines.append(
            f"{name}: {'PASS' if match else 'FAIL'} bytes={len(actual)}/{len(expected)} "
            f"rebuilt_sha256={sha256(actual)} canonical_sha256={sha256(expected)}"
        )
    lines.append(f"active_files={len(ACTIVE_FILES)}/10 total_bytes={total}/25376 exact_rebuild={'PASS' if ok else 'FAIL'}")
    lines.extend(disassembly_lines)
    return ok, lines


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a complete PacRipper board recovery export")
    parser.add_argument("export_root", type=Path)
    parser.add_argument("rom_path", type=Path)
    parser.add_argument("--report", type=Path, help="write a deterministic verification report")
    args = parser.parse_args()
    try:
        ok, lines = verify(args.export_root, args.rom_path)
    except Exception as exc:
        print(f"Complete-board standalone verification: FAIL: {exc}", file=sys.stderr)
        return 1
    report = "Complete Pac-Man board source reconstruction: {}\n{}\n".format("PASS" if ok else "FAIL", "\n".join(lines))
    print(report, end="")
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report, encoding="utf-8", newline="\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
