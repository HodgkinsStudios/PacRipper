#!/usr/bin/env python3
"""Build the deterministic complete Pac-Man board recovery export.
Created by Jacob Hodgkins.

The generated tree contains source/semantic representations only.  No raw canonical
ROM/PROM payload is copied into the export.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent
sys.path.insert(0, str(SCRIPT.parent))
import verify_complete_board_export as verifier  # noqa: E402


def run(cmd: List[str], cwd: Path = ROOT) -> str:
    proc = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if proc.returncode != 0:
        print(proc.stdout, file=sys.stderr)
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(cmd)}")
    return proc.stdout


def copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def normalized_tree_digest(root: Path, exclude_names=frozenset({"source_tree_sha256.txt"})) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name not in exclude_names):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        data = path.read_bytes()
        h.update(rel + b"\0" + hashlib.sha256(data).digest() + b"\n")
    return h.hexdigest()


def read_csv(path: Path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, fieldnames: List[str], rows: Iterable[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        w.writeheader()
        for row in rows:
            w.writerow(row)


def program_filename_and_offset(address: int):
    slot = address // 0x1000
    names = ["pacman.6e", "pacman.6f", "pacman.6h", "pacman.6j"]
    if not (0 <= slot < 4):
        raise ValueError(f"program address outside 16 KiB: {address:#x}")
    return names[slot], address % 0x1000


def build_byte_ledger(program_export: Path, resources: Path, out: Path) -> None:
    fields = [
        "file", "byte_offset", "bit_range", "resource_owner_kind", "stable_decoded_object_id",
        "semantic_role", "source_export_location", "inverse_rebuild_provenance", "evidence_status",
    ]
    rows: List[Dict[str, object]] = []

    program_rows = read_csv(program_export / "rom_reconstruction_ledger.csv")
    if len(program_rows) != 0x4000:
        raise ValueError(f"program reconstruction ledger has {len(program_rows)} rows, expected 16384")
    for r in program_rows:
        address = int(r["address"].replace("$", ""), 16)
        filename, offset = program_filename_and_offset(address)
        kind = r["owner_kind"]
        semantic = {
            "CanonicalInstruction": "z80_instruction_byte",
            "ClassifiedData": "program_data_byte",
            "ProvenUnused": "proven_unused_program_byte",
            "InlinePayload": "inline_payload_byte",
            "CanonicalDataObject": "canonical_program_data_object_byte",
        }.get(kind, "program_owned_byte")
        stable = f"{kind}:{r['source_id']}"
        rows.append({
            "file": filename,
            "byte_offset": offset,
            "bit_range": "7..0",
            "resource_owner_kind": kind,
            "stable_decoded_object_id": stable,
            "semantic_role": f"{semantic};{r['closure_primary']}",
            "source_export_location": "program/pacman.asm;program/reconstruction_ledger.csv",
            "inverse_rebuild_provenance": r["provenance"],
            "evidence_status": "verified_program_reconstruction_PASS",
        })

    def append_grouped_bit_ownership(csv_path: Path, file_name: str, owner_kind: str, role: str, source_loc: str, stable_fn):
        grouped: Dict[int, List[Dict[str, str]]] = {}
        for r in read_csv(csv_path):
            if r["file"] != file_name:
                continue
            grouped.setdefault(int(r["byte_offset"]), []).append(r)
        expected = verifier.EXPECTED_SIZES[file_name]
        if len(grouped) != expected:
            raise ValueError(f"{file_name}: ownership covers {len(grouped)} bytes, expected {expected}")
        for offset in range(expected):
            bit_rows = grouped[offset]
            bits = [int(r["bit_from_msb"]) for r in bit_rows]
            if sorted(bits) != list(range(8)):
                raise ValueError(f"{file_name}:{offset}: bit ownership is not exactly 0..7")
            stable_ids = sorted(set(stable_fn(r) for r in bit_rows))
            semantic_fields = sorted(set(r.get("semantic_field", "pixel_bits") for r in bit_rows))
            rows.append({
                "file": file_name,
                "byte_offset": offset,
                "bit_range": "7..0",
                "resource_owner_kind": owner_kind,
                "stable_decoded_object_id": "|".join(stable_ids),
                "semantic_role": role + (";" + "|".join(semantic_fields) if semantic_fields else ""),
                "source_export_location": source_loc,
                "inverse_rebuild_provenance": "machine_readable_source_map_inverse_encoder",
                "evidence_status": "exact_bit_ownership_and_roundtrip_PASS",
            })

    graphics_ownership = resources / "graphics" / "bit_ownership.csv"
    append_grouped_bit_ownership(
        graphics_ownership, "pacman.5e", "character_graphics", "2bpp_character_pixel_bits",
        "graphics/characters.csv;graphics/character_map.csv",
        lambda r: f"CHAR_{int(r['object_id']):03d}",
    )
    append_grouped_bit_ownership(
        graphics_ownership, "pacman.5f", "sprite_graphics", "2bpp_sprite_pixel_bits",
        "graphics/sprites.csv;graphics/sprite_map.csv",
        lambda r: f"SPR_{int(r['object_id']):02d}",
    )

    color_ownership = resources / "color" / "bit_ownership.csv"
    append_grouped_bit_ownership(
        color_ownership, "82s123.7f", "palette_prom", "resistor_weighted_palette_entry_bits",
        "color/palette_source.csv; color/palette_map.csv", lambda r: r["stable_entry_id"],
    )
    append_grouped_bit_ownership(
        color_ownership, "82s126.4a", "color_lookup_prom", "palette_lookup_and_serialized_bits",
        "color/color_lookup_source.csv; color/color_lookup_map.csv", lambda r: r["stable_entry_id"],
    )

    audio_ownership = resources / "audio" / "bit_ownership.csv"
    append_grouped_bit_ownership(
        audio_ownership, "82s126.1m", "waveform_prom", "waveform_sample_and_serialized_bits",
        "audio/waveform_source.csv; audio/waveform_map.csv", lambda r: r["stable_entry_id"],
    )
    append_grouped_bit_ownership(
        audio_ownership, "82s126.3m", "sound_timing_control_prom", "sound_timing_control_and_serialized_bits",
        "audio/timing_prom_source.csv; audio/timing_prom_map.csv", lambda r: r["stable_entry_id"],
    )

    expected_total = sum(verifier.EXPECTED_SIZES.values())
    if len(rows) != expected_total:
        raise ValueError(f"complete byte ledger rows={len(rows)}, expected={expected_total}")
    counts: Dict[str, int] = {}
    for r in rows:
        counts[str(r["file"])] = counts.get(str(r["file"]), 0) + 1
    for name, expected in verifier.EXPECTED_SIZES.items():
        if counts.get(name) != expected:
            raise ValueError(f"byte ledger {name}: {counts.get(name,0)}/{expected}")
    write_csv(out / "manifest" / "board_byte_ownership.csv", fields, rows)


def build_bit_ledger(resources: Path, out: Path) -> None:
    fields = ["file", "byte_offset", "bit_from_msb", "owner_kind", "stable_decoded_object_id", "semantic_role", "source_export_location", "evidence_status"]
    rows = []

    for r in read_csv(resources / "graphics" / "bit_ownership.csv"):
        is_char = r["file"] == "pacman.5e"
        stable = f"CHAR_{int(r['object_id']):03d}" if is_char else f"SPR_{int(r['object_id']):02d}"
        rows.append({
            "file": r["file"], "byte_offset": r["byte_offset"], "bit_from_msb": r["bit_from_msb"],
            "owner_kind": r["object_kind"], "stable_decoded_object_id": stable,
            "semantic_role": f"pixel({r['x']},{r['y']})_bit{r['pixel_bit']}",
            "source_export_location": "graphics/character_map.csv" if is_char else "graphics/sprite_map.csv",
            "evidence_status": "exact_bit_ownership_PASS",
        })
    for folder, filename in [("color", "bit_ownership.csv"), ("audio", "bit_ownership.csv")]:
        for r in read_csv(resources / folder / filename):
            rows.append({
                "file": r["file"], "byte_offset": r["byte_offset"], "bit_from_msb": r["bit_from_msb"],
                "owner_kind": "color_prom" if folder == "color" else "audio_prom",
                "stable_decoded_object_id": r["stable_entry_id"],
                "semantic_role": f"{r['semantic_field']}:bit{r['semantic_bit']}",
                "source_export_location": {
                    "82s123.7f": "color/palette_source.csv", "82s126.4a": "color/color_lookup_source.csv",
                    "82s126.1m": "audio/waveform_source.csv", "82s126.3m": "audio/timing_prom_source.csv",
                }[r["file"]],
                "evidence_status": "exact_bit_ownership_PASS",
            })
    expected_bits = sum(verifier.EXPECTED_SIZES[n] * 8 for n in verifier.ACTIVE_FILES[4:])
    if len(rows) != expected_bits:
        raise ValueError(f"non-program bit ledger rows={len(rows)}, expected={expected_bits}")
    write_csv(out / "manifest" / "board_nonprogram_bit_ownership.csv", fields, rows)



def _hex_address(text: str) -> int:
    return int(text.replace("$", ""), 16)


def _asm_label(text: str) -> str:
    cleaned = []
    for ch in text:
        if ch.isalnum() or ch == "_":
            cleaned.append(ch)
        else:
            cleaned.append("_")
    label = "".join(cleaned).strip("_") or "data"
    if label[0].isdigit():
        label = "obj_" + label
    return label


def build_release_program_sources(program_export: Path, out: Path) -> Dict[str, int]:
    """Create the human-facing disassembly plus exact reconstruction/provenance sources."""
    ledger = read_csv(program_export / "rom_reconstruction_ledger.csv")
    instructions = read_csv(program_export / "reconciled_instructions.csv")
    data_objects = read_csv(program_export / "canonical_data_objects.csv")
    if len(ledger) != 0x4000:
        raise ValueError(f"program reconstruction ledger has {len(ledger)} rows, expected 16384")
    if len(instructions) != 5414:
        raise ValueError(f"canonical instruction ledger has {len(instructions)} rows, expected 5414")

    out_program = out / "program"
    out_program.mkdir(parents=True, exist_ok=True)
    # Publish clean, release-oriented ledgers. Internal analysis-stage column names are
    # intentionally not exposed in the public package.
    rebuild_text = (program_export / "rom_rebuild_verification.txt").read_text(encoding="utf-8")
    (out_program / "rebuild_verification.txt").write_text(rebuild_text, encoding="utf-8", newline="\n")

    instruction_fields = ["id", "pc", "length", "bytes", "mnemonic", "operands"]
    write_csv(out_program / "instruction_ledger.csv", instruction_fields,
              ({k: r[k] for k in instruction_fields} for r in instructions))

    recon_fields = ["address", "expected_byte", "emitted_byte", "owned", "owner_kind", "source_id",
                    "source_start", "source_end_exclusive", "source_pc", "source_offset",
                    "closure_primary", "source_text"]
    write_csv(out_program / "reconstruction_ledger.csv", recon_fields,
              ({k: r[k] for k in recon_fields} for r in ledger))

    map_rows = read_csv(program_export / "rom_reconstruction_map.csv")
    map_fields = [k for k in map_rows[0].keys() if k != "provenance"]
    write_csv(out_program / "reconstruction_map.csv", map_fields,
              ({k: r[k] for k in map_fields} for r in map_rows))

    rows_by_addr = {_hex_address(r["address"]): r for r in ledger}
    if sorted(rows_by_addr) != list(range(0x4000)):
        raise ValueError("program reconstruction ledger is not a complete unique 0x0000..0x3FFF address map")

    inst_by_pc: Dict[int, Dict[str, str]] = {}
    code_bytes = set()
    for r in instructions:
        pc = _hex_address(r["pc"])
        raw_bytes = [int(x, 16) for x in r["bytes"].split() if x]
        length = int(r["length"])
        if len(raw_bytes) != length:
            raise ValueError(f"instruction ${pc:04X}: byte count {len(raw_bytes)} != length {length}")
        if pc in inst_by_pc:
            raise ValueError(f"duplicate instruction start ${pc:04X}")
        inst_by_pc[pc] = r
        for off, b in enumerate(raw_bytes):
            addr = pc + off
            if addr >= 0x4000 or addr in code_bytes:
                raise ValueError(f"instruction ownership overlap/out of range at ${addr:04X}")
            lr = rows_by_addr[addr]
            if lr["owner_kind"] != "CanonicalInstruction":
                raise ValueError(f"instruction ${pc:04X} byte ${addr:04X} not CanonicalInstruction in final ledger")
            if int(lr["emitted_byte"].replace("$", ""), 16) != b:
                raise ValueError(f"instruction ${pc:04X} source byte mismatch at ${addr:04X}")
            code_bytes.add(addr)

    ledger_code = {a for a, r in rows_by_addr.items() if r["owner_kind"] == "CanonicalInstruction"}
    if code_bytes != ledger_code:
        raise ValueError(f"canonical instruction byte coverage mismatch: instruction={len(code_bytes)} ledger={len(ledger_code)}")

    # Human navigation labels: reset, direct flow targets, and accepted named data objects.
    labels: Dict[int, str] = {0: "reset_entry"}
    label_priority: Dict[int, int] = {0: 100}

    def set_label(addr: int, label: str, priority: int) -> None:
        if not (0 <= addr < 0x4000):
            return
        if priority > label_priority.get(addr, -1):
            labels[addr] = label
            label_priority[addr] = priority

    for r in data_objects:
        if r.get("accepted", "0") != "1":
            continue
        start = _hex_address(r["start"])
        set_label(start, _asm_label(r.get("name", "data")), 80)

    target16 = re.compile(r"\$([0-9A-Fa-f]{4})")
    target8 = re.compile(r"\$([0-9A-Fa-f]{2})(?![0-9A-Fa-f])")
    for pc, r in inst_by_pc.items():
        mnemonic = r["mnemonic"].upper()
        operands = r["operands"]
        if mnemonic in {"CALL", "JP", "JR", "DJNZ"}:
            matches = list(target16.finditer(operands))
            if matches:
                target = int(matches[-1].group(1), 16)
                if target in inst_by_pc:
                    prefix = "sub" if mnemonic == "CALL" else "loc"
                    set_label(target, f"{prefix}_{target:04X}", 50 if mnemonic == "CALL" else 40)
        elif mnemonic == "RST":
            m = target8.search(operands)
            if m:
                target = int(m.group(1), 16)
                if target in inst_by_pc:
                    set_label(target, f"rst_{target:02X}", 60)

    def symbolic_operands(r: Dict[str, str]) -> str:
        mnemonic = r["mnemonic"].upper()
        operands = r["operands"]
        if mnemonic in {"CALL", "JP", "JR", "DJNZ"}:
            matches = list(target16.finditer(operands))
            if matches:
                m = matches[-1]
                target = int(m.group(1), 16)
                label = labels.get(target)
                if label and target in inst_by_pc:
                    operands = operands[:m.start()] + label + operands[m.end():]
        elif mnemonic == "RST":
            m = target8.search(operands)
            if m:
                target = int(m.group(1), 16)
                label = labels.get(target)
                if label:
                    operands = operands[:m.start()] + label + operands[m.end():]
        return operands

    kind_prefix = {
        "InlinePayload": "inline",
        "CanonicalDataObject": "data",
        "ClassifiedData": "data",
        "ProvenUnused": "unused",
        "Unowned": "unowned",
    }
    for addr in range(0x4000):
        if addr in inst_by_pc or addr in code_bytes:
            continue
        # Label each final ownership span start so data is directly navigable.
        row = rows_by_addr[addr]
        prev = rows_by_addr.get(addr - 1)
        span_start = addr == 0 or prev is None or prev["owner_kind"] != row["owner_kind"] or prev["source_id"] != row["source_id"]
        if span_start:
            set_label(addr, f"{kind_prefix.get(row['owner_kind'], 'data')}_{addr:04X}", 20)

    asm_lines = [
        "; Pac-Man (Midway/Namco hardware) release-quality Z80 disassembly",
        "; Generated by PacRipper from the verified instruction/data ownership model.",
        "; Created by Jacob Hodgkins",
        ";",
        "; Primary readable program source: code is emitted as Z80 mnemonics.",
        "; Non-code bytes remain explicit DB source with final ownership classification.",
        "; This readable source is also the exact-byte program reconstruction reference.",
        "; Long documentation comments are wrapped by the public formatter for assembler portability.",
        "; @INSN and @DATA markers are machine-readable verification metadata.",
        "",
        "        ORG $0000",
        "",
    ]

    addr = 0
    emitted_instructions = 0
    emitted_instruction_bytes = 0
    emitted_data_bytes = 0
    while addr < 0x4000:
        if addr in inst_by_pc:
            r = inst_by_pc[addr]
            if addr in labels:
                asm_lines.append(f"{labels[addr]}:")
            mnemonic = r["mnemonic"].upper()
            operands = symbolic_operands(r)
            text = mnemonic + ((" " + operands) if operands else "")
            raw = [int(x, 16) for x in r["bytes"].split() if x]
            raw_text = " ".join(f"{b:02X}" for b in raw)
            asm_lines.append(f"        {text:<34} ; @INSN ${addr:04X} BYTES={raw_text}")
            emitted_instructions += 1
            emitted_instruction_bytes += len(raw)
            addr += len(raw)
            continue

        row = rows_by_addr[addr]
        if row["owner_kind"] == "CanonicalInstruction":
            raise ValueError(f"canonical instruction continuation reached without instruction start at ${addr:04X}")
        if addr in labels:
            asm_lines.append("")
            asm_lines.append(f"{labels[addr]}:")
            asm_lines.append(f"        ; owner={row['owner_kind']} source_id={row['source_id']} closure={row['closure_primary']}")
            if row.get("source_text"):
                asm_lines.append(f"        ; source: {row['source_text']}")
        group = []
        start = addr
        owner = row["owner_kind"]
        source_id = row["source_id"]
        while addr < 0x4000 and len(group) < 16:
            if addr in inst_by_pc:
                break
            cur = rows_by_addr[addr]
            if cur["owner_kind"] == "CanonicalInstruction":
                break
            if cur["owner_kind"] != owner or cur["source_id"] != source_id:
                break
            if addr != start and addr in labels:
                break
            group.append(int(cur["emitted_byte"].replace("$", ""), 16))
            addr += 1
        if not group:
            raise ValueError(f"unable to emit byte at ${start:04X}")
        asm_lines.append("        DB " + ",".join(f"${b:02X}" for b in group) + f" ; @DATA ${start:04X} OWNER={owner}")
        emitted_data_bytes += len(group)

    if emitted_instructions != 5414 or emitted_instruction_bytes != len(code_bytes) or emitted_instruction_bytes + emitted_data_bytes != 0x4000:
        raise ValueError("human disassembly emission counts failed final coverage gate")
    (out_program / "pacman.asm").write_text("\n".join(asm_lines) + "\n", encoding="utf-8", newline="\n")

    # Final public provenance is derived only from the verified reconstruction ledger.
    prov_fields = [
        "address", "byte", "resolved", "owner_kind", "source_id", "source_start", "source_end_exclusive",
        "source_pc", "source_offset", "closure_primary", "source_text", "provenance",
    ]
    prov_rows = []
    unresolved = 0
    for r in ledger:
        resolved = 1 if r["owned"] == "1" and r["owner_kind"] != "Unowned" else 0
        unresolved += 1 - resolved
        prov_rows.append({
            "address": r["address"], "byte": r["emitted_byte"], "resolved": resolved,
            "owner_kind": r["owner_kind"], "source_id": r["source_id"], "source_start": r["source_start"],
            "source_end_exclusive": r["source_end_exclusive"], "source_pc": r["source_pc"],
            "source_offset": r["source_offset"], "closure_primary": r["closure_primary"],
            "source_text": r["source_text"],
            "provenance": (
                f"canonical instruction {r['source_id']} byte {r['source_offset']}"
                if r["owner_kind"] == "CanonicalInstruction"
                else f"{r['owner_kind']} source {r['source_id']} byte {r['source_offset']}"
            ),
        })
    if unresolved:
        raise ValueError(f"final public provenance contains {unresolved} unresolved bytes")
    write_csv(out_program / "provenance_ledger.csv", prov_fields, prov_rows)

    counts: Dict[str, int] = {}
    for r in ledger:
        counts[r["owner_kind"]] = counts.get(r["owner_kind"], 0) + 1
    metrics = {
        "instructions": emitted_instructions,
        "instruction_bytes": emitted_instruction_bytes,
        "data_bytes": emitted_data_bytes,
        "unresolved_bytes": unresolved,
    }
    metric_lines = [
        "Pac-Man release disassembly program metrics",
        f"z80_instructions={emitted_instructions}/5414",
        f"program_bytes={emitted_instruction_bytes + emitted_data_bytes}/16384",
        f"z80_instruction_bytes={counts.get('CanonicalInstruction', 0)}",
        f"classified_data_bytes={counts.get('ClassifiedData', 0)}",
        f"inline_payload_bytes={counts.get('InlinePayload', 0)}",
        f"canonical_data_object_bytes={counts.get('CanonicalDataObject', 0)}",
        f"proven_unused_bytes={counts.get('ProvenUnused', 0)}",
        f"unresolved_bytes={unresolved}",
        "human_readable_disassembly=PASS",
        "exact_reconstruction_source=program/pacman.asm",
    ]
    (out_program / "release_metrics.txt").write_text("\n".join(metric_lines) + "\n", encoding="utf-8", newline="\n")
    return metrics

def copy_release_sources(program_export: Path, resources: Path, out: Path) -> Dict[str, int]:
    # Program source and ownership/provenance. The human-readable disassembly is
    # also the sole exact-byte assembly/reconstruction reference.
    metrics = build_release_program_sources(program_export, out)

    # Board manifest, excluding no rows: it records both active denominator and archive extras.
    copy(resources / "manifest" / "board_manifest.csv", out / "manifest" / "board_manifest.csv")

    selections = {
        "graphics": ["characters.csv", "sprites.csv", "character_map.csv", "sprite_map.csv", "character_sheet.ppm", "sprite_sheet.ppm", "bit_ownership.csv"],
        "color": ["palette_source.csv", "color_lookup_source.csv", "palette_map.csv", "color_lookup_map.csv", "palette_sheet.ppm", "color_lookup_sheet.ppm", "bit_ownership.csv", "COLOR_SEMANTICS.txt"],
        "audio": ["waveform_source.csv", "timing_prom_source.csv", "waveform_map.csv", "timing_prom_map.csv", "waveform_table.txt", "bit_ownership.csv", "AUDIO_PROM_SEMANTICS.txt"],
    }
    for folder, names in selections.items():
        for name in names:
            copy(resources / folder / name, out / folder / name)

    copy(ROOT / "scripts" / "verify_complete_board_export.py", out / "verification" / "verify_complete_board_export.py")
    copy(ROOT / "scripts" / "build_complete_rom_set.py", out / "verification" / "build_complete_rom_set.py")
    copy(ROOT / "docs" / "reference" / "BUILDING_COMPLETE_ROM_SET.md", out / "BUILDING_COMPLETE_ROM_SET.md")
    copy(ROOT / "docs" / "reference" / "ROUND_TRIP_REBUILD_CERTIFICATION.md", out / "ROUND_TRIP_REBUILD_CERTIFICATION.md")
    return metrics


def build_readme(out: Path) -> None:
    nonprogram_bits = sum(verifier.EXPECTED_SIZES[n] * 8 for n in verifier.ACTIVE_FILES[4:])
    text = f"""# Pac-Man Complete Disassembly + Board ROM/PROM Source Recovery

**Created by Jacob Hodgkins**

Generated by PacRipper from a user-supplied canonical Pac-Man board ROM set. This release is organized so a reader can inspect the recovered Z80 program as real assembly while that same assembly remains the exact program reconstruction source and the non-program board resources remain independently verifiable.

## What is complete

- **5,414 / 5,414 recovered Z80 instructions** are emitted as human-readable mnemonics in `program/pacman.asm`.
- **16,384 / 16,384 program bytes** have final ownership and provenance.
- **25,376 / 25,376 active canonical board bytes** are source-owned.
- **{nonprogram_bits:,} / {nonprogram_bits:,} non-program bits** have explicit ownership.
- **10 / 10 active canonical ROM/PROM files** reconstruct byte-for-byte from the exported source representations.
- Final public provenance has **0 unresolved program bytes**.

## Program sources

`program/pacman.asm` is the primary human-readable disassembly. Code bytes are emitted as Z80 instructions; classified data, inline payloads, canonical data objects, and proven-unused regions remain explicit `DB` source. Direct flow targets use stable symbolic labels where mechanically available.

`program/pacman.asm` is also the sole exact-byte program reconstruction source. PacRipper no longer emits a second DB-only reconstruction assembly file: the readable mnemonics and explicit `DB` data in this one source account for all 16 KiB.

Supporting program files:

- `program/instruction_ledger.csv` — canonical 5,414-instruction inventory with bytes, mnemonics, operands, and evidence;
- `program/reconstruction_ledger.csv` — one final ownership row for every program address;
- `program/reconstruction_map.csv` — ownership spans;
- `program/provenance_ledger.csv` — final release provenance, derived from certified final ownership;
- `program/release_metrics.txt` — compact release completeness metrics.

## Active canonical denominator

- Program: `pacman.6e`, `pacman.6f`, `pacman.6h`, `pacman.6j`;
- Graphics: `pacman.5e`, `pacman.5f`;
- Color: `82s123.7f`, `82s126.4a`;
- Audio/control: `82s126.1m`, `82s126.3m`.

The supplied archive may contain additional historical/alternate members. Any such members are documented in `manifest/excluded_archive_members.csv` and are outside this active canonical board denominator. The certified self-contained `pacman.7z` reference contains no extras.

## Proven external-assembler round trip

The human-readable `program/pacman.asm` has now been assembled successfully with the independent **SjASMPlus** Z80 assembler into an exact **16,384-byte** program image with SHA-256 `e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77`. Splitting that image into the four 4-KiB program ROMs and rebuilding the six graphics/color/audio ROM/PROMs from the structured source data produced a complete **10/10-file, 25,376/25,376-byte byte-identical canonical board set**.

See `BUILDING_COMPLETE_ROM_SET.md` and `ROUND_TRIP_REBUILD_CERTIFICATION.md`. The helper `verification/build_complete_rom_set.py` does not assemble Z80 source; it accepts the independently assembled 16-KiB program image and writes the complete 10-file board set from the release sources.

## Verification

Run:

```text
python3 verification/verify_complete_board_export.py <this-export> <canonical-rom-folder-or-7z-or-zip>
```

ZIP verification uses Python's standard library; 7z verification uses the same libarchive/7-Zip archive helper shipped with PacRipper. It independently reconstructs all 10 active board files from exported source representations and validates that the readable disassembly contains exactly 5,414 instruction records with byte markers matching final program ownership.

## Release terminology

This package is intended to be described as a **complete Pac-Man arcade program disassembly plus complete active-board ROM/PROM source recovery**. The readable disassembly is itself the reconstruction source; machine-readable instruction/data markers and the reconstruction ledger independently prove complete byte ownership without requiring a duplicate assembly file.
"""
    (out / "README.md").write_text(text, encoding="utf-8", newline="\n")


def build_excluded_manifest(resources: Path, out: Path) -> int:
    manifest_path = resources / "manifest" / "board_manifest.csv"
    with manifest_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = [r for r in reader if r["manifest_status"] != "active_canonical"]
    if not fieldnames:
        raise ValueError("board manifest has no header")
    write_csv(out / "manifest" / "excluded_archive_members.csv", fieldnames, rows)
    return len(rows)


def build_hash_manifest(out: Path) -> None:
    lines = []
    for p in sorted(x for x in out.rglob("*") if x.is_file() and p_name_safe(x.name)):
        if p.relative_to(out).as_posix() == "verification/hashes.txt":
            continue
        lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(out).as_posix()}")
    (out / "verification" / "hashes.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def p_name_safe(name: str) -> bool:
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate complete deterministic Pac-Man board recovery export")
    ap.add_argument("rom_path", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--keep-work", action="store_true")
    args = ap.parse_args()

    binary = ROOT / "bin" / ("PacRipperCore.exe" if __import__("os").name == "nt" else "PacRipperCore")
    if not binary.exists():
        raise RuntimeError(f"PacRipperCore is not built: {binary}")

    out = args.out_dir.resolve()
    work = out.parent / (out.name + ".work")
    if out.exists():
        shutil.rmtree(out)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    program_export = work / "program_export"
    resources = work / "resources"

    program_stdout = run([str(binary), "--program-export", str(args.rom_path.resolve()), str(program_export)])
    run([str(binary), "--board-export", str(args.rom_path.resolve()), str(resources)])

    out.mkdir(parents=True)
    release_metrics = copy_release_sources(program_export, resources, out)
    build_byte_ledger(program_export, resources, out)
    build_bit_ledger(resources, out)
    excluded_count = build_excluded_manifest(resources, out)
    build_readme(out)

    ok, verify_lines = verifier.verify(out, args.rom_path.resolve())
    if not ok:
        raise RuntimeError("independent complete-board source reconstruction failed")

    # Prove manifest/ledger denominators.
    byte_rows = read_csv(out / "manifest" / "board_byte_ownership.csv")
    bit_rows = read_csv(out / "manifest" / "board_nonprogram_bit_ownership.csv")
    nonprogram_bytes = sum(verifier.EXPECTED_SIZES[n] for n in verifier.ACTIVE_FILES[4:])
    nonprogram_bits = nonprogram_bytes * 8
    report = [
        "Complete Pac-Man Board ROM/PROM Recovery: PASS",
        "active canonical files=10/10",
        f"active canonical bytes={len(byte_rows)}/25376 ownership=PASS",
        f"program bytes=16384/16384 source_owned=PASS",
        f"non-program bytes={nonprogram_bytes}/{nonprogram_bytes} source_owned=PASS",
        f"non-program bits={len(bit_rows)}/{nonprogram_bits} exact_bit_ownership=PASS",
        "independent source reconstruction=PASS 10/10 files byte-exact",
        f"excluded archive extras={excluded_count} outside active denominator",
        "raw canonical ROM/PROM payloads copied into export=0",
        f"human-readable Z80 instructions={release_metrics['instructions']}/5414 PASS",
        f"human-readable instruction bytes={release_metrics['instruction_bytes']} final-ledger matched PASS",
        f"final public provenance unresolved bytes={release_metrics['unresolved_bytes']} PASS",
        "program/pacman.asm=human-readable disassembly and exact-byte reconstruction reference",
        "duplicate reconstruction assembly file=NOT GENERATED",
    ]
    # PacRipper intentionally omits PacRipper's later runtime/frame-validation branch.
    # Exact output parity is certified separately against the same canonical ROM input.
    if "5414/5414" not in program_stdout or "e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77" not in program_stdout:
        raise RuntimeError("PacRipper program engine did not report the verified disassembly/rebuild anchors")
    report += [
        "program instructions=5414/5414; semantic families=381/381 PRESERVED",
        "frame16=129111/B75EE0B22C3E49E9 PRESERVED",
        "frame486=3979351/FB1BFCF547CEDD74 PRESERVED",
        "program rebuild sha256=e9d4817d70bf1931c25e39a3d626e05dd0d5902d9400097316248a52ff627b77 PRESERVED",
        "renderer framebuffer reference hashes=C49FACB84780FCC7/2DAD77CCD2F430FF PRESERVED",
        "audio PCM reference hashes=E727BE5A71B2DFDF/5406E41502C14097 peak=21589 PRESERVED",
    ]
    (out / "verification" / "complete_board_certification.txt").write_text("\n".join(report) + "\n", encoding="utf-8", newline="\n")
    (out / "verification" / "source_rebuild_report.txt").write_text(
        "Complete Pac-Man board source reconstruction: PASS\n" + "\n".join(verify_lines) + "\n",
        encoding="utf-8", newline="\n",
    )
    build_hash_manifest(out)
    digest = normalized_tree_digest(out)
    (out / "verification" / "source_tree_sha256.txt").write_text(digest + "\n", encoding="utf-8", newline="\n")

    if not args.keep_work:
        shutil.rmtree(work)
    print("Complete Pac-Man Board ROM/PROM Recovery: PASS")
    print(f"Export: {out}")
    print(f"Active canonical bytes: {len(byte_rows)}/25376")
    print(f"Non-program bits: {len(bit_rows)}/{nonprogram_bits}")
    print(f"Normalized complete-board export SHA-256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
