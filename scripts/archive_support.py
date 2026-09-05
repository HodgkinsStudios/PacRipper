#!/usr/bin/env python3
"""Safe, resource-bounded ROM archive helpers for PacRipper.
Created by Jacob Hodgkins.

ZIP support uses Python's standard library. 7z support uses the platform's
libarchive when available, with a command-line 7-Zip fallback. No ROM data is
stored by this module.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import shutil
import subprocess
import zipfile
from pathlib import Path, PurePosixPath

_SEVEN_Z_MAGIC = b"7z\xbc\xaf\x27\x1c"
_AE_IFMT = 0o170000
_AE_IFREG = 0o100000
_AE_IFDIR = 0o040000

# PacRipper's certified boards are only 25,376 bytes. These deliberately generous
# ceilings make malformed/hostile archives fail before they can consume meaningful
# memory while still leaving ample room for future metadata or closely related sets.
MAX_ARCHIVE_FILE_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 64
MAX_MEMBER_BYTES = 64 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 200.0


def _check_archive_file(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"input archive does not exist or is not a file: {path}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"unable to stat input archive: {path}") from exc
    if size > MAX_ARCHIVE_FILE_BYTES:
        raise ValueError(
            f"archive is too large ({size} bytes; maximum {MAX_ARCHIVE_FILE_BYTES})"
        )


def archive_kind(path: Path) -> str | None:
    if not path.is_file():
        return None
    _check_archive_file(path)
    if zipfile.is_zipfile(path):
        return "zip"
    try:
        with path.open("rb") as f:
            if f.read(6) == _SEVEN_Z_MAGIC:
                return "7z"
    except OSError:
        return None
    return None


def _safe_member_parts(name: str) -> tuple[str, ...]:
    member = PurePosixPath(name.replace("\\", "/"))
    if member.is_absolute() or not member.parts or any(part in ("", ".", "..") for part in member.parts):
        raise ValueError(f"unsafe archive member path: {name!r}")
    if len(member.parts[0]) >= 2 and member.parts[0][1] == ":":
        raise ValueError(f"unsafe archive member path: {name!r}")
    if member.parts[0].startswith("-"):
        raise ValueError(f"unsafe option-like archive member path: {name!r}")
    return tuple(member.parts)


def _check_duplicate(seen: set[str], parts: tuple[str, ...], original: str) -> None:
    key = "/".join(parts).casefold()
    if key in seen:
        raise ValueError(f"duplicate archive member path: {original!r}")
    seen.add(key)


def _check_member_count(count: int) -> None:
    if count > MAX_ARCHIVE_MEMBERS:
        raise ValueError(
            f"archive contains too many files ({count}; maximum {MAX_ARCHIVE_MEMBERS})"
        )


def _check_declared_size(name: str, size: int, running_total: int) -> None:
    if size < 0:
        raise ValueError(f"archive member has invalid size: {name!r}")
    if size > MAX_MEMBER_BYTES:
        raise ValueError(
            f"archive member is too large: {name!r} ({size} bytes; maximum {MAX_MEMBER_BYTES})"
        )
    if running_total + size > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise ValueError(
            "archive expands beyond PacRipper's safety limit "
            f"({MAX_TOTAL_UNCOMPRESSED_BYTES} bytes total)"
        )


def _zip_members(path: Path) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    total = 0
    with zipfile.ZipFile(path, "r") as zf:
        regular = [info for info in zf.infolist() if not info.is_dir()]
        _check_member_count(len(regular))
        for info in regular:
            parts = _safe_member_parts(info.filename)
            _check_duplicate(seen, parts, info.filename)
            _check_declared_size(info.filename, int(info.file_size), total)
            if info.file_size >= 1024 and info.compress_size == 0:
                raise ValueError(f"invalid compressed size for archive member: {info.filename!r}")
            if info.file_size >= 4096 and info.compress_size > 0:
                ratio = info.file_size / info.compress_size
                if ratio > MAX_ZIP_COMPRESSION_RATIO:
                    raise ValueError(
                        f"archive member compression ratio is unsafe: {info.filename!r} ({ratio:.1f}:1)"
                    )
            chunks: list[bytes] = []
            read_size = 0
            with zf.open(info, "r") as src:
                while True:
                    chunk = src.read(min(8192, MAX_MEMBER_BYTES - read_size + 1))
                    if not chunk:
                        break
                    read_size += len(chunk)
                    if read_size > MAX_MEMBER_BYTES:
                        raise ValueError(f"archive member exceeds safety limit while reading: {info.filename!r}")
                    chunks.append(chunk)
            if read_size != info.file_size:
                raise ValueError(f"archive member size changed while reading: {info.filename!r}")
            total += read_size
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise ValueError("archive expands beyond PacRipper's total safety limit")
            out.append(("/".join(parts), b"".join(chunks)))
    return out


def _load_libarchive():
    candidates: list[str] = []
    found = ctypes.util.find_library("archive")
    if found:
        candidates.append(found)
    if os.name == "nt":
        candidates += ["archive.dll", "libarchive.dll"]
    elif sys_platform_is_macos():
        candidates += ["libarchive.dylib"]
    else:
        candidates += ["libarchive.so.13", "libarchive.so"]
    for name in candidates:
        try:
            return ctypes.CDLL(name)
        except OSError:
            pass
    return None


def sys_platform_is_macos() -> bool:
    import sys
    return sys.platform == "darwin"


def _libarchive_7z_members(path: Path) -> list[tuple[str, bytes]] | None:
    lib = _load_libarchive()
    if lib is None:
        return None

    lib.archive_read_new.restype = ctypes.c_void_p
    lib.archive_read_support_filter_all.argtypes = [ctypes.c_void_p]
    lib.archive_read_support_format_7zip.argtypes = [ctypes.c_void_p]
    lib.archive_read_open_filename.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.archive_read_open_filename.restype = ctypes.c_int
    lib.archive_read_next_header.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    lib.archive_read_next_header.restype = ctypes.c_int
    lib.archive_entry_pathname.argtypes = [ctypes.c_void_p]
    lib.archive_entry_pathname.restype = ctypes.c_char_p
    lib.archive_entry_filetype.argtypes = [ctypes.c_void_p]
    lib.archive_entry_filetype.restype = ctypes.c_uint
    lib.archive_entry_size.argtypes = [ctypes.c_void_p]
    lib.archive_entry_size.restype = ctypes.c_longlong
    lib.archive_read_data.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    lib.archive_read_data.restype = ctypes.c_ssize_t
    lib.archive_error_string.argtypes = [ctypes.c_void_p]
    lib.archive_error_string.restype = ctypes.c_char_p
    lib.archive_read_free.argtypes = [ctypes.c_void_p]
    lib.archive_read_free.restype = ctypes.c_int

    ar = lib.archive_read_new()
    if not ar:
        raise RuntimeError("libarchive could not allocate a reader")
    try:
        lib.archive_read_support_filter_all(ar)
        lib.archive_read_support_format_7zip(ar)
        rc = lib.archive_read_open_filename(ar, os.fsencode(str(path)), 10240)
        if rc != 0:
            msg = lib.archive_error_string(ar)
            raise ValueError(f"unable to open 7z archive: {(msg or b'unknown libarchive error').decode(errors='replace')}")
        out: list[tuple[str, bytes]] = []
        seen: set[str] = set()
        total = 0
        entry = ctypes.c_void_p()
        while True:
            rc = lib.archive_read_next_header(ar, ctypes.byref(entry))
            if rc == 1:
                break
            if rc < 0:
                msg = lib.archive_error_string(ar)
                raise ValueError(f"unable to read 7z archive: {(msg or b'unknown libarchive error').decode(errors='replace')}")
            raw_name = lib.archive_entry_pathname(entry)
            if not raw_name:
                raise ValueError("7z archive contains an unnamed member")
            name = os.fsdecode(raw_name)
            parts = _safe_member_parts(name)
            filetype = int(lib.archive_entry_filetype(entry)) & _AE_IFMT
            if filetype == _AE_IFDIR:
                continue
            if filetype != _AE_IFREG:
                raise ValueError(f"unsupported non-regular 7z member: {name!r}")
            _check_member_count(len(out) + 1)
            _check_duplicate(seen, parts, name)
            declared = int(lib.archive_entry_size(entry))
            if declared >= 0:
                _check_declared_size(name, declared, total)
            chunks: list[bytes] = []
            member_size = 0
            buf = ctypes.create_string_buffer(8192)
            while True:
                n = lib.archive_read_data(ar, buf, len(buf))
                if n == 0:
                    break
                if n < 0:
                    msg = lib.archive_error_string(ar)
                    raise ValueError(f"unable to read 7z member {name!r}: {(msg or b'libarchive read error').decode(errors='replace')}")
                member_size += int(n)
                if member_size > MAX_MEMBER_BYTES:
                    raise ValueError(f"7z member exceeds safety limit while reading: {name!r}")
                if total + member_size > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise ValueError("7z archive expands beyond PacRipper's total safety limit")
                chunks.append(buf.raw[:n])
            if declared >= 0 and member_size != declared:
                raise ValueError(f"7z member size changed while reading: {name!r}")
            total += member_size
            out.append(("/".join(parts), b"".join(chunks)))
        return out
    finally:
        lib.archive_read_free(ar)


def _find_7z_executable() -> str | None:
    for name in ("7zz", "7z", "7zr"):
        found = shutil.which(name)
        if found:
            return found
    if os.name == "nt":
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "7-Zip" / "7z.exe",
        ]
        for p in candidates:
            if p.is_file():
                return str(p)
    return None


def _run_7z_member_limited(exe: str, path: Path, name: str) -> bytes:
    proc = subprocess.Popen(
        [exe, "x", "-so", str(path), name], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert proc.stdout is not None
    data = bytearray()
    try:
        while True:
            chunk = proc.stdout.read(8192)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MAX_MEMBER_BYTES:
                proc.kill()
                proc.wait()
                raise ValueError(f"7z member exceeds safety limit while reading: {name!r}")
        _, stderr = proc.communicate()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    if proc.returncode != 0:
        raise ValueError(f"unable to read 7z member {name!r}: {stderr.decode(errors='replace').strip()}")
    return bytes(data)


def _external_7z_members(path: Path) -> list[tuple[str, bytes]]:
    exe = _find_7z_executable()
    if not exe:
        raise RuntimeError(
            "7z input requires either libarchive support or 7-Zip (7z/7zz) installed. "
            "ZIP input remains dependency-free."
        )
    listing = subprocess.run(
        [exe, "l", "-slt", "-ba", str(path)], capture_output=True, text=True, errors="replace"
    )
    if listing.returncode != 0:
        raise ValueError("unable to list 7z archive: " + (listing.stderr.strip() or listing.stdout.strip()))

    entries: list[tuple[str, int | None]] = []
    current: dict[str, str] = {}
    for line in listing.stdout.splitlines() + [""]:
        if not line.strip():
            if current.get("Path") and current.get("Folder", "-") != "+":
                size_text = current.get("Size", "")
                size = int(size_text) if size_text.isdigit() else None
                entries.append((current["Path"], size))
            current = {}
            continue
        if " = " in line:
            key, value = line.split(" = ", 1)
            current[key.strip()] = value

    _check_member_count(len(entries))
    out: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    total = 0
    for name, declared in entries:
        parts = _safe_member_parts(name)
        _check_duplicate(seen, parts, name)
        if declared is not None:
            _check_declared_size(name, declared, total)
        data = _run_7z_member_limited(exe, path, name)
        if declared is not None and len(data) != declared:
            raise ValueError(f"7z member size changed while reading: {name!r}")
        total += len(data)
        if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise ValueError("7z archive expands beyond PacRipper's total safety limit")
        out.append(("/".join(parts), data))
    return out


def read_archive_members(path: Path) -> list[tuple[str, bytes]]:
    _check_archive_file(path)
    kind = archive_kind(path)
    if kind == "zip":
        return _zip_members(path)
    if kind == "7z":
        members = _libarchive_7z_members(path)
        return members if members is not None else _external_7z_members(path)
    raise ValueError(f"input is not a readable ZIP or 7z archive: {path}")


def safe_extract_archive(path: Path, destination: Path) -> None:
    members = read_archive_members(path)
    destination.mkdir(parents=True, exist_ok=True)
    for name, data in members:
        parts = _safe_member_parts(name)
        target = destination.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
