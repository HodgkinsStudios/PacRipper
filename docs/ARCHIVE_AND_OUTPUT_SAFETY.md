# Archive and Output Safety — PacRipper V1.0

**Created by Jacob Hodgkins**

PacRipper treats user-supplied ZIP/7z files as untrusted input.

## Archive protections

The public archive reader rejects:

- absolute paths, `..` traversal, Windows drive-path members, and malformed member names;
- case-insensitive duplicate member paths;
- non-regular 7z members;
- input archives larger than 16 MiB;
- more than 64 regular members;
- any decompressed member larger than 64 KiB;
- more than 1 MiB total decompressed member data;
- ZIP members of at least 4 KiB whose declared compression ratio exceeds 200:1.

Size limits are enforced while reading, not only after a member has already been decompressed into memory. These ceilings are intentionally much larger than either certified 25,376-byte board set.

Run the synthetic safety regression:

```bash
python3 scripts/test_archive_safety.py
```

No copyrighted ROM data is used by that test.

## Output replacement protections

PacRipper never silently replaces an existing destination. Existing output requires explicit `--force`.

Even with `--force`, PacRipper always refuses:

- filesystem roots;
- the user's home directory itself;
- PacRipper's application directory or any ancestor that would delete it;
- the current working directory or any ancestor that would delete it;
- symbolic-link output destinations;
- any output destination that contains the input ROM archive.

Output is staged on the destination filesystem and moved into place only after generation and verification succeed.
