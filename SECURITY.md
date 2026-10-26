# Security Policy

PacRipper parses user-supplied ZIP and 7z archives, so malformed archive handling is considered a security-sensitive part of the project.

## Supported release

Security fixes are maintained for the current public 1.0 release line.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than publishing a working exploit first. If PacRipper is hosted on a platform with private security-advisory reporting (for example, a repository security-advisory feature), use that channel. Include the affected PacRipper version, operating system, minimal reproduction steps, and a harmless test archive when possible.

Particularly useful reports include archive path traversal, symlink/reparse-point issues, decompression/resource-exhaustion bypasses, unsafe output replacement, command execution, or cases where ROM data is unintentionally included in the PacRipper distribution.

Do not include copyrighted ROM payloads in a public issue. Hashes and minimal synthetic test cases are preferred.
