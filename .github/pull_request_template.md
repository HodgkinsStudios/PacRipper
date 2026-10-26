## Summary

Describe the change and why it is needed.

## Release-safety checklist

- [ ] `make release-check` passes.
- [ ] I did not add ROM/PROM payloads, generated complete disassemblies, reconstructed ROM files, or copyrighted test fixtures.
- [ ] Archive/output safety protections remain fail-closed.
- [ ] If reconstruction or a supported profile changed, I independently tested both certified variants locally with user-supplied references.
- [ ] If reconstruction or a supported profile changed, I reran `scripts/strict_rom_free_audit.py` against both external canonical references.
- [ ] Documentation and `CHANGELOG.md` were updated when user-visible behavior changed.

## Testing

List the tests/builds performed. Do not attach copyrighted ROM data or generated full source trees.
