## Summary

Describe the problem and the change. Keep the pull request focused.

## Security impact

Describe any effect on SSH transport, authentication, host-key verification,
registry handling, logging, or private-key memory/file handling. Write `None`
when the change has no security impact.

## Verification

- [ ] Win32 Release builds
- [ ] x64 Release builds
- [ ] `bin/test.ps1` passes without network credentials
- [ ] Relevant regression tests were added or updated
- [ ] No real keys, credentials, hostnames, fingerprints, or private logs were committed
- [ ] Documentation and `CHANGELOG.md` were updated when behavior changed

## Additional notes

Add screenshots, sanitized logs, or compatibility notes when useful.
