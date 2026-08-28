# Contributing to tc-putty-sftp

Thank you for helping improve the plugin. This is a security-sensitive Windows
project: changes to SSH transport, host-key handling, registry import, and
private-key parsing require extra care.

## Before opening an issue

- Search existing issues first.
- Use the bug or feature form instead of a blank issue.
- Remove hostnames, usernames, IP addresses, private-key paths, fingerprints,
  and other identifying data from logs and screenshots.
- Never attach a real PPK, PEM, OpenSSH private key, password, or access token.
- Report suspected vulnerabilities through GitHub private vulnerability
  reporting, not through a public issue.

## Development workflow

1. Fork the repository and clone it with submodules:

   ```powershell
   git clone --recurse-submodules https://github.com/<you>/tc-putty-sftp.git
   cd tc-putty-sftp
   ```

2. Create a focused branch such as `fix/session-decoding` or
   `feature/encrypted-ppk`.
3. Keep the change small and avoid unrelated formatting.
4. Build and run the local checks:

   ```powershell
   pwsh -NoProfile -File .\bin\release.ps1 -Configuration Release -Version dev
   pwsh -NoProfile -File .\bin\build-tests.ps1
   pwsh -NoProfile -File .\bin\test.ps1
   ```

5. Open a pull request and complete its checklist.

Requirements are Windows, Visual Studio 2026 with Desktop development with
C++, CMake, Git, and PowerShell 7.

## Test expectations

- Build both Win32 and x64 Release configurations.
- Keep the ordinary INI connection path working.
- Add a regression test for parser, registry, and collision-handling changes.
- Use only synthetic, explicitly test-only key material in committed tests.
- Do not add CI secrets or network tests that depend on a private server.
- Network test modes require a host key that the tester has independently
  validated. They are never a replacement for host-key verification.

## Pull requests

A pull request should explain the problem, the chosen approach, security
impact, and verification performed. Maintainers may request a narrower change
or decline work that is outside the current project scope.

By submitting a contribution, you agree that it is licensed under the
repository's MIT License and that you have the right to contribute it.
