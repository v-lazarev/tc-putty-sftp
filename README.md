# tc-putty-sftp

[![CI](https://github.com/v-lazarev/tc-putty-sftp/actions/workflows/ci.yml/badge.svg)](https://github.com/v-lazarev/tc-putty-sftp/actions/workflows/ci.yml)
[![Release](https://github.com/v-lazarev/tc-putty-sftp/actions/workflows/release.yml/badge.svg)](https://github.com/v-lazarev/tc-putty-sftp/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](License.txt)

An experimental Total Commander WFX plugin that combines the current SFTP
transport with a live, read-only view of saved PuTTY sessions.

This is not an official Total Commander or PuTTY project. The implementation
is based on Christian Ghisler's SFTP plugin, with the maintained 3.21 mirror as
the code baseline and the original 3.10 snapshot retained in its history. See
`UPSTREAM.md` for exact commits.

## What works

- Saved SSH sessions from
  `HKCU\Software\SimonTatham\PuTTY\Sessions` appear in the plugin root.
- The list is refreshed whenever Total Commander refreshes the root.
- Existing INI connections remain available.
- PuTTY entries are read-only. Edit, rename, or delete them in PuTTY.
- Session name escaping, Unicode registry access, default settings, custom SSH
  ports, usernames, and private-key paths are imported.
- Pageant is disabled for generated PuTTY entries.
- Unencrypted PuTTY PPK v3 RSA keys are authenticated directly from memory.
  No converted private key or temporary PEM file is written to disk.
- Unsupported PPK versions, encryption, and key algorithms are identified
  before a network connection is opened, with bounded metadata-only checks.
- Host keys are stored as SHA-256 fingerprints. The normal plugin confirmation
  remains in place for first use and changed keys.

Name collisions are deterministic: a PuTTY entry receives a `[PuTTY]` suffix
when an INI connection already uses the same display name.

## Download

Use the latest package on the
[Releases page](https://github.com/v-lazarev/tc-putty-sftp/releases).
Versions below 1.0 are published as pre-releases while the compatibility
surface and key-format support are still intentionally narrow. Each ZIP is
accompanied by a SHA-256 checksum file.

## Security boundary of the MVP

The built-in PPK loader intentionally accepts only:

- `PuTTY-User-Key-File-3`
- `ssh-rsa`
- `Encryption: none`
- RSA keys from 2048 through 8192 bits

It validates the PPK HMAC-SHA-256, strictly parses SSH strings and positive
mpints, imports the key through Windows CNG, verifies it by signing, and clears
private working buffers after authentication. Private blobs, PEM data, and MAC
inputs are not logged. Connection-attempt logs record only whether key files
are configured; they do not include private- or public-key paths.

Encrypted PPK files, PPK v2, Ed25519, ECDSA, PuTTY proxy/jump settings, and
other PuTTY-specific connection commands are not yet imported. A session with
proxy settings is blocked instead of silently connecting directly. Existing
OpenSSH/PEM authentication for ordinary INI connections is unchanged.

## Install

1. Download or build `dist/sftpplug-<version>.zip`.
2. Open the ZIP in Total Commander and accept the WFX installation prompt.
3. Open **Network Neighborhood** and then **TC PuTTY SFTP** (or the name chosen
   during installation).
4. Refresh the root after adding or changing a PuTTY session.

The package contains separate x86/x64 WFX files and matching WinCNG
`libssh2.dll` files. Do not replace the x64 DLL with the root x86 DLL.

## Build

Requirements: Windows, Visual Studio 2026 with C++, CMake, and PowerShell 7.

```powershell
git clone --recurse-submodules <repository-url>
cd tc-putty-sftp
pwsh -NoProfile -File .\bin\release.ps1 -Configuration Release -Version 0.1.0
```

`bin/build-libssh2.ps1` pins the submodule revision and builds shared x86/x64
libssh2 with the Windows CNG backend. `bin/release.ps1` then builds both WFX
architectures, creates the release ZIP, and writes its SHA-256 checksum.

## Tests

`tests/smoke_tests.cpp` covers PuTTY name decoding, live registry enumeration,
INI overlay preservation, and optional PPK parsing/CNG conversion.
`tests/ppk_diagnostics_tests.cpp` generates an ephemeral TEST-ONLY RSA key at
runtime and checks valid LF/CRLF/CR PPK files plus unsupported, corrupted,
truncated, embedded-NUL, missing, empty, and oversized inputs.

`tests/wfx_root_smoke.cpp` loads the compiled WFX through the public Total
Commander API, enumerates its root, verifies the packaged transport, and can
perform an optional connection test. `tests/libssh2_ppk_integration.cpp`
isolates the transport/key path for diagnosis.

Network test modes deliberately require an explicit flag saying the server
host key was already validated with PuTTY. They must not be used as a general
replacement for host-key verification.

Build and run the offline test suite with:

```powershell
pwsh -NoProfile -File .\bin\build-tests.ps1
pwsh -NoProfile -File .\bin\test.ps1
```

The test runner creates a uniquely named, non-secret PuTTY registry session
and an isolated runtime directory, then removes both. GitHub Actions performs
the same x86/x64 build, package, and offline checks for every pull request.

## Contributing and support

Bug reports and small, focused improvements are welcome. Start with
[`CONTRIBUTING.md`](CONTRIBUTING.md), use the issue templates, and open a pull
request against `main`. Maintainer review is best-effort; there is no support
SLA.

Do not post private keys, passwords, host-key records, private hostnames, or
connection logs containing sensitive data. Report security issues privately
as described in [`SECURITY.md`](SECURITY.md).

User-visible changes are recorded in [`CHANGELOG.md`](CHANGELOG.md).
Repository-owner routines for reviews, dependency updates, releases, security
reports, upstream syncs, and a future GitHub Pages site are documented in
[`MAINTAINING.md`](MAINTAINING.md).

## License

The plugin code is MIT-licensed; see `License.txt`. libssh2 is BSD-3-Clause.
See `THIRD_PARTY_NOTICES.md` for provenance and notices.
