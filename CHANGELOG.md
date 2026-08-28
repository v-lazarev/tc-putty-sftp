# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
while it remains in the 0.x development series.

## [Unreleased]

## [0.1.0] - 2026-08-28

### Added

- Live, read-only PuTTY SSH sessions in the Total Commander plugin root.
- Default Settings fallback, Unicode session names, custom ports, usernames,
  private-key paths, and deterministic collision handling.
- Strict in-memory loader for unencrypted PPK v3 RSA keys from 2048 to 8192
  bits, including HMAC verification and Windows CNG validation.
- In-memory libssh2 public-key authentication without Pageant, puttygen, or
  temporary converted private-key files.
- SHA-256 host-key fingerprints and explicit blocking of unsupported PuTTY
  proxy configurations.
- Reproducible x86/x64 build, packaging, smoke, WFX, and integration harnesses.

[Unreleased]: https://github.com/v-lazarev/tc-putty-sftp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/v-lazarev/tc-putty-sftp/releases/tag/v0.1.0
