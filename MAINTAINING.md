# Maintainer guide

This project is intentionally small and security-sensitive. The goal is to
keep `main` releasable, make changes reviewable, and avoid collecting user
secrets while diagnosing SSH problems.

## Routine

Check new issues and pull requests when convenient; there is no support SLA.
Apply `needs-triage` until an item has a clear outcome, then add the most
specific label available. Close duplicates with a link to the canonical item.
Use `blocked` only when a concrete dependency or decision prevents progress.

Keep discussion in the issue or pull request so decisions remain discoverable.
Do not move ordinary support to private messages. Security reports are the
exception and belong in GitHub private vulnerability reporting.

## Reviewing an external pull request

1. Confirm that the change has a focused issue or a clear problem statement.
2. Inspect the entire diff, including generated files, workflows, submodule
   revisions, build scripts, and binary-looking additions.
3. Reject real keys, credentials, hostnames, fingerprints, unsanitized logs,
   or test code that connects to a contributor's private server.
4. Treat PPK parsing, host-key handling, authentication, logging, registry
   access, and GitHub Actions as security-sensitive code.
5. Require a regression test for observable behavior whenever practical.
6. Wait for the protected `Build and test` check on the current `main` base.
7. Resolve every review conversation, then use **Squash and merge**.

Do not download and run an arbitrary executable supplied in an issue. Build
source changes in the repository workflow or in an isolated environment.
A green workflow proves that the configured checks passed; it does not replace
reading a security-sensitive diff.

## Dependency updates

- Dependabot groups GitHub Actions updates into one weekly pull request and
  checks the libssh2 submodule monthly.
- Review release notes and the actual revision diff before merging.
- Do not auto-merge major versions or libssh2 changes.
- Keep every GitHub Action pinned to a full 40-character commit SHA. The
  repository setting enforces this policy.
- Run the ordinary CI after rebasing an update onto the latest `main`.
- For libssh2, confirm WinCNG support, the exported in-memory authentication
  API, upstream security fixes, license notices, and x86/x64 packaging.

## Releasing

1. Move completed user-visible entries from `Unreleased` in `CHANGELOG.md`
   into a dated version section.
2. Open a release-preparation pull request and wait for the protected CI check.
3. Create an annotated SemVer tag on the final `main` commit:

   ```powershell
   git switch main
   git pull --ff-only
   git tag -a v0.2.0 -m "tc-putty-sftp 0.2.0"
   git push origin v0.2.0
   ```

4. The Release workflow rebuilds x86/x64 from the tag and publishes the ZIP
   plus its SHA-256 file. Versions below 1.0 are marked as pre-releases.
5. Download both published assets, verify the checksum, inspect the ZIP, and
   perform an installation smoke test in Total Commander.
6. Edit the generated GitHub release notes so highlights, limitations, and
   upgrade guidance are useful to users.

Do not move or reuse a published tag. If a release is wrong, document it, fix
forward on a branch, and publish a new patch version.

## Security reports

Keep a report private until impact and remediation are understood. Reproduce
with synthetic data, establish affected versions, prepare a fix and regression
test in the private advisory fork when appropriate, and agree on disclosure
timing with the reporter. Rotate any credential that is accidentally exposed;
deleting it from Git history is not sufficient.

## Upstream changes

The configured `upstream` remote tracks the maintained SFTP plugin mirror; see
`UPSTREAM.md` for provenance. Review upstream changes on a separate branch.
Do not overwrite the PuTTY session provider, PPK adapter, host-key behavior,
or pinned libssh2 revision with an unreviewed bulk merge. Preserve upstream
license and third-party notices.

## GitHub Pages

A project site is optional. The README and Releases page are currently the
canonical documentation and download location. Add GitHub Pages when there are
stable screenshots, a longer user guide, or enough releases to justify a
separate landing page. If a site is added, generate it from repository content
and link to GitHub Releases instead of copying binaries or maintaining a second
set of feature claims.

## If the community grows

Add another trusted maintainer before increasing the required review count.
At that point, require one approving CODEOWNER review, publish a code of
conduct with a monitored contact address, and document who can triage issues,
merge code, handle advisories, and publish releases.
