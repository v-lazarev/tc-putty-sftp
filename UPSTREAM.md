# Upstream provenance

This repository is not an official Total Commander or PuTTY project.

- Original SFTP plugin: Christian Ghisler, SFTP 3.10 source snapshot,
  published 2026-07-06 at https://www.ghisler.com/plugins.htm
- Git mirror used for reproducible history:
  https://github.com/klodoma/totalcmd-plugin-sftp
- Exact original snapshot tag: `3.10.0`, commit
  `bcc7d1638474e1f8d78f2342bdcd37e18aa1b100`
- Maintained mirror baseline: `3.21.0`, commit
  `b2da7560904366c2cb2822de8018d779c9fe261c`
- libssh2 source is pinned as a Git submodule. The selected commit is recorded
  by the parent repository and is built with the Windows CNG backend.

The official `sftpplug_src.zip` download was also used as the authority for
the 3.10 release announcement and security baseline. The Git mirror retains
the 3.10 snapshot as an ancestor and adds build-system maintenance.
