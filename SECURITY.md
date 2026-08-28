# Security Policy

## Supported versions

Security fixes are provided on a best-effort basis for the latest published
0.x release and the current `main` branch. Older builds should be upgraded
before a report is investigated.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting:

https://github.com/v-lazarev/tc-putty-sftp/security/advisories/new

Do not open a public issue for a suspected vulnerability. Include the affected
version, impact, reproduction steps, and a minimal proof of concept when safe.
Do not send real private keys, passwords, access tokens, production hostnames,
or personal data. Synthetic test keys are preferred.

Reports and fixes are handled on a best-effort basis with no support SLA. A
coordinated disclosure date will be agreed before details are made public.

## Security scope

The project handles SSH credentials and host-key decisions. Relevant reports
include private-key disclosure, authentication bypass, host-key verification
failures, unsafe temporary files, secret logging, memory-safety defects, and
malicious PuTTY session or PPK input.
