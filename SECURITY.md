# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not in public issues.

- Preferred: enable and use GitHub's **private vulnerability reporting** for
  this repository (Settings → Code security → Private vulnerability reporting),
  then use the "Report a vulnerability" button on the Security tab.
- Alternatively, contact the maintainer directly (see the repository profile).

Please do **not** include private keys, secrets, or confidential hostnames in
any report. A redacted description is enough to get started.

## Scope note

certflow (Phase 0) is a read-only tool. It does not require, generate, or store
private keys, and it does not write to remote systems. If you find behavior
that contradicts this, that itself is a security issue worth reporting.

## Supported versions

This project is pre-1.0. Only the latest release on the default branch is
supported. Fixes are made forward, not back-ported.
