# AGENTS.md

Rules for any AI agent (Claude Cowork, Claude Code, Copilot coding agent, etc.)
that reads, writes, or reviews code in this repository. Human contributors
should follow these too. These rules exist to keep the project safe to publish,
safe to run, and free of copyright/licensing risk.

## Project

- **certflow** — a certificate lifecycle tool for operators.
- **Current scope: Phase 0 only** — a *read-only* TLS certificate inventory.
  Do not add issuance, key generation, key storage, remote writes, or service
  reloads. Those are later phases and must be proposed and approved first.
- **License: MIT.** Everything added here must be compatible with MIT.

## Licensing and copyright (hard rules)

1. **No copyleft.** Do not copy, port, paraphrase, or translate code from any
   GPL, AGPL, LGPL, or other copyleft-licensed project into this repository.
2. **Do not use `acme.sh` as a reference.** It is GPL-3.0. Do not read it,
   copy from it, or reimplement it line-for-line. For ACME work in later
   phases, build on permissively licensed libraries only:
   `github.com/go-acme/lego` (MIT) or `github.com/caddyserver/certmagic`
   (Apache-2.0).
3. **Cite non-trivial borrowed logic.** If a non-obvious algorithm or approach
   comes from an external source, add a short comment naming the source and its
   license, and confirm the license is permissive (MIT, Apache-2.0, BSD, ISC).
4. **Prefer the standard library.** For Phase 0, `crypto/tls` and `crypto/x509`
   are enough. Do not add dependencies without a clear reason.
5. **Disclose AI authorship.** If a change was substantially AI-generated, say
   so in the pull request description.

## Security (hard rules)

1. **Never handle real private keys or secrets.** Do not read, generate, log,
   print, or commit private keys, passwords, API keys, or tokens.
2. **Do not weaken TLS elsewhere.** The one intentional `InsecureSkipVerify` is
   in `internal/scan/scan.go`, and only because this is a read-only inventory
   that must be able to inspect expired/self-signed certs. Do not copy that
   pattern into code that *trusts* or *acts on* a connection.
3. **No network writes to third-party systems.** Phase 0 opens read-only TLS
   connections and nothing else. No POST/PUT/DELETE, no SSH, no file writes on
   remote hosts.
4. **No secrets in code or CI logs.** Configuration comes from flags/files the
   user controls, not hard-coded values.

## Workflow (hard rules)

1. **Propose a plan before writing code.** For any non-trivial change, first
   post a short plan (what and why) and wait for human approval.
2. **All changes go through a pull request.** Never commit directly to `main`.
3. **Keep pull requests small and focused.** One logical change per PR.
4. **Tests and formatting are required.** Run `gofmt`, `go vet`, and
   `go test ./...`. Add tests for new logic.
5. **The guardrail CI must pass.** If the copyleft/license check fails, stop and
   fix the source of the code — do not disable the check.
6. **A human must review and merge.** The agent never merges its own PR and
   never approves a release.
7. **If unsure, stop and ask.** Do not guess on scope, security, or licensing.

## Definition of done for a change

- [ ] Within Phase 0 scope (read-only, no keys, no remote writes)
- [ ] `gofmt -l .` is clean, `go vet ./...` passes, `go test ./...` passes
- [ ] No copyleft-derived code; sources cited where relevant
- [ ] No secrets or private keys added
- [ ] Small, focused PR with a clear description (AI authorship disclosed)
- [ ] Guardrail CI green
- [ ] Awaiting human review before merge
