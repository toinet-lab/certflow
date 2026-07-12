# CLAUDE.md

Project rules for Claude Code. Place this at the root of the `certflow` repo.

@AGENTS.md

The rules in AGENTS.md above are binding. The notes below are Claude Code specifics.

## Project

**certflow** — a read-only TLS certificate inventory tool (Phase 0). Go, MIT licensed.

## Commands

```sh
gofmt -l .        # must print nothing
go vet ./...
go test ./...
go build -o certflow .
```

Run all four before proposing that a change is done.

## Workflow

1. **Plan first.** For anything non-trivial, use plan mode and show me the plan.
   Wait for my approval before editing code.
2. **Branch, never `main`.** Create a branch, commit with `-s` (DCO sign-off),
   open a pull request.
3. **I merge, not you.** Never merge a PR, never tag, never publish a release.
4. **Small PRs.** One logical change each.
5. **Disclose AI authorship** in the PR description.

## Hard limits (repeated here because they matter most)

- **Scope: Phase 0 only.** No issuance, no key generation, no key storage, no
  writes to remote systems. Propose and get approval before expanding scope.
- **No copyleft code.** No GPL/AGPL/LGPL. Do not read or copy from `acme.sh`
  (GPL-3.0). For future ACME work, use `lego` (MIT) or `certmagic` (Apache-2.0).
- **Never touch private keys or secrets.** Do not read, generate, log, print, or
  commit them.
- The single `InsecureSkipVerify` in `internal/scan/scan.go` is intentional (we
  must be able to inspect expired/self-signed certs). Never copy that pattern
  into code that *trusts* a connection.

## If unsure

Stop and ask. Do not guess on scope, security, or licensing.
