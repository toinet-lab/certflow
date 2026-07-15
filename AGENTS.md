# Repository Development Instructions

These instructions apply to all contributors and coding agents working on
this repository.

## Required Checks

Run the following commands before reporting a change as complete:

```sh
gofmt -l .
go vet ./...
go test -race ./...
go build ./...
```

All commands must succeed.
`gofmt -l .` must produce no output. If any command cannot be run, clearly
state which command was skipped and why.

This applies to work produced or modified by an AI agent exactly as it applies
to work typed by a human. "An agent wrote it" is not a reason to skip the
checks — it is a reason to run them.

## Project

**certflow** — a read-only TLS certificate inventory tool. Go, MIT.

certflow finds the certificates on your mail servers, not just your web servers.
Certificate monitoring looks at HTTPS; meanwhile the certificate on an SMTP relay
expires with no browser warning, and mail silently stops being delivered. Seeing
those certificates is the point of this tool.

### Scope: read-only, and staying that way

certflow **only reads.** It opens a connection, reads the certificate the server
presents, reports on it, and closes.

Do NOT add, without explicit approval:

- certificate issuance or renewal
- private key generation, storage, or transport
- writes to any remote system, service reloads, file writes on remote hosts

These belong to a separate tool (`certmgr`) that imports this one as a library.
Proposing them is welcome. Building them unasked is not.

## Repository map

- `scan/` — **the public API.** The probe engine: connect, negotiate STARTTLS if
  needed, read the certificate, evaluate trust. Read the package doc first.
- `main.go` — the CLI. A thin wrapper over `scan`.
- `scripts/` — `install-hooks.sh` installs the local git hooks; `pre-commit.sh`
  is the pre-commit guardrail check. Before tagging a release, run the Required
  Checks (top of this file) and confirm CI is green.

## Design invariants — do not "fix" these

Each of these looks like a bug to a reader who does not know the domain. Each is
deliberate. Changing any of them silently breaks the tool.

1. **The TLS dial is unverified** (`InsecureSkipVerify` in `scan/scan.go`).
   Verification happens afterwards, on the certificate we retrieved. Verifying on
   the dial makes expired, self-signed, and hostname-mismatched certificates
   unreachable — and those are precisely the ones an operator needs to find.

   CodeQL flags this on every change to that line. It is dismissed as "won't
   fix", with the reason recorded. Do not silence it by weakening the code, and
   **never copy this pattern into code that trusts or acts on a connection.**

2. **`Trusted` is `*bool`, not `bool`.** `nil` means *undetermined* (the host was
   unreachable). That is different from `false` (*we looked, and it is not
   trusted*). Collapsing the two reports an outage as a TLS trust failure.

3. **Self-signed detection requires a signature check**
   (`leaf.CheckSignatureFrom(leaf)`), not just `Issuer == Subject`. Those fields
   are attacker-controlled and trivially forged.

4. **No AIA fetching.** Following URLs embedded in a scanned certificate is an
   SSRF risk and outside a read-only tool's remit. `incomplete_chain` and
   `unknown_authority` are therefore reported together as `untrusted_chain` — an
   honest limitation rather than a guess.

5. **Non-HTTPS is not a second-class path.** STARTTLS for SMTP/IMAP/POP3 is the
   reason this tool exists. A change that makes certflow HTTPS-only, or treats
   other services as an afterthought, is the wrong change.

6. **`NEGOTIATED` must keep its caveat.** It reports the TLS version certflow and
   the server *agreed on*, not the server's supported range. The README and `-h`
   both say so. Removing that caveat makes the tool lie.

## The `scan` package is public API

`scan` is imported by `certmgr` and potentially by others. It is not a private
implementation detail.

- **Breaking changes to `scan` require a minor version bump** and must be called
  out in the release notes.
- Adding fields to `Result` is fine. Removing or renaming them is not, without
  discussion.
- Do not move code back into `internal/`.

## Licensing rules

1. **MIT-compatible only.** Never copy, port, paraphrase, or translate GPL,
   AGPL, or LGPL code.
2. **Never use `acme.sh` (GPL-3.0) as a reference** — not even for design
   sketches of future work. For ACME, use `lego` (MIT) or `certmagic`
   (Apache-2.0).
3. **Prefer the standard library.** certflow currently has zero external
   dependencies. Keep it that way unless there is a clear reason not to.
4. **Every new dependency: check its licence and state it** in the PR.
5. Cite the source and licence of any non-trivial borrowed logic.
6. **Disclose AI authorship** in the PR description.

## Security rules

1. **Never handle real private keys, passwords, or tokens.** Do not read,
   generate, log, print, or commit them.
2. **No internal hostnames, IPs, or customer names** in code, tests, fixtures, or
   commit messages. This repository is public. Use `example.co.jp`.
3. **No network writes.** Read-only means read-only: no POST/PUT/DELETE, no SSH,
   no writes on remote hosts.

These rules are enforced mechanically, not left to memory:

- `.git/hooks/pre-commit` blocks them at commit time
  (install once per clone: `./scripts/install-hooks.sh`)
- the `secret scan` CI job (gitleaks) scans the **full history** on every push,
  and **blocks** — this repository is public, so reporting is not enough

## Workflow

`main` is protected. Pull requests are mandatory and enforced by GitHub — this is
not merely a convention.

1. **Plan before non-trivial work.** Present the plan and wait for approval
   before writing code.
2. **Branch, never `main`.** Commit with `-s` (DCO sign-off). Small, focused PRs
   — one logical change each.
3. **Run the Required Checks** (see top) before reporting anything as done.
4. **You may use `gh` freely for reversible, low-risk actions:** opening PRs,
   reading CI results, fetching failure logs, commenting on issues, reading repo
   state.
5. **Merging, tagging, and releasing require explicit approval in this session,
   for this specific change.** You may run the command — but only after I have
   reviewed the diff and told you to proceed.

   **Green CI is not approval.** A passing check means the code compiles and the
   scanners found nothing. It does not mean the change is correct, in scope, or
   wanted. Never infer permission from a plan, from a previous session, or from
   the fact that everything is green. Ask, and wait.

6. **Never disable a failing guardrail check.** If the licence scan fails, remove
   the offending code. If CodeQL flags something, fix it — or explain why it is
   intentional and ask me to dismiss it.
7. If unsure about scope, security, or licensing: **stop and ask.**

## Definition of done

- [ ] Within scope (read-only inventory)
- [ ] **Required Checks** all run and passing — or any skipped command named,
      with the reason
- [ ] New logic has tests
- [ ] Design invariants intact
- [ ] No breaking change to the `scan` public API without discussion
- [ ] Any new dependency's licence checked and named
- [ ] No secrets, no internal hostnames
- [ ] Guardrail CI green
- [ ] AI authorship disclosed in the PR
