@AGENTS.md

## Naming (fixed — do not waver)

This repository was renamed from `certflow` to CertRenova Probe. Write the name
consistently, the way `git`/`Git`, `docker`/`Docker`, and `postgres`/`PostgreSQL`
are written:

- **Brand / prose / titles:** `CertRenova Probe` (and the family name
  `CertRenova`). Capital `C` and `R`, a space, and the role word `Probe` with a
  capital `P`. Future family members follow the same rule: `CertRenova Renew`,
  `CertRenova CA`.
- **Command / binary / runnable examples:** `certrenova-probe` (and
  `certrenova`). All lowercase, hyphenated.
- **Code / import / module path:** `github.com/toinet-lab/certrenova-probe`. All
  lowercase.

Never write `CertRenova probe` (lowercase p), `certRenova`, `Certrenova`, or
`Cert Renova`. The brand is always `CertRenova Probe`; the command is always
`certrenova-probe`. The same rule applies to `certrenova` (formerly `certmgr`)
and to any future product in the family.

## Language

Talk to me in Japanese. Explanations, reports, and questions in our
conversation should be written in Japanese.

Keep the following in English, because they are public — CertRenova Probe is a
public repository — and they outlive the conversation:

- code, comments, commit messages
- documentation (README, AGENTS.md, ADRs)
- pull request and issue bodies

## Using `gh`

`gh` is authenticated. Use it rather than asking me to click through the browser.

Freely, without asking — these are reversible:

```sh
gh pr create --fill              # after pushing a branch
gh pr checks --watch             # wait for CI and report the result
gh pr diff                       # show me what changed
gh run view --log-failed         # when CI fails, fetch the ACTUAL error
gh issue list / gh issue view N
gh pr comment N --body "..."     # e.g. "@dependabot rebase"
```

Only after I approve, in this session, for this specific change:

```sh
gh pr merge N --squash --delete-branch
git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z
gh release create / gh release edit
```

**When CI fails, do not guess.** Run `gh run view --log-failed` and read the real
error before proposing a fix. Guessing at CI failures has cost more time on this
project than anything else.

## Reporting back

When you finish a piece of work, tell me:

1. what changed — and show me the diff,
2. the result of each Required Check,
3. the CI status,

then stop and wait. Do not proceed to merge.
