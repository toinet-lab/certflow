@AGENTS.md

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
