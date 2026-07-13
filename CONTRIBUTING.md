# Contributing to certflow

Thanks for your interest. A few rules keep this project safe to publish and
safe to run.

## Before you start

- Read [AGENTS.md](AGENTS.md). Its licensing and security rules apply to human
  contributors too.
- This release is **Phase 0: read-only inventory**. Changes must stay within
  that scope unless a maintainer has approved an expansion.

## How to contribute

1. Open an issue describing the problem or idea first (use the templates).
2. Fork the repo and create a branch.
3. Make a small, focused change.
4. Run these locally and make sure they pass:
   ```sh
   gofmt -l .        # should print nothing
   go vet ./...
   go test ./...
   go build ./...
   ```
5. Open a pull request. The guardrail CI will run automatically. A maintainer
   reviews and merges — please do not merge your own PR.

## Licensing

- All contributions are made under the project's [MIT license](LICENSE).
- **Do not add copyleft-derived code** (GPL/AGPL/LGPL), and do not use `acme.sh`
  (GPL-3.0) as a reference. See AGENTS.md for details. The ScanOSS check in CI
  enforces this.

## AI-assisted contributions

AI assistance is welcome, but:

- Disclose in the PR description if a change was substantially AI-generated.
- You are still responsible for the code: it must pass the guardrail CI, stay
  within scope, and contain no copyleft-derived or key-handling code.

## Sign your commits (DCO)

Add a `Signed-off-by` line to certify you have the right to submit the code
(the [Developer Certificate of Origin](https://developercertificate.org/)):

```sh
git commit -s -m "your message"
```

## Setup

    ./scripts/install-hooks.sh   # once per clone
