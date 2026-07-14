#!/bin/sh
# Stop secrets and internal hostnames BEFORE they enter the history.
#
# This repository is PUBLIC. A push is instantly visible, and the history is
# visible forever. git rm does not remove anything from history.
#
# Files that DEFINE the detection rules are excluded: they necessarily contain
# the very patterns they look for.

EXCLUDE='^(\.gitleaks\.toml|scripts/pre-commit\.sh|scripts/install-hooks\.sh|AGENTS\.md)'

FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -vE "$EXCLUDE" || true)
[ -z "$FILES" ] && exit 0

# Two passes, because the case-sensitivity differs:
#
#   SECRETS (private keys) are matched case-INSENSITIVELY.
#
#   HOSTS/IPs are matched case-SENSITIVELY. Internal hostnames are lowercase by
#   convention (dev-alma, foo.local); matching them case-insensitively also flags
#   every PascalCase Go identifier ending in .Local/.Corp -- notably the stdlib
#   `time.Local` -- a false positive that trains people to --no-verify. Matching
#   lowercase only still catches the real thing (foo.local, dev-alma10-01.local)
#   while ignoring Go identifiers. gitleaks in CI is the case-insensitive backstop.
#
# shellcheck disable=SC2086
SECRETS=$(git diff --cached -- $FILES | grep -inE \
  'BEGIN [A-Z ]*PRIVATE KEY' \
  || true)
# shellcheck disable=SC2086
HOSTS=$(git diff --cached -- $FILES | grep -nE \
  '192\.168\.[0-9]|10\.[0-9]+\.[0-9]+\.[0-9]|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]|dev-alma|ansible-ctl|[a-z0-9-]+\.(local|internal|lan|corp)\b' \
  || true)
HITS=$(printf '%s\n%s\n' "$SECRETS" "$HOSTS" | grep -vE '^$' || true)

if [ -n "$HITS" ]; then
    echo ""
    echo "BLOCKED: the staged changes look like they contain a secret or an"
    echo "internal hostname/address:"
    echo ""
    echo "$HITS" | sed 's/^/    /'
    echo ""
    echo "This repository is PUBLIC. Use example.co.jp / 192.0.2.x instead."
    echo ""
    echo "If you are certain this is safe: git commit --no-verify"
    exit 1
fi
