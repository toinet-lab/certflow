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

# shellcheck disable=SC2086
HITS=$(git diff --cached -- $FILES | grep -inE \
  'BEGIN [A-Z ]*PRIVATE KEY|192\.168\.[0-9]|10\.[0-9]+\.[0-9]+\.[0-9]|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]|dev-alma|ansible-ctl|[a-z0-9-]+\.(local|internal|lan|corp)\b' \
  || true)

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
