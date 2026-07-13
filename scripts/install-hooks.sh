#!/bin/sh
# Install the local git hooks. Run once after cloning.
#
#   ./scripts/install-hooks.sh
#
# .git/hooks/ is not tracked by git, so this must be done per clone.
set -e
cd "$(dirname "$0")/.."
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo "Installed .git/hooks/pre-commit"
