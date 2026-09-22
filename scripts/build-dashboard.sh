#!/usr/bin/env bash
# Rebuilds ui/ and refreshes the committed copy under
# src/main/resources/static/dashboard/.
#
# This is a developer step. Reviewers never run it: the built output is
# committed precisely so cloning the repo needs no Node.js.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UI_DIR="$REPO_ROOT/ui"
# Vite builds into ui/dist (gitignored); the tracked copy lives here. Keeping
# them separate means a stray `npm run build` cannot dirty the committed output
# without this script's explicit copy step.
TARGET="$REPO_ROOT/src/main/resources/static/dashboard"

if ! command -v npm > /dev/null 2>&1; then
  echo "npm is not on PATH. Install Node.js to rebuild the dashboard." >&2
  echo "The committed output under src/main/resources/static/dashboard/ is what" >&2
  echo "reviewers use; it only needs regenerating when ui/ changes." >&2
  exit 1
fi

echo "Installing ui/ dependencies..."
npm --prefix "$UI_DIR" install

echo "Building ui/..."
npm --prefix "$UI_DIR" run build

echo "Refreshing $TARGET"
rm -rf "$TARGET"
mkdir -p "$TARGET"
cp -R "$UI_DIR/dist/." "$TARGET/"

echo "Done. Committed dashboard is now:"
find "$TARGET" -type f | sed "s#$REPO_ROOT/##" | sort
