#!/usr/bin/env bash
# Set up a fresh git worktree for bv-mcp: verify Node 22, install real
# dependencies, and build the dns-checks workspace package (Worker code and
# tests import the BUILT dist/, not src/).
#
# WHY THIS SCRIPT EXISTS: symlinking node_modules from another checkout to
# skip a slow per-worktree `npm ci` is disallowed (see the "Never symlink
# node_modules" note in CLAUDE.md, and the enforcement in .gitignore /
# .githooks/pre-commit / .github/workflows/symlink-escape-gate.yml). A
# symlinked node_modules resolves the dns-checks workspace package to
# whatever happens to be installed in the OTHER checkout, so your tests
# validate code you did not write, silently. This script does the supported
# thing instead — a real, per-worktree install.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/worktree-setup.sh [--help]

Sets up a freshly created bv-mcp git worktree so it is ready to build and
test:

  1. Verifies the active Node.js major version is 22 (Wrangler 4.x
     hard-fails below 22; sharp's postinstall source build fails above 22
     on this repo's current toolchain).
  2. Runs `npm ci --ignore-scripts` at the repo root (installs the npm
     workspace, including packages/dns-checks, without running lifecycle
     scripts).
  3. Runs `npm -w packages/dns-checks run build` — Worker code and tests
     import the BUILT packages/dns-checks/dist/, not its src/, so this step
     is required even for a pure TypeScript source checkout.

Idempotent: safe to re-run any time (e.g. after a fresh `npm ci` or a
dependency bump) — it does not skip or special-case a partially-set-up
worktree, it just repeats the three steps above.

Do NOT symlink node_modules from another checkout instead of running this
script — see the comment at the top of this file for why.

Options:
  --help    Show this help and exit.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  usage
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Checking Node.js version"
if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node not found on PATH. Install Node 22 (e.g. via nvm) and re-run." >&2
  exit 1
fi

NODE_VERSION="$(node -v)"
NODE_MAJOR="${NODE_VERSION#v}"
NODE_MAJOR="${NODE_MAJOR%%.*}"

if [ "$NODE_MAJOR" -ne 22 ]; then
  echo "ERROR: this repo requires Node 22 (found $NODE_VERSION)." >&2
  echo "       Wrangler 4.x hard-fails below Node 22; sharp's postinstall" >&2
  echo "       source build fails on Node versions newer than 22 with this" >&2
  echo "       repo's current toolchain. Switch with 'nvm use 22' (or" >&2
  echo "       equivalent) and re-run this script." >&2
  exit 1
fi
echo "    Node $NODE_VERSION OK"

echo "==> Installing dependencies (npm ci --ignore-scripts)"
npm ci --ignore-scripts

echo "==> Building packages/dns-checks (Worker code + tests import dist/, not src/)"
npm -w packages/dns-checks run build

echo "==> Done. node_modules is a real directory, not a symlink:"
ls -ld node_modules
