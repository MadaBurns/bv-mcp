#!/usr/bin/env bash
# ship.sh <X.Y.Z> [--skip-deploy] [--dry-run]
#
# Operator-run release shipping for bv-mcp: deploy the MCP Worker, verify it, THEN publish the
# MCP Registry, then verify again. One command replaces the multi-line block that used to be
# hand-typed after every release. Run it yourself (`! .claude/skills/bv-mcp-release/scripts/ship.sh
# 3.108.2`) — deploy and publish stay operator actions; this only fixes their order.
#
# Steps, stopping at the FIRST failure (so the registry can never get ahead of prod):
#   1. Refuse unless tag vX.Y.Z exists on origin.
#   2. Use (or create) a DETACHED worktree pinned to that tag at .worktrees/ship-vX.Y.Z. Refuse if an
#      existing one is dirty or not at the tag. Copy in the gitignored .dev/wrangler.deploy.jsonc.
#   3. Node 22 (via nvm when available); scripts/worktree-setup.sh if node_modules is absent.
#   4. Refuse unless the tree's package.json version == X.Y.Z.
#   5. npm run deploy:prod                       (skipped with --skip-deploy, e.g. a re-run after a
#                                                 publish failure; the step-6 verify still runs)
#   6. verify-release.sh X.Y.Z --before-publish  (live prod must serve X.Y.Z)
#   7. npm run build, then mcp-publisher login with the key from the MAIN checkout's .dev.vars
#      (written to a mode-600 temp file, never printed), npm run publish:registry, logout.
#   8. verify-release.sh X.Y.Z                   (adds registry + GitHub Release)
#
# --dry-run runs steps 1-4 (tag, pinned worktree, Node, version) and stops before anything outward.
#
# Limits:
#   - Sidecars (deploy:whois / deploy:infra-probe / deploy:ct-index) are NOT deployed; deploy:prod's
#     check:sidecar-freshness gate blocks if one is stale and names the command to run.
#   - Step 8's GitHub Release check FAILs inside the ~15 min publish.yml window after the tag push;
#     re-run verify-release.sh alone later. Registry reads are CDN-cached; re-run before acting.
#   - verify-release.sh proves the anonymous surface only; a behaviour probe for the release's own
#     change is still yours.
#
# Exit: 0 shipped and verified, 1 a step failed, 2 usage or missing prerequisite. bash 3.2 safe.

set -u
VERSION="${1:-}"
case "$VERSION" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "usage: $0 <X.Y.Z> [--skip-deploy] [--dry-run]" >&2; exit 2;; esac
shift
SKIP_DEPLOY=0
DRY_RUN=0
while [ $# -gt 0 ]; do
	case "$1" in
	--skip-deploy) SKIP_DEPLOY=1 ;;
	--dry-run) DRY_RUN=1 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
	shift
done

die() { printf '\nSHIP FAILED at: %s\n' "$1" >&2; exit "${2:-1}"; }
step() { printf '\n==> %s\n' "$1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERIFY="$SCRIPT_DIR/verify-release.sh"
[ -x "$VERIFY" ] || [ -f "$VERIFY" ] || die "verify-release.sh not found beside this script" 2
COMMON_DIR="$(git -C "$SCRIPT_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || die "not inside the bv-mcp repo" 2
MAIN="$(dirname "$COMMON_DIR")"
TAG="v$VERSION"
WT="$MAIN/.worktrees/ship-$TAG"
for bin in git npm node curl mcp-publisher; do command -v "$bin" >/dev/null 2>&1 || die "missing prerequisite: $bin" 2; done
[ -f "$MAIN/.dev/wrangler.deploy.jsonc" ] || die "missing $MAIN/.dev/wrangler.deploy.jsonc (the private-config injector fails closed without it)" 2
[ -f "$MAIN/.dev.vars" ] || die "missing $MAIN/.dev.vars (holds MCP_PUBLISHER_KEY)" 2

step "1. tag $TAG on origin"
git -C "$MAIN" fetch -q origin "refs/tags/$TAG:refs/tags/$TAG" 2>/dev/null || die "tag $TAG not found on origin — merge the bump PR and push the tag first"
TAG_SHA="$(git -C "$MAIN" rev-parse "$TAG^{commit}")" || die "cannot resolve $TAG"
echo "$TAG -> $TAG_SHA"

step "2. worktree pinned to $TAG"
if [ -d "$WT" ]; then
	[ "$(git -C "$WT" rev-parse HEAD)" = "$TAG_SHA" ] || die "$WT exists but is not at $TAG"
	[ -z "$(git -C "$WT" status --porcelain --untracked-files=no)" ] || die "$WT has uncommitted changes to tracked files"
	echo "reusing $WT"
else
	git -C "$MAIN" worktree add -q --detach "$WT" "$TAG" || die "git worktree add"
	echo "created $WT"
fi
mkdir -p "$WT/.dev" && cp "$MAIN/.dev/wrangler.deploy.jsonc" "$WT/.dev/wrangler.deploy.jsonc" || die "copy .dev/wrangler.deploy.jsonc"
chmod 600 "$WT/.dev/wrangler.deploy.jsonc"
cd "$WT" || die "cd $WT"

step "3. Node 22 + dependencies"
if [ "$(node -v | sed 's/^v//; s/\..*//')" != "22" ] && [ -s "${NVM_DIR:-$HOME/.nvm}/nvm.sh" ]; then
	# shellcheck disable=SC1090,SC1091
	. "${NVM_DIR:-$HOME/.nvm}/nvm.sh" >/dev/null 2>&1
	nvm use 22 >/dev/null 2>&1 || die "nvm use 22" 2
fi
[ "$(node -v | sed 's/^v//; s/\..*//')" = "22" ] || die "Node 22 required (found $(node -v))" 2
echo "node $(node -v)"
if [ ! -d node_modules ]; then
	scripts/worktree-setup.sh || die "scripts/worktree-setup.sh"
fi

step "4. version surfaces"
PKG_VERSION="$(node -p "require('./package.json').version")"
[ "$PKG_VERSION" = "$VERSION" ] || die "package.json is $PKG_VERSION, expected $VERSION"
echo "package.json $PKG_VERSION"
if [ "$DRY_RUN" = "1" ]; then
	printf '\nDRY RUN OK for %s: tag, worktree (%s), Node 22 and version verified. Nothing deployed or published.\n' "$VERSION" "$WT"
	exit 0
fi

if [ "$SKIP_DEPLOY" = "1" ]; then
	step "5. deploy:prod SKIPPED (--skip-deploy)"
else
	step "5. npm run deploy:prod"
	npm run deploy:prod || die "deploy:prod (nothing was published to the registry)"
fi

step "6. verify live prod before publishing"
bash "$VERIFY" "$VERSION" --before-publish || die "verify-release --before-publish (registry NOT published; prod may still be propagating — re-run with --skip-deploy)"

step "7. MCP Registry publish"
npm run build >/dev/null || die "npm run build (publish:registry's integrity gate needs a current dist)"
KEYDIR="$(mktemp -d)"
trap 'rm -rf "$KEYDIR"; mcp-publisher logout >/dev/null 2>&1 || true' EXIT
umask 077
awk -F= '$1=="MCP_PUBLISHER_KEY"{v=$0; sub(/^[^=]*=/,"",v); gsub(/^"|"$/,"",v); printf "%s", v}' "$MAIN/.dev.vars" > "$KEYDIR/k"
case "$(cat "$KEYDIR/k")" in
	*[!0-9a-fA-F]* | "") die "MCP_PUBLISHER_KEY in .dev.vars is absent or not hex" 2 ;;
esac
mcp-publisher validate || die "mcp-publisher validate"
mcp-publisher login dns --domain blackveilsecurity.com --private-key "$(cat "$KEYDIR/k")" >/dev/null || die "mcp-publisher login dns"
rm -f "$KEYDIR/k"
npm run publish:registry || die "publish:registry (prod IS on $VERSION; registry may be behind — benign, re-run with --skip-deploy)"

step "8. full verification"
sleep 20
bash "$VERIFY" "$VERSION" || die "verify-release (if only the GitHub Release or a cached registry read failed, re-run verify-release.sh $VERSION in a few minutes)"

printf '\nSHIPPED %s: prod and registry verified. Worktree: %s (remove with: git worktree remove "%s")\n' "$VERSION" "$WT" "$WT"
