---
name: bv-mcp-release
description: "Use when bumping the version or cutting a release of the bv-mcp / blackveil-dns repo — version-sync across SERVER_VERSION, package.json, package-lock.json, server.json, CHANGELOG, and the publish.yml tag flow. Symptoms: version mismatch CI failures, the publish workflow's auto-bump push rejected by branch protection, MCP Registry liveness check failing, or unsure which files hold the version."
---

# bv-mcp Version Bump & Release

A version lives in **4 hand-edited places** (plus the auto-derived `SERVER_VERSION`) that must match the tag, and the publish/registry flow has stale-prod foot-guns. Pre-bump locally, then tag — and publish the MCP Registry **only after** the prod deploy.

## Version-sync surfaces (all must equal `X.Y.Z`)

1. `package.json` `version` + `package-lock.json` (use `npm version --no-git-tag-version`).
2. `server.json` — **`version`** (top-level).
3. `CHANGELOG.md` — new `[X.Y.Z]` heading.

➡️ **`SERVER_VERSION` (`src/lib/server-version.ts`) is NOT a hand-edit surface — it auto-derives** (`export const SERVER_VERSION: string = pkg.version;`). Do not `sed` it; the old sed line in this skill no longer matches and would silently no-op. Bump `package.json` and `SERVER_VERSION` follows. (Prod only advertises the new `serverInfo.version` on the *next* `deploy:prod` after the bump — so the bump must precede the release deploy.)

⚠️ **`server.json` is currently remotes-only** — it has a single top-level `version` and a `remotes` array, **no `packages` stanza**. CLAUDE.md's "TWO version fields (top-level + `packages[0].version`)" warning applies **only if** an npm `packages` stanza is re-added. The npm `packages` block was removed because the MCP Registry liveness-checks npm versions and the 3.3.x line isn't published to npm. **If you re-add a `packages` stanza, you re-introduce the two-field foot-gun — sync both.**

## Pre-bump locally before tagging

Pre-bumping is **enforced, not merely advised**. `publish.yml`'s `version-bump` job is a read-only *verification gate* (PR #632): it asserts `package.json`, `package-lock.json`, `server.json` (plus `packages[0].version` if that stanza ever returns) and the `CHANGELOG.md` heading already match the tag, and fails the release with a per-surface `::error::` if any disagree. It edits and pushes nothing. So do the bump first:

```bash
npm version <X.Y.Z> --no-git-tag-version --allow-same-version   # package.json + lock; SERVER_VERSION auto-derives
# Update CHANGELOG.md ([X.Y.Z] heading) + server.json top-level version by hand
git commit -am "chore: release <X.Y.Z>" && git push origin main   # via PR — direct push to main is blocked
git tag v<X.Y.Z> <merged-main-HEAD> && git push origin v<X.Y.Z>   # tag the squashed merge commit, not the bump-branch tip
```

Then `publish.yml` runs: validate → version-verify (read-only gate) → GH Release. **That is the whole pipeline** (2026-08-23): the `publish-npm` and `publish-registry` jobs were deleted — across 5 tagged releases neither ever published once (3.60–3.62 failed on missing `production`-environment secrets; 3.63/3.64 parked forever in `waiting` on the environment reviewer, who is the same solo operator doing the tagging — a self-approval deadlock). The remaining jobs need only `GITHUB_TOKEN`, so a tag now completes unattended. npm and registry publishing are **manual, operator-run steps** (below); `registry-drift-check.yml` (12-hourly) is the net that catches a forgotten registry publish.

### Why the gate replaced the auto-bump (3.40.0–3.42.0 incident)

Releases **3.40.0, 3.41.0 and 3.42.0 all half-failed** and nobody noticed for weeks, because the failure was in a job everything else `needs:` — npm publish, Cloudflare deploy, registry publish **and Create GitHub Release** all reported `skipped`, so the GH Release had to be cut by hand each time.

The job pushed an auto-bump commit to `main`, which protected-branch rules reject unconditionally (`GH006 … 4 of 4 required status checks are expected`) — a direct push can never satisfy required checks. The skill and CLAUDE.md both said pre-bumping made the step "a no-op". **It did not.** The step re-serialized `server.json` with `JSON.stringify(o, null, '\t')`, reindenting the committed **2-space** file to **tabs**; the no-op guard `git diff --cached --quiet` is a **byte** test, so a whitespace-only, semantically-identical rewrite took the "version changed" branch and pushed anyway. Replayed against the real v3.42.0 tag: `package.json`/`package-lock.json` clean, `server.json` 14 insertions / 14 deletions.

Two transferable lessons:

- **A "this becomes a no-op" claim is worth executing once.** This one was documented in two places and false in both for three releases.
- **Never re-serialize a file to check whether it needs changing.** Compare the parsed value; write only on a real difference. Any `JSON.stringify` round-trip silently normalizes indentation, key quoting and trailing newline, which defeats every byte-level idempotency guard downstream.

`test/audits/workflow-permissions.audit.test.ts` now pins this shut: `contents: write` may appear **only** in `github-release`, and a tripwire asserts `version-bump` stays read-only and never regains `git push origin HEAD:main`.

## Current publish reality (verify, don't assume)

- **`publish.yml` carries NO publish jobs (removed 2026-08-23).** History for context: the jobs sat behind `if: false` for ~46 minor versions (skipped = GREEN, npm rotted at `blackveil-dns` 2.13.0 / `@blackveil/dns-checks` 1.3.12); #719 re-enabled them fail-loud, but they then never once succeeded — 3.60–3.62 failed, 3.63/3.64 parked on the `production` environment reviewer. The jobs were deleted rather than re-armed (tombstone comment in the workflow explains; re-arming requires a second reviewer so approval isn't a self-deadlock). npm publish remains gated off deliberately (#719 posture: no live `NPM_TOKEN`).
- **MCP Registry is published manually** via `mcp-publisher publish` with `MCP_PUBLISHER_KEY` (in `.dev.vars`) + DNS-TXT auth for `com.blackveilsecurity/*` — this IS the authoritative path, not a fallback. The server entry is **remotes-only**.
- Verify what's live: query the registry with `?version=latest` (CDN-cached — cache-bust, and check `?version=X.Y.Z` before trusting `latest`). `registry-drift-check.yml` compares live prod vs registry every 12h and opens a `registry-drift` issue on drift.

## Registry publish must FOLLOW the prod deploy (ordering)

`mcp-publisher publish` advertises `X.Y.Z` on the registry's `?version=latest` (sets `isLatest=true`) — a **public liveness claim**. The registry remote points at prod (`dns-mcp.blackveilsecurity.com`). So publishing the registry entry for a version prod isn't serving yet = advertising a version that doesn't exist in prod — the **same stale-prod class as the v2.10.2–v2.10.6 silent-prod-stale incidents**, just from the other direction.

**Rule: deploy to prod first, then publish the registry. Never the reverse.**

- Correct order: merge bump → tag (safe any time — the tag pipeline only cuts the GH Release) → **`npm run deploy:prod`** from a worktree pinned to the tag → verify `serverInfo.version` + scoring footer on prod → **only then `npm run publish:registry`**. The registry publish is the outward liveness claim, so it is always the LAST step.
- Registry **behind** prod (published 3.8.0 while prod serves 3.9.0) is **benign** — it just means "not yet bumped," and is the safe state to pause in if the deploy is deferred. Registry **ahead** of prod is the foot-gun.
- **The tag pipeline is ordering-safe again (2026-08-23)** — with `publish-registry` deleted, tagging advertises nothing; the manual `mcp-publisher` step is the only publisher, and the ordering rule is enforced by the operator running deploy before publish. (Between #719 and 2026-08-23 the job existed armed, making a pre-deploy tag a stale-prod hazard — that window is closed.)
- "Formalize the release" (version surfaces + tag + GH Release) and "deploy + publish" are separable. Deploy and registry publish are outward-facing — confirm before each unless told to run the whole sequence.

Publish steps (key never echoed): `mcp-publisher validate` → `login dns --domain blackveilsecurity.com --private-key "$KEY"` (read `$KEY` from `.dev.vars`, ed25519) → `publish` → `logout`. Verify: `?search=com.blackveilsecurity/dns&version=latest` → expect `version=X.Y.Z status=active isLatest=true` (search endpoint sometimes returns an empty body — retry a few times).

🚨 **Run BOTH shipping commands from a worktree pinned to the release commit — never from a shared or long-lived checkout.** They read the WORKING TREE, not the tag: `deploy:prod` compiles it, and `mcp-publisher publish` reads `./server.json` from **cwd**. Neither validates that the tree matches the tag, so a stale checkout ships whatever it happens to hold — and for the registry that means publishing the wrong version, silently and publicly. A fresh worktree also needs the gitignored `.dev/wrangler.deploy.jsonc` copied in (the injector fails closed without it) plus `npm ci`.

🚨 **Never let the ed25519 private key reach stdout.** `--private-key` takes **hex** (not base64, not PEM). If it is echoed it persists in shell history, terminal scrollback and any agent transcript, and must then be discarded and rotated — the public half lives in an apex TXT record, so rotating it is an operator-only zone write. Write the key to a file and pass `--private-key "$(cat mcp.hex)"` so only the substitution is recorded. Keep the local `mcp-publisher` version matching CI's: a version skew moves the token store and invalidates the saved login.

## Manual / local shipping steps (the authoritative path — CI publishes nothing)

```bash
npm -w packages/dns-checks run build && npm run build
npm publish --access public      # only if npm is intended + token present
npm run deploy:prod              # injects private bindings, deploys the Worker
mcp-publisher publish            # MCP Registry, DNS-TXT-gated namespace
```

Never commit `.npmrc`, registry tokens, the DNS publisher key, or generated production config. Keep the publisher key in `.dev.vars` / an approved secret manager only.

## Workflow secret-check invariant

`test/audits/workflow-secret-check.audit.test.ts` enforces that every `[ -z "$*_TOKEN" ]` guard in the workflows does `exit 1` (no warn-and-skip). This codifies the v2.10.2–v2.10.6 silent-prod-stale incidents — **don't soften a token guard to a warning.**

## Red flags

- Bumping `package.json` only → CI version-sync audit fails. Hit all 4 surfaces (package.json + lock, server.json, CHANGELOG).
- Tagging without pre-bumping → the `version-bump` gate fails the release with a per-surface `::error::` and nothing publishes. Bump all 4 surfaces, then move the tag. (It no longer tries to fix this up for you — see the 3.40.0–3.42.0 incident above.)
- "Reformatting" `server.json` to tabs to match Prettier → harmless now, but it is the *shape* of the bug that cost three releases. Prettier flags the file; leave it alone unless you also re-verify the release path.
- Re-adding a `packages` stanza to `server.json` and syncing only the top-level `version` → registry/version mismatch. Sync both fields.
- `mcp-publisher publish` BEFORE `deploy:prod` → registry advertises a version prod doesn't serve (stale-prod, public). Deploy first, publish last.
- Hand-editing `SERVER_VERSION` → no-op at best (it auto-derives from `pkg.version`); bump `package.json` instead.
- A single early post-deploy version/scoring mismatch is usually **Cloudflare rollout propagation lag**, not a stale bundle — re-poll a few times before debugging. (A genuine stale bundle is when `packages/dns-checks` wasn't rebuilt before `deploy:prod` — always `npm -w packages/dns-checks run build` first.)
- `wrangler d1 execute --remote --file=-` with stdin → not supported; pass a real file path.

## Provenance

Moved here from the fleet-global `bv-cc` skills library (`~/.claude/skills/`) on 2026-08-03. It is bv-mcp-specific, so as a global skill its description competed for context in every session on every repo — including repos it can never apply to. Scoping it to this repo is the "scope skills to specific paths so they only activate in the relevant part" rule from Anthropic's large-codebase guidance.

Keep it here. If a fact in it turns out to be cross-repo (a seam bv-web-prod also depends on), the cross-repo half belongs in `fleet-architecture`, not back in the global library.
