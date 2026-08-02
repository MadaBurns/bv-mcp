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

The `publish.yml` version-sync step auto-commits a bump and **pushes to `main` — which branch protection rejects** unless you've already done it. So do it first:

```bash
npm version <X.Y.Z> --no-git-tag-version --allow-same-version   # package.json + lock; SERVER_VERSION auto-derives
# Update CHANGELOG.md ([X.Y.Z] heading) + server.json top-level version by hand
git commit -am "chore: release <X.Y.Z>" && git push origin main   # via PR — direct push to main is blocked
git tag v<X.Y.Z> <merged-main-HEAD> && git push origin v<X.Y.Z>   # tag the squashed merge commit, not the bump-branch tip
```

Then `publish.yml` runs: validate → version-sync (no-op, already bumped) → npm publish (provenance) ‖ Cloudflare deploy → MCP Registry → GH Release. Requires `NPM_TOKEN`, `CLOUDFLARE_API_TOKEN`, `MCP_REGISTRY_TOKEN` in the `production` env (fail-fast if absent).

## Current publish reality (verify, don't assume)

- **npm publish is gated** (`NPM_TOKEN` not configured) — the hosted npm step won't run. The 3.3.x line is **not on npm**.
- **MCP Registry IS publishable locally** via `mcp-publisher publish` with `MCP_PUBLISHER_KEY` (in `.dev.vars`) + DNS-TXT auth for `com.blackveilsecurity/*`. Registry liveness-checks npm versions, so the server entry is **remotes-only**.
- Verify what's live: query the registry with `?version=latest`.

## Registry publish must FOLLOW the prod deploy (ordering)

`mcp-publisher publish` advertises `X.Y.Z` on the registry's `?version=latest` (sets `isLatest=true`) — a **public liveness claim**. The registry remote points at prod (`dns-mcp.blackveilsecurity.com`). So publishing the registry entry for a version prod isn't serving yet = advertising a version that doesn't exist in prod — the **same stale-prod class as the v2.10.2–v2.10.6 silent-prod-stale incidents**, just from the other direction.

**Rule: deploy to prod first, then publish the registry. Never the reverse.**

- Correct order: merge bump → tag (→ `publish.yml` cuts the GH Release; its Cloudflare deploy ends `cancelled`, registry `skipped`) → **`npm run deploy:prod`** → verify `serverInfo.version` + scoring footer on prod → **only then `mcp-publisher publish`** → verify `?version=latest` shows `isLatest=true`.
- Registry **behind** prod (published 3.8.0 while prod serves 3.9.0) is **benign** — it just means "not yet bumped," and is the safe state to pause in if the deploy is deferred. Registry **ahead** of prod is the foot-gun.
- The tag pipeline itself is ordering-safe: per the job table it does the GH Release but **skips** the registry, so tagging advertises nothing to the registry. Only the manual `mcp-publisher` step does — keep it last.
- "Formalize the release" (version surfaces + tag + GH Release) and "deploy + publish" are separable. Deploy and registry publish are outward-facing — confirm before each unless told to run the whole sequence.

Publish steps (key never echoed): `mcp-publisher validate` → `login dns --domain blackveilsecurity.com --private-key "$KEY"` (read `$KEY` from `.dev.vars`, ed25519) → `publish` → `logout`. Verify: `?search=com.blackveilsecurity/dns&version=latest` → expect `version=X.Y.Z status=active isLatest=true` (search endpoint sometimes returns an empty body — retry a few times).

## Manual / local release fallback (hosted secrets unavailable)

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
- Letting `publish.yml` do the bump push → rejected by branch protection. Pre-bump locally.
- Re-adding a `packages` stanza to `server.json` and syncing only the top-level `version` → registry/version mismatch. Sync both fields.
- `mcp-publisher publish` BEFORE `deploy:prod` → registry advertises a version prod doesn't serve (stale-prod, public). Deploy first, publish last.
- Hand-editing `SERVER_VERSION` → no-op at best (it auto-derives from `pkg.version`); bump `package.json` instead.
- A single early post-deploy version/scoring mismatch is usually **Cloudflare rollout propagation lag**, not a stale bundle — re-poll a few times before debugging. (A genuine stale bundle is when `packages/dns-checks` wasn't rebuilt before `deploy:prod` — always `npm -w packages/dns-checks run build` first.)
- `wrangler d1 execute --remote --file=-` with stdin → not supported; pass a real file path.

## Provenance

Moved here from the fleet-global `bv-cc` skills library (`~/.claude/skills/`) on 2026-08-03. It is bv-mcp-specific, so as a global skill its description competed for context in every session on every repo — including repos it can never apply to. Scoping it to this repo is the "scope skills to specific paths so they only activate in the relevant part" rule from Anthropic's large-codebase guidance.

Keep it here. If a fact in it turns out to be cross-repo (a seam bv-web-prod also depends on), the cross-repo half belongs in `fleet-architecture`, not back in the global library.
