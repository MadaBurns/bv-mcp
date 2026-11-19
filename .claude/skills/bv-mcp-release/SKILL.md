---
name: bv-mcp-release
description: "Use when bumping the version or cutting a release of the bv-mcp / blackveil-dns repo — version-sync across SERVER_VERSION, package.json, package-lock.json, server.json, CHANGELOG, and the publish.yml tag flow. Symptoms: version mismatch CI failures, the publish workflow's auto-bump push rejected by branch protection, MCP Registry liveness check failing, unsure which files hold the version, or publishing the npm packages (npm-publish.yml, trusted publishing)."
---

# bv-mcp Version Bump & Release

A version lives on **4 surfaces** (plus the auto-derived `SERVER_VERSION`): `npm version` sets `package.json` + lock, and its lifecycle hook syncs `server.json` and the CHANGELOG heading. All four must match the tag, and the publish/registry flow has stale-prod foot-guns. Pre-bump locally, then tag — and publish the MCP Registry **only after** the prod deploy.

## The release in order

Each step names the evidence that ends it. The sections below hold the detail.

0. **Read this file from `origin/main`.** A main checkout that is behind loads a stale copy of this skill (2026-11-17: 27 commits behind, missing the tag hand-off and `ship.sh` failure notes). `git fetch origin && git diff --stat HEAD origin/main -- .claude/skills/bv-mcp-release/` must be empty, or read the file with `git show origin/main:`.
1. **Scope.** `git fetch origin --tags`, then `git log --first-parent --oneline v<last>..origin/main` and `gh pr list --state open`. Done when you can name every commit the release carries and have asked the operator about any green open PR that would change the version. Note whether a carried commit touches a sidecar source path; if so, step 5 applies.
2. **Bump.** In a worktree from `origin/main`: `npm version <X.Y.Z> --no-git-tag-version`, then write the CHANGELOG entry by hand (see "Pre-bump locally before tagging"). `.release/unreleased/*.md` fragments are source text for that entry; nothing consumes or deletes them at release. Done when `git diff --stat` shows exactly the four version surfaces.
3. **Merge.** Merge only when all four required checks are `success` on the pushed head, counting BOTH `build-and-test` runs: five required check-runs in total. GitHub reports the PR mergeable while the slower run does not exist yet, so count the runs. Hold every other merge until the ship is done.
4. **Tag.** Hand the operator the tag and push lines (see "The agent hands over three lines"). Done when `git ls-remote --tags origin v<X.Y.Z>` shows the merge commit.
5. **Sidecars, only if touched.** From a detached worktree at the tag: `scripts/worktree-setup.sh && npm run deploy:<sidecar>`. Done on "Deploy complete". It must precede the ship, which blocks on sidecar freshness.
6. **Ship.** `ship.sh <X.Y.Z>`. Done on `ALL PASS`; see "Reading a `ship.sh` failure" for the exits that are not failures.
7. **Behaviour probe.** One live call that exercises the release's own change, with a control that would have shown the old behaviour. `verify-release.sh` proves versions and tool counts only.
8. **npm, when the operator asks.** See "npm publishing": dry run on the tag, then the real run.

Tear a finished worktree down from the main checkout (`git -C .worktrees/<name> wt-done`). Removing the directory an agent's shell is sitting in makes its next command fail without running.

## dns-checks consumer promotion (#1187)

Consumer promotion is initiated manually. `dns-checks-release.yml` publishes the immutable package artifact and records its package version, release tag, SHA-256 and **tagged checkout commit** in the Actions summary. It does not hold a cross-repository credential or send a promotion dispatch. Artifact publication does not mean bv-web-prod has re-vendored it.

After operator authorization, use those exact summary values to initiate the existing consumer workflow from an authenticated operator terminal, or prepare a reviewed re-vendor PR by hand. Verify that the downloadable artifact, attached checksum and internal package version agree; never substitute the producer workflow's default-branch commit for the tagged source commit. Do not reuse an immutable version tag for changed package source.

```bash
# Set these from the verified release summary; do not guess a version or commit.
test -n "$VERSION" && test -n "$SHA256" && test -n "$SOURCE_COMMIT" &&
gh api repos/MadaBurns/bv-web-prod/dispatches --method POST \
  -f event_type=dns-checks-released \
  -f "client_payload[version]=$VERSION" \
  -f "client_payload[sha256]=$SHA256" \
  -f "client_payload[source_commit]=$SOURCE_COMMIT" \
  -f "client_payload[release_tag]=dns-checks-v$VERSION"
```

The consumer workflow still needs its own producer-read credential and repository settings that permit it to create a PR. Confirm download, integrity, all parity guards, typecheck and actual PR creation; a successful dispatch only proves acceptance of the event. Review/merge and deployment remain separate actions. Leave #1187 open until the required artifact and a real consumer promotion PR are verified.

## Worker version-sync surfaces (all must equal `X.Y.Z`)

1. `package.json` `version` + `package-lock.json` (use `npm version --no-git-tag-version`).
2. `server.json` — **`version`** (top-level).
3. `CHANGELOG.md` — new `[X.Y.Z]` heading.

➡️ **`SERVER_VERSION` (`src/lib/server-version.ts`) is NOT a hand-edit surface — it auto-derives** (`export const SERVER_VERSION: string = pkg.version;`). Do not `sed` it; the old sed line in this skill no longer matches and would silently no-op. Bump `package.json` and `SERVER_VERSION` follows. (Prod only advertises the new `serverInfo.version` on the _next_ `deploy:prod` after the bump — so the bump must precede the release deploy.)

⚠️ **`server.json` is currently remotes-only** — it has a single top-level `version` and a `remotes` array, **no `packages` stanza**. The "TWO version fields (top-level + `packages[0].version`)" foot-gun applies **only if** an npm `packages` stanza is re-added. The npm `packages` block was removed because the MCP Registry liveness-checks npm versions and the 3.3.x line isn't published to npm. **If you re-add a `packages` stanza, you re-introduce the two-field foot-gun — sync both.**

## `@blackveil/dns-checks` version moves in LOCKSTEP with scoring behaviour (#855)

The package version is a **coordination signal, not a registry fact** (npm lags the repo: it moves only when the operator dispatches `npm-publish.yml`): bv-web-prod vendors the package as a tarball pinned by that version (`vendor/blackveil-dns-checks-X.Y.Z.tgz`), so a version that no longer identifies the code defeats the pin. Between #794 and 3.71.0 the package sat at 1.27.0 across THREE `SCORING_MODEL_VERSION` bumps, two of which moved scores — "re-vendor 1.27.0" meant different grades on different days.

**Standing rule (settled 2026-08-31, #855 / #856 / #862):**

1. Any PR that changes scoring behaviour in the package — `packages/dns-checks/src/scoring/`, `parity-fixtures.ts`, `types.ts` — MUST bump `packages/dns-checks/package.json` **and** `PARITY_CORPUS_VERSION` (`packages/dns-checks/src/parity-fixtures.ts`) to the same new minor **in that PR**. `parity-corpus.contract.test.ts` asserts the two are equal; `npm run check:scoring-contract-change` (runs inside the required `build-and-test` job, base = the PR base SHA) BLOCKS a PR that touches those paths with the package version unchanged.
2. Any PR that touches `packages/dns-checks/src/checks/`, `src/scoring/` or `src/lib/scoring-*.ts` without touching `src/lib/scoring-version.ts` gets the advisory `Review scoring-model version decision` warning (`scripts/ci/check-scoring-version.mjs`). Either bump `SCORING_MODEL_VERSION` with a history entry, or declare the change score-neutral with the `no-scoring-change` label / `[no-scoring-change]` in the PR body. ⚠️ `check-*.ts` changes are NOT caught by rule 1's blocking gate — a check fix that moves scores (e.g. an abstention-vs-penalty correction) still needs the package + corpus bump; do it by hand.
3. The package and corpus versions are bumped PER behaviour change, not per release — so they may advance several times between server releases. The release commit does not bump them (it owns only the 4 server-version surfaces above).
4. After the server release that carries the new package version deploys, bv-web-prod must re-vendor: verify the tarball **contents and `exports`**, never the filename (fleet-architecture / [[bv-web-bv-mcp-coupling]]). Lockstep is closed only when bv-web-prod `package.json` pins the new version.

5. `npm run check:dns-checks-version-bump` (CI `preflight`, base = the PR base SHA) BLOCKS any PR that touches a dns-checks shipping input (`isDnsChecksIdentityPath`) while the package version still names an EXISTING `dns-checks-v<version>` tag whose tree differs on those inputs. An absent tag passes (a bumped version is tagged at release); unrelated PRs are not compared. Same remedy as rule 1: bump the package and `PARITY_CORPUS_VERSION` together.

Re-verify: `git log --oneline -5 -- packages/dns-checks/package.json` should show one bump per scoring-affecting PR; `grep -n PARITY_CORPUS_VERSION packages/dns-checks/src/parity-fixtures.ts` must equal `packages/dns-checks/package.json`'s version.

**CHANGELOG version axes (#1187).** The package and `SCORING_MODEL_VERSION` share the `1.x.0` namespace (a bare "1.38.0" has meant both), so every CHANGELOG line naming a version MUST name its axis: `dns-checks <X.Y.Z>` for the package, `scoring model <X.Y.Z>` for `SCORING_MODEL_VERSION`, `v<X.Y.Z>` for the Worker — never a bare `1.x.0`. A `## [x.y.z]` heading must correspond to a pushed tag + GitHub Release. Known gaps: `## [3.91.0]` is an orphan heading (no tag or Release; operator to confirm whether it was folded into 3.92.0) and `dns-checks-v1.52.0` is a tag without a Release. In-tree dns-checks 1.53.3–1.58.0 have no published artifact (cut via `dns-checks-release.yml`, operator step).

## Pre-bump locally before tagging

Pre-bumping is **enforced, not merely advised**. `publish.yml`'s `version-bump` job is a read-only _verification gate_ (PR #632): it asserts `package.json`, `package-lock.json`, `server.json` (plus `packages[0].version` if that stanza ever returns) and the `CHANGELOG.md` heading already match the tag, and fails the release with a per-surface `::error::` if any disagree. It edits and pushes nothing. So do the bump first:

```bash
npm version <X.Y.Z> --no-git-tag-version --allow-same-version   # package.json + lock; SERVER_VERSION auto-derives
# server.json top-level version + a CHANGELOG.md [X.Y.Z] stub are auto-synced by the `version` lifecycle hook (scripts/bump-version.mjs) and STAGED — fill the CHANGELOG stub in by hand; `git diff` won't show server.json because it is already staged
# ⚠️ The stub is inserted ABOVE the existing `## [Unreleased]` section, not in place of it: delete the `- TODO` stub, retitle the
# populated `[Unreleased]` heading to `[X.Y.Z] - date`, and leave an EMPTY `## [Unreleased]` above it. Skipping this left a
# stray `[3.76.0]` TODO block + duplicate `[Unreleased]` in the file for two releases (removed in #960).
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

- **`publish.yml` carries NO publish jobs (removed 2026-08-23).** History for context: the jobs sat behind `if: false` for ~46 minor versions (skipped = GREEN, npm rotted at `blackveil-dns` 2.13.0 / `@blackveil/dns-checks` 1.3.12); #719 re-enabled them fail-loud, but they then never once succeeded — 3.60–3.62 failed, 3.63/3.64 parked on the `production` environment reviewer. The jobs were deleted rather than re-armed (tombstone comment in the workflow explains). npm now publishes through its own workflow, `npm-publish.yml` (see "npm publishing"); `publish.yml` still carries no publish job. **Two claims previously recorded here were MEASURED FALSE on 2026-09-20 - do not restate them:** (a) there is NO self-deadlock - the `production` environment has `prevent_self_review: false` with a sole required reviewer, so the maintainer CAN approve his own deployment and a gated job waits for one click; (b) `NPM_TOKEN` IS set in that environment (created 2026-05-07, never rotated) - the real blocker is that **no workflow, script or package.json consumes it**, so setting or rotating it changes nothing observable. That token last failed `npm whoami` with E401 on the v3.62.0 publish run.
- **MCP Registry is published manually** via `mcp-publisher publish` with `MCP_PUBLISHER_KEY` (in `.dev.vars`) + DNS-TXT auth for `com.blackveilsecurity/*` — this IS the authoritative path, not a fallback. The server entry is **remotes-only**.
- Verify what's live: query the registry with `?version=latest` (CDN-cached — cache-bust, and check `?version=X.Y.Z` before trusting `latest`). `registry-drift-check.yml` compares live prod vs registry every 12h and opens a `registry-drift` issue on drift.

## npm publishing

`.github/workflows/npm-publish.yml` is the only publish path (operator ruling 2026-11-17, which set aside the 2026-10-09 KILL ruling's "named external requester" condition and kept its OIDC-only condition). Publish with **trusted publishing**; a local token publish or a revived `NPM_TOKEN` stays out of bounds, and `NPM_KEY` in `.dev.vars` is dead anyway (`npm whoami` E401 on 2026-11-17).

```bash
gh workflow run npm-publish.yml --ref v<X.Y.Z> -f dry_run=true    # rehearsal: packs, runs every gate, publishes nothing
gh workflow run npm-publish.yml --ref v<X.Y.Z> -f dry_run=false   # real publish
```

How it behaves:

- **Tag-bound.** It runs only when dispatched on a release tag and publishes that tag's own checkout, because npm's provenance attestation names the dispatched commit. Consequence: a fix to the workflow file does nothing until a new tag contains it, so a workflow bug costs a release. Dry-run every new tag first.
- **Three jobs.** `pack` runs `npm ci` and the build with no OIDC permission and uploads two tarballs; `publish` holds `id-token: write` behind `environment: production`, checks out and installs nothing, and publishes the tarballs, `@blackveil/dns-checks` first because the `blackveil-dns` bundle imports it. After a real publish, the read-only `smoke` job installs from the public npm registry and checks the CLI and stdio server together. A dns-checks-only run installs and imports that package. `test/audits/workflow-permissions.audit.test.ts` pins the split, the dispatch-only trigger, the dry-run default and the absence of any token.
- **Every run waits for approval**, dry runs included. Approve in the Actions UI, or with `gh api -X POST repos/MadaBurns/bv-mcp/actions/runs/<run>/pending_deployments -F "environment_ids[]=<id>" -f state=approved -f comment=...`, taking `<id>` from a GET on the same path. Approve a real publish only on the operator's explicit word.
- **Runs queue.** They share one concurrency group, so a dry run waiting for approval holds a later real run at `pending` with no jobs.
- **Re-runs are safe.** A version already on npm is skipped.

Reading the result:

- Proof of a publish is the `+ <name>@<version>` log line and `npm view <name>@<version> version --prefer-online`. The first real run (44011277396, v3.117.3) published both packages and was still marked FAILED: its confirm step gave up after 150 seconds while `blackveil-dns` took about four minutes to become readable. The window is ten minutes from the tag after v3.117.3.
- `E404` on the PUT means the run has no publish rights: the trusted publisher is missing or one of its fields does not match. npm does not validate the fields on save.
- A `git ls-remote` error naming a GitHub repository called `tarballs/<file>.tgz` means a tarball was passed as a bare relative path, which npm reads as a GitHub shorthand. The workflow passes `./tarballs/...`.

Trusted publishers (both saved 2026-11-17; repeat only if one is deleted or the workflow is renamed): per package on npmjs.com, Settings, Trusted publishing, GitHub Actions, user `MadaBurns`, repository `bv-mcp`, workflow `npm-publish.yml`, environment `production`, direct `npm publish` ticked. Saving asks for the operator's security key. An agent may fill and submit the form in the operator's browser when asked, but the operator clicks "Use security key": an automated click sends the browser down a QR-code flow that npm then rejects. A new configuration expires if its first publish does not succeed within two days.

What is published is permanent per version:

- `@blackveil/dns-checks` 2.3.0 went out with a description that still says "16 checks". Count the exported checks before correcting it, and correct it only in the NEXT dns-checks version: changing the text in place changes what an existing version tag identifies.
- The root `prepack` (`check:release-integrity:publish`) requires HEAD to be the version tag and fails when the version embedded in `dist/index.js` or `dist/stdio.js` differs from the release version, so a stale build cannot ship. The same gate guards `publish:registry`; build before either.
- Package descriptions, npm About text and README wording follow the BUSL positioning: "source-available". `test/audits/busl-positioning.audit.test.ts` enforces it on the README, CONTRIBUTING, CLAUDE.md and scoring config; apply it to anything published.

## Registry publish must FOLLOW the prod deploy (ordering)

`mcp-publisher publish` advertises `X.Y.Z` on the registry's `?version=latest` (sets `isLatest=true`) — a **public liveness claim**. The registry remote points at prod (`dns-mcp.blackveilsecurity.com`). So publishing the registry entry for a version prod isn't serving yet = advertising a version that doesn't exist in prod — the **same stale-prod class as the v2.10.2–v2.10.6 silent-prod-stale incidents**, just from the other direction.

**Rule: deploy to prod first, then publish the registry. Never the reverse.**

- Correct order: merge bump → tag (safe any time — the tag pipeline only cuts the GH Release) → **`npm run deploy:prod`** from a worktree pinned to the tag → verify `serverInfo.version` + scoring footer on prod → **only then `npm run publish:registry`**. The registry publish is the outward liveness claim, so it is always the LAST step.
- Registry **behind** prod (published 3.8.0 while prod serves 3.9.0) is **benign** — it just means "not yet bumped," and is the safe state to pause in if the deploy is deferred. Registry **ahead** of prod is the foot-gun.
- **A re-cut release re-opens the publish step (2026-09-24, 3.88.0 → 3.88.1).** The registry was published for 3.88.0 at 02:13Z; `check:deploy-freshness` then refused the v3.88.0 deploy (#1113 had merged mid-release), the tag moved forward to v3.88.1 and prod shipped 3.88.1 — but nobody re-ran `publish:registry`, so the registry sat one patch behind live for ~1h. The drift check only REPORTS this (first sighting opens an issue and exits green; it fails on the second 12h cycle) — it never closes it. Whenever the tag moves after a registry publish, treat the publish as not done: re-run it from a worktree pinned to the NEW tag, then confirm `?version=latest` reads the new version. The saved `mcp-publisher` login expires between releases (`401 … token is expired`), so expect to `login dns` again first.
- **Tag after the LAST merge — even a docs-only merge after the tag breaks `ship.sh` (3.90.0, again 3.111.3).** The tagged checkout is then behind `origin/main`, so `check:deploy-freshness` blocks, and `check:sidecar-freshness` returns `unverified` ("HEAD does not contain origin/main") without measuring anything. Clear both with evidence, never by reflex: `git diff --stat v<X.Y.Z> origin/main` must show no runtime or sidecar path, and `npm run check:sidecar-freshness` run from a worktree AT `origin/main` must say OK; only then `BV_ALLOW_STALE_DEPLOY=1 BV_ALLOW_STALE_SIDECARS=1 ship.sh <X.Y.Z>`. Cheaper: hold merges between the bump PR and the ship.
- **The tag pipeline is ordering-safe again (2026-08-23)** — with `publish-registry` deleted, tagging advertises nothing; the manual `mcp-publisher` step is the only publisher, and the ordering rule is enforced by the operator running deploy before publish. (Between #719 and 2026-08-23 the job existed armed, making a pre-deploy tag a stale-prod hazard — that window is closed.)
- "Formalize the release" (version surfaces + tag + GH Release) and "deploy + publish" are separable. Deploy and registry publish are outward-facing — confirm before each unless told to run the whole sequence.
- **A PR can sit `mergeStateStatus: BLOCKED` with all four required checks green.** Two workflows (`CI` and `CI Docs`) each run a job named `build-and-test`, and a required check is satisfied only when EVERY check-run of that name has completed — the slower one (~15 min) is still `in_progress`. Diagnose with `gh api repos/MadaBurns/bv-mcp/commits/<sha>/check-runs --jq '.check_runs[] | select(.status!="completed") | .name'`; it is not a failure and needs no re-run (observed on #907, 2026-09-04).
- **Post-deploy verification is one script, not a hand-rolled probe:** `.claude/skills/bv-mcp-release/scripts/verify-release.sh <X.Y.Z>`. Run it with `--before-publish` right after `deploy:prod` (both hosts: `serverInfo.version` over 3 probes, unknown-argument rejection, every tool strict, tool count = the advertised "N MCP tools"), then again without the flag after `publish:registry` (adds registry `/versions/latest` and the GitHub Release). Exit 0 = all PASS, 1 = a FAIL, 2 = usage. Its header lists what it does NOT prove — anonymous tier only, no scoring check — so still run one behaviour probe for the release's own change.
- **Shipping is one operator command: `.claude/skills/bv-mcp-release/scripts/ship.sh <X.Y.Z>`** (2026-11-02). Run it with `!` after the bump PR merges and the tag is pushed. It pins a detached worktree to `v<X.Y.Z>` (`.worktrees/ship-v<X.Y.Z>`), copies `.dev/wrangler.deploy.jsonc`, switches to Node 22, runs `worktree-setup.sh`, then `deploy:prod` → `verify-release.sh --before-publish` → `npm run build` → registry login (key from the main checkout's `.dev.vars`, via a mode-600 temp file, never printed) → `publish:registry` → logout → full `verify-release.sh`. It stops at the first failure, so the registry cannot get ahead of prod. `--dry-run` stops after the tag/worktree/Node/version checks; `--skip-deploy` re-runs from the verify step after a publish failure; the publish is skipped when the registry already has the version, so a re-run is safe. It does NOT deploy sidecars. The agent's part: merge, hand the operator the tag, push and ship lines (next bullet), and verify afterwards.
- **The agent hands over three lines, not one (measured 3.115.0 and 3.116.0, 2026-11).** A local publish-lock hook refuses an agent `git tag`, and the guard hook refuses an agent tag push. Do not work around either. After the bump PR merges, give the operator these as three separate `!` lines, with the full merge SHA filled in: `git tag -a v<X.Y.Z> <merge-sha> -m "v<X.Y.Z>"`, `git push origin v<X.Y.Z>`, then `ship.sh <X.Y.Z>`. Measure the tag afterwards (`git cat-file -t v<X.Y.Z>`, `git ls-remote --tags origin v<X.Y.Z>`) before saying it exists.
- **A late fix before the tag goes under the same heading.** When a fix lands after the bump PR but before the tag (3.115.0 took two), add its CHANGELOG line under the existing `## [X.Y.Z]` heading in that PR, leave `## [Unreleased]` empty, and tag the LAST merge. Do not cut a new patch version for work that has not shipped.
- **Reading a `ship.sh` failure (3.115.0, 3.116.0).** A verify FAIL that shows two versions across the three probes right after the deploy is propagation: re-probe, and once all three read the new version re-run `ship.sh <X.Y.Z> --skip-deploy`. A final FAIL of only `GitHub Release v<X.Y.Z>: release not found` means `publish.yml` has not finished: check `gh run list --workflow publish.yml`, and re-run `verify-release.sh <X.Y.Z>` when it has. If that run's `Pre-release checks` job fails or times out inside the test suite with no assertion failure (seen after the lookalikes compact-format spec, and once on a 15s timeout in the bv-ct-index indexer test), `gh run rerun <run-id> --failed` cleared it both times.
- **cf strict conflict (2026-11-02, 3.108.2).** `cf deploy` and `cf workers versions create` hard-code `strict` and abort with "last updated via the script API" when the serving version was uploaded through the API or the dashboard. There is no override flag. First find out what the API change was: run `cf audit-logs list` for that time, then diff binding names between the serving version and the last `cf_cli` version (`wrangler versions view <id> --json`). Confirm the repo config reproduces the change before you overwrite it. Then deploy with Wrangler using the `exports` form. Copy `wrangler.production.jsonc`, delete `migrations`, and add `exports: { QuotaCoordinator: {type: "durable-object", storage: "sqlite"}, ProfileAccumulator: {...same} }` (mirroring `cloudflare.config.ts`). Run `wrangler versions upload --config <copy>`. Before any traffic moves, diff the new version against the serving one; bindings, migration tag, exports and compat must be identical. Then canary with `wrangler versions deploy <new>@10% <old>@90%`, probe with the header `Cloudflare-Workers-Version-Overrides: bv-dns-security-mcp="<new>"` (plus a no-header control), promote to 100%, and finish with `ship.sh --skip-deploy`. ⚠️ Never promote a plain `wrangler.production.jsonc` upload. It drops `exports`, Cloudflare treats that as a Durable Object configuration change and refuses a percentage split, and the quota and profile Durable Objects hold the data. Moving traffic is operator-run (the classifier denies `wrangler versions deploy`).
- **In auto mode the classifier can refuse `npm run deploy:prod` itself** (2026-09-09, 3.78.0: refused both as a compound command and as the bare script). Do everything up to the deploy (merge, tag, pin a worktree to the merge commit, copy `.dev/wrangler.deploy.jsonc`, `npm ci`), then hand the operator the exact `cd` + `nvm use 22` + `npm run deploy:prod` + verify + `publish:registry` sequence in a fenced block; after they run it, verify `serverInfo.version`, the registry `?version=X.Y.Z`, and one behaviour probe yourself.
- **A `wrangler rollback <version-id>` may be refused by the session permission classifier** (prod-mutating class) even when a fresh deploy has just been allowed. Per the no-retry-loop rule, do not rephrase it; fix forward with a hotfix release instead (3.75.0 → 3.75.1 took ~70 min end to end) and note the blocked rollback in the issue. Cache keys carry `v<SERVER_VERSION>-dc<PARITY_CORPUS_VERSION>`, so the hotfix deploy also retires every cached result from the defective version immediately.

Publish steps (key never echoed): `mcp-publisher validate` → `login dns --domain blackveilsecurity.com --private-key "$KEY"` (read `$KEY` from `.dev.vars`, ed25519) → `publish` → `logout`. Verify: `?search=com.blackveilsecurity/dns&version=latest` → expect `version=X.Y.Z status=active isLatest=true` (search endpoint sometimes returns an empty body — retry a few times).

🚨 **Run BOTH shipping commands from a worktree pinned to the release commit — never from a shared or long-lived checkout.** They read the WORKING TREE, not the tag: `deploy:prod` compiles it, and `mcp-publisher publish` reads `./server.json` from **cwd**. Neither validates that the tree matches the tag, so a stale checkout ships whatever it happens to hold — and for the registry that means publishing the wrong version, silently and publicly. A fresh worktree also needs the gitignored `.dev/wrangler.deploy.jsonc` copied in (the injector fails closed without it) plus `npm ci`.

🚨 **Never let the ed25519 private key reach stdout.** `--private-key` takes **hex** (not base64, not PEM). If it is echoed it persists in shell history, terminal scrollback and any agent transcript, and must then be discarded and rotated — the public half lives in an apex TXT record, so rotating it is an operator-only zone write. Write the key to a file and pass `--private-key "$(cat mcp.hex)"` so only the substitution is recorded. Keep the local `mcp-publisher` version matching CI's: a version skew moves the token store and invalidates the saved login.

## Manual / local shipping steps (Worker, sidecars and MCP Registry; npm goes through `npm-publish.yml`)

```bash
npm -w packages/dns-checks run build && npm run build
npm run check:cf-binding-parity  # runbook step 1 (first cf deploy; see bv-mcp-operations): cf build vs wrangler.production.jsonc must be identical
npm run deploy:prod              # injects private bindings, deploys the MCP Worker ONLY (via cf deploy --mode production; PRIMARY rollback: npx wrangler rollback <version-id> --name bv-dns-security-mcp -y; secondary: injector + npx wrangler rollback <version-id> --config wrangler.production.jsonc -y)
npm run deploy:whois             # sidecar: bv-whois (cf deploy from packages/bv-whois/cloudflare.config.ts; its wrangler.jsonc is only the vitest config)
npm run deploy:infra-probe       # sidecar: bv-infra-probe (cf deploy from packages/bv-infra-probe/; rollback: npx wrangler rollback --name bv-infra-probe)
mcp-publisher publish            # MCP Registry, DNS-TXT-gated namespace
```

The two sidecar lines are not optional extras — `deploy:prod` has never deployed either
Worker, and until #945 nothing else did: bv-whois sat 4 source commits stale for 3 months.
`deploy:prod` now runs `check:sidecar-freshness` early and **blocks** when either sidecar's
live deployment predates its source, naming the commits and the exact fix command. Deploy
the named sidecar and re-run; the escape hatch is `BV_ALLOW_STALE_SIDECARS=1` (distinct from
`BV_ALLOW_STALE_DEPLOY`, so a deliberate rollback does not also wave the sidecars through).

⚠️ **Rollback of the MCP Worker needs no injector:** `npx wrangler rollback <version-id> --name bv-dns-security-mcp -y`
cannot be blocked by an API incident (the injector's secret-list call can). The FIRST rollback after the cf cutover
crosses the migrations-to-exports boundary for both SQLite Durable Objects, so rehearse it once (staged upload, then
rollback to the serving version, then promote) before relying on it; the full runbook is in `bv-mcp-operations`.

Never commit `.npmrc`, registry tokens, the DNS publisher key, or generated production config. Keep the publisher key in `.dev.vars` / an approved secret manager only.

## Workflow secret-check invariant

`test/audits/workflow-secret-check.audit.test.ts` enforces that every `[ -z "$*_TOKEN" ]` guard in the workflows does `exit 1` (no warn-and-skip). This codifies the v2.10.2–v2.10.6 silent-prod-stale incidents — **don't soften a token guard to a warning.**

## Red flags

- Bumping `package.json` only → CI version-sync audit fails. Use `npm version <X.Y.Z>`, which hits all 4 surfaces (package.json + lock, then server.json + CHANGELOG via the hook).
- Tagging without pre-bumping → the `version-bump` gate fails the release with a per-surface `::error::` and nothing publishes. Bump all 4 surfaces, then move the tag. (It no longer tries to fix this up for you — see the 3.40.0–3.42.0 incident above.)
- "Reformatting" `server.json` to tabs to match Prettier → harmless now, but it is the _shape_ of the bug that cost three releases. Prettier flags the file; leave it alone unless you also re-verify the release path.
- Re-adding a `packages` stanza to `server.json` and syncing only the top-level `version` → registry/version mismatch. Sync both fields.
- `mcp-publisher publish` BEFORE `deploy:prod` → registry advertises a version prod doesn't serve (stale-prod, public). Deploy first, publish last.
- Hand-editing `SERVER_VERSION` → no-op at best (it auto-derives from `pkg.version`); bump `package.json` instead.
- A single early post-deploy version/scoring mismatch is usually **Cloudflare rollout propagation lag**, not a stale bundle — re-poll a few times before debugging. (A genuine stale bundle is when `packages/dns-checks` wasn't rebuilt before `deploy:prod` — always `npm -w packages/dns-checks run build` first.)
- A `check:sidecar-freshness` result of **`unverified` is NOT proof the sidecars are current** — it means the gate could not read the deployment list (expired/absent `CLOUDFLARE_API_TOKEN`, offline, wrangler missing; wrangler prints an auth banner on STDOUT while exiting non-zero, which is why stdout is never parsed without a status check). Restore auth and re-run. Do NOT reach for `BV_ALLOW_STALE_SIDECARS=1` — that turns "I could not measure" into "I shipped anyway", which is the exact fail-open shape #945 was filed against.
- `wrangler d1 execute --remote --file=-` with stdin → not supported; pass a real file path.
- The advisory `contract` check failing on a bump PR with a log that stops mid-suite and prints no failed assertion → the same stall as `publish.yml`'s `Pre-release checks` (seen on three PRs, 2026-11-16/17). `gh run rerun <run> --failed` went green each time it was awaited. It is not one of the four required checks.

## Provenance

Moved here from the fleet-global `bv-cc` skills library (`~/.claude/skills/`) on 2026-08-03. It is bv-mcp-specific, so as a global skill its description competed for context in every session on every repo — including repos it can never apply to. Scoping it to this repo is the "scope skills to specific paths so they only activate in the relevant part" rule from Anthropic's large-codebase guidance.

Keep it here. If a fact in it turns out to be cross-repo (a seam bv-web-prod also depends on), the cross-repo half belongs in `fleet-architecture`, not back in the global library.
