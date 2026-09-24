---
name: bv-mcp-merge-queue
description: Use when reviewing and merging the open-PR backlog in bv-mcp — enumerating open PRs, classifying each READY or HOLD against the four required checks, presenting one consent manifest, and merging in order with a re-check after every merge. Invoke via /bv-mcp-merge-queue, or when asked to "merge the open PRs", "clear the backlog", or "land the queue".
---

# bv-mcp-merge-queue — land the open-PR backlog

**One manifest, one go, one merge at a time — and every merge invalidates the evidence for
the next one.**

This skill owns the stretch between "the PRs exist" and "`main` holds them". It does not
deploy, tag, or publish. `npm run deploy:prod` is operator-run and stays entirely out of
scope here — this skill ends with a `## Continuation prompt` that hands off to
**`bv-mcp-release`** for the version-bump/tag/deploy/registry flow.

## 0. Preflight — establish the base before reading a single PR

```bash
gh auth status
git fetch origin
git status -sb                 # must NOT say `ahead`, must not be dirty
git rev-parse origin/main      # ← the verified base; quote it in the manifest
```

- **Refuse to run from a dirty or `ahead` shared checkout.** A merge session holding
  uncommitted work of its own cannot tell a conflict from a local edit. Use an isolated
  worktree (`scripts/worktree-setup.sh`, never a `node_modules` symlink — see CLAUDE.md).
- **Record the `origin/main` SHA.** It is the base for every mergeability and staleness
  claim below, and it is dead the moment the first merge lands (§4).
- **Landing ≠ deploying.** `origin/main` is not "what is live". Never answer an "is this
  live" question from this session's data — that is `bv-mcp-release`'s question, after an
  operator-run `npm run deploy:prod`.

## 1. Enumerate

```bash
gh pr list --state open --json number,title,isDraft,headRefName,baseRefName,mergeable,statusCheckRollup,labels,updatedAt
```

- Skip drafts — list them as "not considered", do not classify them.
- Note each PR's class (workflow-only / docs-only / dependency bump / code) — it decides
  merge order in §3.

## 2. Classify each PR: READY or HOLD, one line of reason

### Required vs advisory (branch protection settled 2026-08-23)

**Exactly four checks are required:** `build-and-test`, `Secret & PII scan`,
`Dependency audit`, `File hygiene check`. Everything else — `contract`, `fast-checks`,
`typecheck-tests`, `dns-scan`, `registry-drift-check`, `dogfood-scan`, CodeQL, Socket,
semgrep — is **advisory**. Branch protection is `strict=true` +
`enforce_admins=true` + `required_conversation_resolution=true`, with **NO required
reviews** (deliberate, solo maintainer). A green-but-`BLOCKED` PR is waiting on one of the
four, not on review. `mergeStateStatus: UNSTABLE` is mergeable once the four pass — do not
treat `UNSTABLE` as a HOLD reason by itself.

### ⚠️ Step 2a (mandatory, before merging any PR that touches code): the same-name `build-and-test` hole

**MEASURED 2026-09-24, PR #1117 merged red.** `build-and-test` is reported by BOTH
`ci.yml` (the real suite) and `ci-docs.yml` (docs-only PRs, path-complement of `ci.yml`).
On a PR that touches code AND a `.md` file, both workflows run. `ci-docs.yml` finished
`success` first while `ci.yml`'s `build-and-test` was still pending and later went
`failure` (its `preflight` job went red) — yet `gh pr checks --required --watch` read
green (it dedups by name), `mergeStateStatus` read `UNSTABLE`, and `gh pr merge` SUCCEEDED.
`main` went red on the very next CI run.
<!-- The two ci.yml run IDs from this incident are omitted deliberately: as bare 10-11
     digit numbers they trip the repo's phone-number secret scanner (see CLAUDE.md's
     pre-commit gates note). Do not restore them without rewording, e.g. spacing the
     digits, and do not widen .gitleaks.toml or use --no-verify to work around it. -->

**Rule, not a footnote:**

1. Before merging a PR that touches any non-docs path, run:
   ```bash
   gh run list --branch <head-ref> --workflow ci.yml --json databaseId,conclusion,status
   ```
2. Require **that run's own `build-and-test` job** to report `success`. Do not accept a
   green `gh pr checks` rollup alone as proof — it cannot distinguish "ci.yml passed" from
   "ci-docs.yml passed and ci.yml hasn't finished yet."
3. Only a **docs-only** PR (no source path in its diff) may rely on `ci-docs.yml` alone,
   since `ci.yml`'s `paths-ignore` skips it entirely and no `ci.yml` run will ever exist
   for it.

### HOLD reasons

| HOLD reason | How it presents, and what to do |
| --- | --- |
| **`build-and-test` red or still pending on `ci.yml`** | See Step 2a. HOLD until ITS run reports `success`, regardless of what `gh pr checks` shows. |
| **Merge conflict** (`mergeable: CONFLICTING`) | See conflict classes below. HOLD; resolve by regenerating, never by hand-merging a generated file. |
| **Owned by another live session** | The PR is a concurrent orchestrator's in-flight wave: its board tickets hold live claims or "groom-close follows this PR's merge" comments, or its branch is a `fix-wave-*` another session composed. HOLD and name the session, even when every gate is green — two sessions racing `gh pr update-branch` / `gh pr merge` on one PR is the shared-checkout hazard, and the owner's groomClose depends on the merge commit it expects to make. (Measured 2026-09-24: #1140 was green-but-BEHIND and owned by session 6e2d5d00; this session held it.) |
| **Operator-hold label / satellite work** | An operator hold is a decision, not an obstacle. HOLD and name the label. |
| **Unreviewed security-relevant change** | Auth, tenant scope, SSRF/`safeFetch`, `/internal/*` keys, secrets. HOLD and route to a security review first (`bv-mcp-security-surface` names the surface); a review after merge is an incident report. |
| **Scoring-behavior change without the lockstep bump** | If the PR touches `packages/dns-checks/src/scoring/`, `parity-fixtures.ts`, or `types.ts` without bumping `packages/dns-checks/package.json` + `PARITY_CORPUS_VERSION` together, the required `build-and-test` job already blocks it (`check:scoring-contract-change`) — read the failure, do not try to work around it here. Full rule: `bv-mcp-release`. |

### Conflict classes — measured this session, not invented

Derived from `git log --merges --since=2026-08-01 --format=%s | sort | uniq -c | sort -rn`
(26 of the last ~140 merges are an `origin/main`-into-branch resolution merge) and
`gh pr list --state merged --limit 40 --json number,title,files` (file recurrence across
the last 40 merged PRs, 2026-09-24):

| File | Recurrence (last 40 merged PRs) | Resolution rule |
| --- | --- | --- |
| `CHANGELOG.md` | 17 | Keep **both** bullet sets under one `## [Unreleased]` heading — do not pick a side. |
| `package.json` | 15 | Version-sync surface (`bv-mcp-release`). A real conflict here is almost always two branches both bumping the version — resolve to the higher target version, then re-run the bump. |
| `package-lock.json` | 12 | Never hand-edit. Take either side, then `npm install --package-lock-only` and commit the regenerated file. |
| `server.json` | 5 | Version-sync surface, same as `package.json` — see `bv-mcp-release`. |
| `packages/dns-checks/package.json` / `parity-fixtures.ts` | 4 each | Lockstep pair — see `bv-mcp-release`'s scoring-lockstep rule; do not resolve one without the other. |
| Generated tool-surface prose (README tool counts, `docs/**` audited counts) | recurs after any `TOOL_DEFS` change | `npm run generate:tool-surface`, never hand-edit the counts. |

Anything else — a real code conflict in `src/` or `packages/dns-checks/src/checks/`:
**escalate with a summary** (the two branches' intent, the conflicting hunk, and which one
this session believes should win). Do not hand-resolve application logic inside this
skill.

## 3. The manifest — then STOP

Present one table and nothing else:

| PR | Title | READY/HOLD | Reason (one line) | Class |
| --- | --- | --- | --- | --- |

State the verified base SHA above it. Order **workflow-only and docs-only PRs first** —
they never conflict with `package.json`/`package-lock.json`, so landing them costs nothing
and shrinks the queue before the version-surface PRs start going stale on each other.

**Never run `gh pr merge` before an explicit go.** One go covers exactly the LISTED set —
a PR not on the manifest needs its own go, and a broad "ship it" does not authorize a
merge by itself. There is no auto-merge to fall back on if this step is skipped: `gh pr
merge --auto` fails outright (`GraphQL: Auto merge is not allowed for this repository
(enablePullRequestAutoMerge)`, measured 2026-08-14) and there is no merge queue, so a batch
can never be fire-and-forgotten — every PR in the manifest needs this session to walk it
through §4 by hand.

## 4. Merge in the listed order, one at a time

Because `strict=true`, merging one PR puts **every other PR in the manifest BEHIND**. Each
of the rest then needs its own cycle before it can merge:

```bash
gh pr update-branch <n>
gh run list --branch <head-ref> --workflow ci.yml --json databaseId,conclusion,status   # wait for it (~5 min since #1117's 3-shard layout)
```

**Re-check `mergeStateStatus` in the LAST moment before `gh pr merge`, not once at manifest
time.** GitHub recomputes it **asynchronously** after a merge — a session that reads
`CLEAN` once, polls checks, then merges can still get `{"mergeStateStatus":"BEHIND"}`
because the recompute landed mid-poll. On `BEHIND`/`UNKNOWN`, loop back to
`gh pr update-branch` and re-poll ci.yml's own `build-and-test` (Step 2a) before trying
again.

A **"failed to delete local branch … used by worktree"** message printed AFTER `gh pr
merge` is a **successful merge**, not a failure — confirm with:

```bash
gh pr view <n> --json state,mergeCommit
```

After each merge, before touching the next PR:

```bash
git fetch origin && git rev-parse origin/main   # the base moved; everything above is now stale
```

Re-classify the next PR against the new base — a conflict that did not exist at manifest
time is normal here, not a bug in this process.

- **If a merge is refused** by branch protection or the permission classifier — STOP, do
  not retry-loop. Report the exact refusal and move to the next PR or hand it back.
- Land every ready PR in the manifest before moving to §5. There is no release train to
  wait for — merging is not deploying, and nothing here schedules or blocks on a deploy
  window.

## 5. Closing — measure AFTER the last merge

### Post-merge hygiene

- **Close linked Sidequest tickets** with the merge SHA as evidence (`gh pr view <n>
  --json mergeCommit`).
- **Reap worktrees with the Sidequest sweep, NOT `git janitor`:**
  ```bash
  node <sidequest.js> worktrees sweep --yes --project /Applications/Github/bv-mcp
  ```
  `git janitor` reads a squash-merged branch's "pushed" test as false — the remote branch
  is deleted on merge (`delete_branch_on_merge=true`), so its local commits never match
  anything upstream, and janitor reports `KEEP (uncommitted=0 pushed=no)` for **every**
  integrated tree. Measured **2026-09-18**: 47 worktrees, janitor would have removed 0.
  Measured **2026-09-20**: the sweep classified 52 trees and removed 13 (6
  `patch_equivalent` + 7 `ticket_done`) where janitor's `[gone]`-branch list held exactly
  one candidate.
- **Measure disk, don't extrapolate.** `df -g` before and after; `du -sh .worktrees` the
  **whole** directory, never a sample — a 2-tree sample under-estimated the true total by
  ~4× on 2026-09-20. Also confirm worktree cleanup is actually the disk lever before
  spending a session on it: on 2026-09-20 the volume sat at 99% full but the entire bv-mcp
  sweep reclaimed only 0.8 GB, because the real mass was unrelated directories outside this
  repo.

### Closing table

Take this measurement **after the last merge**, on a re-fetched `origin/main` — not what a
branch is about to do.

| PR | Outcome (merged / held / closed) | Evidence |
| --- | --- | --- |

Then emit this block, always, verbatim heading included:

````text
## Continuation prompt

```
Base: origin/main <sha-before> → <sha-after> (this session merged N PRs).
MERGED: #A <title> · #B <title>
HELD:   #C — <reason> · #D — <reason>
DISK:   .worktrees <before> → <after> (df -g / du -sh .worktrees)
NEXT:   <the exact next command — normally the bv-mcp-release flow for the unreleased
        commits now on main, or nothing if this queue carried no releasable change>
```
````

End by saying deploy/tag/publish were not attempted and pointing at `bv-mcp-release` for
that leg.

## Red flags — STOP, you are about to skip a gate

| Thought | Reality |
| --- | --- |
| "`gh pr checks` is all green, that's the four required checks" | `build-and-test` dedups by name across `ci.yml` and `ci-docs.yml`. A green rollup can mean ci-docs finished and ci.yml hasn't (measured 2026-09-24, #1117). Read ci.yml's own run. |
| "It's `UNSTABLE`, that's a HOLD" | `UNSTABLE` just means "not yet clean" — it's mergeable once the four required checks pass. Don't hold on the label alone. |
| "Auto-merge will pick these up once I flip the label" | Auto-merge is disabled at the repo level (`enablePullRequestAutoMerge` GraphQL error). There is no queue — every PR needs this session's own walk through §4. |
| "I checked `mergeStateStatus` at manifest time, that's enough" | It's recomputed asynchronously after every merge. Re-check in the last moment before `gh pr merge`, every time. |
| "The branch-deletion error means the merge failed" | A "failed to delete local branch … used by worktree" line printed AFTER `gh pr merge` is a successful merge. Confirm with `gh pr view --json state,mergeCommit`, don't assume from the error text. |
| "`git janitor` says 0 worktrees to clean, so there's nothing to reap" | Janitor is blind to squash-merged branches in this repo (measured twice). Use the Sidequest `worktrees sweep`. |
| "Merged, so it's shipped" | Merged ≠ deployed. `npm run deploy:prod` is operator-run and outside this skill's scope — hand off to `bv-mcp-release`. |

## Claim provenance — label it, or do not say it

- **`MEASURED`** — a command ran THIS session and its key output is pasted alongside
  (mergeability, check rollup, `gh run list` result, `mergedAt`).
- **`READ`** — taken from a PR body, label, or this skill's own dated facts without
  re-running the check this session. Legitimate, never presented as reproduction.
- **`ASSUMED`** — reasoned, not checked. An `ASSUMED` row may not be merged on; either
  measure it or move the PR to HOLD.

Every READY/HOLD verdict in the manifest cites the command that produced it. Nothing
carried forward from memory or a prior session is stated as current — branch protection,
required-check names, and the same-name hole above are all re-verifiable with
`gh api repos/<owner>/bv-mcp/branches/main/protection` and `gh run list`; re-check them
if this skill's dated facts are more than a few weeks old.

## Provenance

Written 2026-09-24, from the `/insights` review (263 sessions, 460 commits) that found
landing this repo's PR backlog by hand as the largest recurring bv-mcp session shape, with
no landing skill to encode the traps. Every rule above is a recorded incident, not a
preference:

- Same-name `build-and-test` hole across `ci.yml`/`ci-docs.yml` — measured 2026-09-24, PR
  #1117 merged red on an inferred-green rollup; corrected in
  `~/.claude/projects/-Applications-Github-bv-mcp/memory/project_merge-chain-strict-protection.md`.
- Branch protection settled 2026-08-23: four required checks, `strict=true`,
  `enforce_admins`, `required_conversation_resolution`, no required reviews.
- Auto-merge disabled and `strict=true` serialization, the async `mergeStateStatus` race,
  and the branch-deletion-error-is-actually-success case — measured 2026-08-14.
- Janitor's squash-merge blind spot and the Sidequest sweep as the remedy — measured
  2026-09-18 and 2026-09-20, including the 2-tree-sample ~4× under-count and the "measure
  disk first" correction, in
  `~/.claude/projects/-Applications-Github-bv-mcp/memory/project_worktree-janitor-squash-blindspot.md`.
- Conflict-class file recurrence (`CHANGELOG.md` 17, `package.json` 15,
  `package-lock.json` 12, `server.json` 5, dns-checks lockstep pair 4 each) — measured
  2026-09-24 from `gh pr list --state merged --limit 40 --json number,title,files` over
  this repo; regenerate commands cross-checked against `bv-mcp-release`.
- Structure follows bv-web-prod's `/merge-queue` skill; every rule's content is bv-mcp's
  own.
