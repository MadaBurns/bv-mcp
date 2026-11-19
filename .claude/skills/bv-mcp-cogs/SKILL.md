---
name: bv-mcp-cogs
description: Use when measuring what bv-mcp costs to run — a COGS run, a "fresh" cost reading, Cloudflare D1 rows written/read per database, the CT-index write rate, whether a cost fix (compaction, index drop, cache change) actually cut usage after a deploy, tool calls by auth tier, or any "what does X cost per month" question. Run scripts/cogs-snapshot.sh instead of hand-running `wrangler d1 info` and Analytics Engine SQL, and append the reading to docs/economics/cogs-ledger.md so the next comparison is against a recorded number, not a memory. Symptoms - "run a COGS", "did the fix land", "is D1 still the biggest line", a before/after deploy comparison, a back-fitted estimate that was never measured.
---

# bv-mcp COGS

One script, one dated reading, one ledger. The cost question keeps coming back
("fresh COGS", "did the compaction fix cut writes"), and each time it was answered
by hand with `wrangler d1 info` and an AE query, with the numbers parked in a memory
file. A memory is not a measurement: the next session cannot re-check it, and an
"expected 70% cut" stays an estimate until a reading says otherwise.

## Take a reading

```bash
.claude/skills/bv-mcp-cogs/scripts/cogs-snapshot.sh            # measure + append to the ledger
.claude/skills/bv-mcp-cogs/scripts/cogs-snapshot.sh --no-append # print only
.claude/skills/bv-mcp-cogs/scripts/cogs-snapshot.sh --days 7 --db bv-ct-index-cursors
```

Needs: wrangler OAuth (`npx wrangler whoami`) for D1, and the `cf` CLI logged in
(`cf auth whoami`) for Analytics Engine. The AE lane degrades to "unavailable" on
its own; the D1 lane is the one that must succeed, and the script exits 2 and writes
nothing when it does not — an empty reading must never look like a result.

Database names come from the wrangler configs on disk. The four production tenant /
intelligence / brand-audit databases are only in the private, untracked
`wrangler.production.jsonc`, so from a checkout without it only the CT-index
database is read; pass `--db <name>` for the rest.

## Read the result

- **Compare rows for the same database across sections.** The useful number is the
  change in `rows written/24h` between a pre-deploy and a post-deploy reading, not
  the absolute US$ figure.
- **US$ is marginal at D1 list price** ($1.00 per 1M rows written, $0.001 per 1M read,
  $0.75 per GB-month) with the account-wide included allowances not netted. It ranks
  databases against each other; it is not the invoice.
- **A 24h counter is one day.** Take the post-deploy reading only once the 24h window
  is entirely after the deploy; a reading 43 minutes after a deploy is still the old
  world. Say which deploy the reading follows when you log it.
- **AE counts are sampled** and already sample-weighted (`SUM(_sample_interval)`).
  Blob layout lives in `src/lib/analytics-queries.ts` (tool_call: blob7 = tier).

## What it does not measure

Worker CPU time, KV, Durable Objects, R2 (class A/B ops and storage), Queues and
Browser Rendering. Those lanes need an operator billing token; the `cf` CLI returns
403 on billing endpoints. When one of them matters (R2 class A ops moved with the
CT-index compaction change), say so in the ledger entry as an unmeasured lane rather
than leaving it out silently.

## Ledger

`docs/economics/cogs-ledger.md`, append-only, newest last. The script creates it on
first run. The file is gitignored on purpose (cost figures stay out of the public
repo), so it lives only in the main checkout: run the script there, not in a linked
worktree, or the reading is lost with the worktree. When a reading is taken to confirm a specific change, add one line under
the section naming the PR or deploy it follows; the script cannot know that.

Related: the `bv-mcp-operations` skill for the AE dataset, blob layout and `cf` vs
wrangler; the global `clocked-blackveil` skill for the fleet-wide cost picture.
