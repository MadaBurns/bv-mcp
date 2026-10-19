# bv-ct-index

An owned Certificate Transparency (CT) names index, deployed as the Cloudflare Worker `bv-ct-index` (US-12). It reads new
certificates straight from the public CT logs, keeps one row per distinct hostname, and answers the three routes bv-mcp already
calls on its `BV_CERTSTREAM` service binding: `/enumerate`, `/sans` and `/cert-meta`. It replaces the third-party-backed
`bv-certstream-worker` path for `discover_subdomains` and SAN correlation, so those tools no longer depend on a CertSpotter plan
quota or on crt.sh being reachable.

- Operator runbook (provision, deploy, latency gate, repoint, rollback, kill switch, cost watch, fleet registration):
  [`docs/bv-ct-index-runbook.md`](../../docs/bv-ct-index-runbook.md)
- Short deploy reference: [`DEPLOY.md`](./DEPLOY.md)
- Query API, status codes and 503 codes: [`docs/design/bv-ct-index-query-api.md`](../../docs/design/bv-ct-index-query-api.md)
- Benchmark that gates the first production use: [`bench/RUNBOOK.md`](./bench/RUNBOOK.md)

## Architecture

One Worker, two cron triggers, two queue consumers, three bindings. Source of truth: [`wrangler.jsonc`](./wrangler.jsonc) (test-only
config) and [`cloudflare.config.ts`](./cloudflare.config.ts) (deploy config); an audit asserts they agree.

```
CT logs ──(cron * * * * *)──> tailer ──> queue bv-ct-index-entries ──> indexer ──> R2 sorted runs (tier 0) + D1 catalog
                                                                                          │
                              (cron 17 * * * *) planner ──> queue bv-ct-index-compact ──> compaction jobs (tier 0 → 1 → 2 → 3)
                                                                                          │
bv-mcp  ──(service binding BV_CERTSTREAM)──> fetch: /enumerate /sans /cert-meta ──> IndexReader (D1 range select + R2 range GETs)
```

| Piece          | Where                 | What it does                                                                                                                                                                                                                                                                                                             |
| -------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Tailer         | `src/tailer/`         | Every minute, six concurrent lanes read the Chrome CT log list (cached up to an hour) and tail every usable or qualified log whose temporal interval has not ended, except the Geomys and IPng operators, each from its cursor. It parses **precert leaves only** (23,414 of 23,417 sampled final certs embed their SCTs, so tailing precerts avoids counting each cert twice) and sends `ObservationBatch` messages. A log seen for the first time starts at its current tree size: the index is **forward-only**. |
| Indexer        | `src/indexer/write.ts` | Queue consumer (batch 100). Validates each observation against the key helpers and writes exactly one tier-0 sorted run to R2 plus a `runs` row in D1.                                                                                                                                                                  |
| Compactor      | `src/indexer/plan.ts`, `compact.ts` | Hourly at :17 the planner enqueues jobs (one key range each): tier 0 → 1 (per hour), 1 → 2 (per UTC day), 2 + 3 → 3 (shards of about 10 MB). T1 and T2 jobs take at most `MAX_JOB_INPUTS` (32) runs and `MAX_JOB_ROWS` (750k) rows, T3 jobs at most `MAX_T3_JOB_ROWS` (1.5M) rows, and a T2 run that straddles a T3 cut is first re-cut T2 → T2. Output is streamed through `createRunWriter`, so a job holds one block per input, never a whole run.                                                                          |
| Generations    | `src/indexer/generations.ts` | Once a week the planner snapshots the catalog under a new generation. The previous generation stays for a week, so a rollback is one `UPDATE` (see the runbook).                                                                                                                                                         |
| Reader         | `src/indexer/read.ts` | `scan`, `siblings` and `meta`. One D1 overlap query selects the runs of the current generation whose key range overlaps the query, then block-index-guided R2 range GETs read only the blocks needed.                                                                                                                  |
| Query API      | `src/api/`            | The three routes plus open `GET /health`. Bearer auth. Budget 1500 ms per request.                                                                                                                                                                                                                                       |

### Data model

- **One row per distinct (apex, name)**: `firstSeen` (min), `notAfter` (max), `issuer`, `wildcard`. `*.x` is folded into `x` with
  `wildcard: true`. About 37.5 B/row raw and about 25 B/row compressed on disk (SQ-348/SQ-352 measurements).
- **Keys sort by reversed labels** (`nameKey` in `src/codec.ts`), so every name under an apex, or under a public suffix, is one
  contiguous key range. Labels must be printable ASCII; the tailer skips and counts anything else.
- **Sibling rows** (other apexes seen on the same certificates) live in a separate keyspace and are written only from certs with at
  most 32 apexes. They feed `/sans`.
- **Runs** are immutable sorted objects in R2 (`runs/t<tier>/...`), each split into ~64 KB deflate blocks with a block index stored in
  D1. The D1 catalog (`runs`, `meta`, `ops_ledger`, `log_cursors`) is the only index of what exists: R2 has no list-and-read path
  in the query route.

### Public suffixes (no rollup list)

An earlier draft kept a rollup table for allowlisted public suffixes such as `govt.nz`. The chosen design deleted it: because the
sort order is reversed labels, a query for `govt.nz` is an ordinary range scan over every name ending in `.govt.nz`, paged with a
cursor like any other large apex. There is no suffix allowlist to maintain. The apex rule is bv-mcp's own registrable-domain rule
(`tldts` with `allowPrivateDomains: true`), so `workers.dev` children are their own apexes. On `/sans`, a public suffix has no
registrable apex and answers a healthy empty list.

## Routes and auth

All routes are `GET ?domain=<hostname>` and need `Authorization: Bearer <CT_INDEX_ADMIN_KEY>` (constant-time compare; unset secret
fails closed with 401). `GET /health` is the only open route and returns `{"ok":true,"worker":"bv-ct-index"}`. The Worker has no
`workers.dev` hostname and no route: it is reachable only through the `BV_CERTSTREAM` service binding.

The same secret value is bv-mcp's `BV_CERTSTREAM_ADMIN_KEY` (bv-mcp falls back to `BV_INTERNAL_DEV_KEY` when it is unset). Setting
only one side makes every `/enumerate` call 401, and bv-mcp then falls through to crt.sh.

| Route                 | Used by                                           | Notes                                                                    |
| --------------------- | ------------------------------------------------- | ------------------------------------------------------------------------ |
| `/enumerate?domain=d` | `discover_subdomains`                             | Up to 500 names per page; `&cursor=` for the next page.                  |
| `/sans?domain=d`      | `discover_subdomains`, SAN correlation            | Sibling apexes on shared certificates, up to 500.                        |
| `/cert-meta?domain=d` | `scan_domain` Cloudflare-CDN attribution          | Issuer of the exact name; `issuer: null` (HTTP 200) when never seen.    |

Full status-code table and the `ct_index_unavailable` / `ct_index_timeout` / `index_not_ready` 503 bodies:
[`docs/design/bv-ct-index-query-api.md`](../../docs/design/bv-ct-index-query-api.md). A reader fault is **never** an empty 200,
because bv-mcp treats any non-null answer as final and an empty 200 would stop it falling back to crt.sh.

## Coverage semantics

The index is **forward-only**: it contains only certificates logged after it started tailing. Every response carries a `coverage`
object:

```json
{ "source": "bv-ct-index", "indexStartedAt": "...", "freshThrough": "...", "historyWindow": "forward-from", "truncated": false }
```

- `indexStartedAt` is when the first tier-0 run was written (`meta.index_started_at`). Nothing logged before it is present, so a
  quiet apex whose certificates were issued earlier can legitimately return zero names.
- `freshThrough` is the commit time of the latest indexed batch (`meta.fresh_through`). It is **not** a CT-log timestamp.
- The index approaches full coverage of the **unexpired** certificate population as certificates issued before the start age out.
  SQ-340's measured curve from a stock sample: about 87% at day 90, 94% at day 150, 97% at day 180, and about 100% at day 200 (that is,
  roughly 200 days to full unexpired coverage). Treat an apex with few or no names inside the first 200 days as **unmeasured**, not clean.
- `truncated: true` means the page hit the 500-name limit and a `cursor` is present.

bv-mcp reads `coverage` and `truncated` (`src/lib/ct-coverage.ts`, SQ-345). An answer that is truncated, from an index younger than
200 days, or whose `freshThrough` is more than 6 hours old counts as partial: `discover_subdomains` keeps its names as a supplement
and still consults crt.sh and CertSpotter, instead of returning it as final.

## Develop

```bash
npm -w packages/bv-ct-index run typecheck
npm -w packages/bv-ct-index test          # vitest in the Workers pool (miniflare D1 and R2)
```

Run from the repo root. Never symlink `node_modules` into a worktree (see the root `CLAUDE.md`). Every source file carries the
`BUSL-1.1` SPDX header.
