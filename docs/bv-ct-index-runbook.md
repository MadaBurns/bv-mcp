# bv-ct-index operator runbook

Operator-run. Nothing here is run by CI or by an agent. `bv-ct-index` is the owned Certificate Transparency names index that
replaces the third-party-backed `BV_CERTSTREAM` source for `discover_subdomains` and SAN correlation (US-12). What it is and how it
works: [`packages/bv-ct-index/README.md`](../packages/bv-ct-index/README.md). The short deploy reference:
[`packages/bv-ct-index/DEPLOY.md`](../packages/bv-ct-index/DEPLOY.md).

Run every command from the **repo root**. Node 22 and `npm ci` at the root first.

## Where things stand (recorded 2026-10-17)

The sidecar Worker is **already live**, as a version that predates the query API: version `f8b4a245`, deployed 2026-10-17 06:40Z, `index_started_at`
`2026-10-17T06:46:25Z`. Resources that exist: R2 bucket `bv-ct-index`, D1 `bv-ct-index-cursors`, queues `bv-ct-index-entries` and
`bv-ct-index-compact`. It tails forward from that start time, so the index is young (see "Coverage" in the package README).

So on this account the remaining steps are **5 (redeploy with the API), 6, 7 and 8**: health, the benchmark and latency gate,
then the `BV_CERTSTREAM` repoint. Steps 1 to 4 are the provisioning record, and the recipe for any fresh account.

`BV_CERTSTREAM` still points at the old service until step 8. Until then bv-mcp behaviour is unchanged.

## 1. Re-verify the name is free (fresh account only)

```bash
npx wrangler deployments list --name bv-ct-index
```

Before the **first** deploy this must say the Worker is not found. If it lists deployments on an account where you have not
deployed this package, STOP: the name is taken.

Worker names are one account-global namespace, and `wrangler deploy` / `cf deploy` is upsert-by-name with no ownership check. A
deploy under a name someone else owns silently overwrites their Worker. **NEVER deploy under the name `bv-certstream-worker`**: a
different application with that name is live on this account. The only name for this package is `bv-ct-index`, and
`npm run check:ct-index-deploy-ready` (part of `deploy:ct-index`) refuses any other.

## 2. Provision (fresh account only)

`npm run provision:ct-index` **prints** the ordered, idempotent commands and executes nothing. Run them one at a time. In order:
check the name, create the R2 bucket `bv-ct-index`, the queues `bv-ct-index-entries` and `bv-ct-index-compact`, the D1 database
`bv-ct-index-cursors`, apply every file in `packages/bv-ct-index/migrations/` (currently 0001 to 0003: `log_cursors`, then
`runs` / `meta` / `ops_ledger`, then the `log_cursors` error columns), then deploy.

Two rules differ from older sidecar runbooks:

- **Never paste the D1 id into a tracked file.** Export it: `export BV_CT_INDEX_D1_ID=<database_id printed by d1 create>`
  (recover it with `npx wrangler d1 info bv-ct-index-cursors --json`). `cloudflare.config.ts` fails closed without it, and the
  sidecar gate needs a clean tree. Do not pass `--update-config` to `d1 create`.
- **Remote migrations and D1 queries use the gitignored `packages/bv-ct-index/.wrangler.migrate.jsonc`**, which the printed
  migration step creates from the test config with the id substituted. Pass it with `--config` on every `wrangler d1` command below.
  Without it wrangler reads the placeholder id from the tracked config.

Optional: create the R2 bucket with the same location hint the benchmark bucket reported (`bench/RUNBOOK.md` step 1), so the
benchmark numbers match production.

## 3. The admin key

One shared secret authenticates bv-mcp to the sidecar. It must be the same value in both places:

| Side     | Name                      | Where                                                              |
| -------- | ------------------------- | ------------------------------------------------------------------ |
| sidecar  | `CT_INDEX_ADMIN_KEY`      | Worker `bv-ct-index` secret                                        |
| bv-mcp   | `BV_CERTSTREAM_ADMIN_KEY` | bv-mcp secret (bv-mcp falls back to `BV_INTERNAL_DEV_KEY` if unset) |

Keep the value in your password manager first and never echo it. If you still hold the value bv-mcp's `BV_CERTSTREAM_ADMIN_KEY`
already has, reuse it: then step 8 changes no secret and rollback is a pure binding flip. If you generate a new value, the old
service needs the old key back on rollback, so keep the old one too.

**On a first deploy of a NEW Worker, `wrangler secret put` fails** ("This Worker does not exist yet, so secrets cannot be set in
advance", measured on the 2026-10-17 first deploy). Pass the secret to the deploy instead, from a file outside the repo (this keeps
the key out of git, and the tree must stay clean):

```bash
umask 077
printf 'CT_INDEX_ADMIN_KEY=%s\n' "$CT_INDEX_ADMIN_KEY" > "$HOME/ct-index-first-deploy.env"
npm run check:ct-index-deploy-ready && npm run check:deploy-freshness && npm run check:release-integrity:sidecar
npm -w packages/bv-ct-index run deploy -- --secrets-file "$HOME/ct-index-first-deploy.env"
rm -f "$HOME/ct-index-first-deploy.env"
```

(`cf deploy --secrets-file` accepts JSON or `.env`. The three `check:` commands are the gates `npm run deploy:ct-index` runs; they
are listed explicitly because `npm run deploy:ct-index -- <flag>` would hand the flag to the last command in a chain, and running
the inner `npm run deploy -- <flag>` yourself is unambiguous.)

**Later rotations** can use `printf %s "$NEW_KEY" | npx wrangler secret put CT_INDEX_ADMIN_KEY --name bv-ct-index`, followed by
the same value into bv-mcp (step 8). Rotate both sides back to back: a mismatch makes every `/enumerate` call 401, and bv-mcp then
falls through to crt.sh.

## 4. First deploy (fresh account only)

Covered by the block in step 3. Equivalent plain form once the secret exists: `npm run deploy:ct-index`.

`check:sidecar-freshness` probes `wrangler deployments list --name bv-ct-index`. It blocks `deploy:prod`, `deploy:prod:staged` and
`deploy-private.mjs` while the Worker is undeployed (an unreadable result reads as `unverified`) and, as with the other sidecars,
whenever its live deployment predates its source. The override `BV_ALLOW_STALE_SIDECARS=1` also waives the whois and infra-probe
checks; prefer deploying the sidecar.

## 5. Redeploy with the API

The live version `f8b4a245` predates the query API. From a clean checkout at the tag or commit you intend to ship, with
`BV_CT_INDEX_D1_ID` exported:

```bash
npm run deploy:ct-index
npx wrangler deployments list --name bv-ct-index   # record the new version id
```

This redeploy is also required before `npm run deploy:prod` (step 8) will pass `check:sidecar-freshness`, because the live
version predates the sidecar source. The secret persists across versions, so no `--secrets-file` is needed. Rollback of a bad sidecar deploy:
`npx wrangler rollback --name bv-ct-index`.

## 6. Health checks and the first hour

The Worker has no `workers.dev` hostname and no route, so `/health` is only reachable through a service binding (or `wrangler dev
--remote`, step 7). Judge health from its own telemetry instead. All D1 commands are read-only:

```bash
D1="npx wrangler d1 execute bv-ct-index-cursors --remote --config packages/bv-ct-index/.wrangler.migrate.jsonc"

# a. Tailer ticks every minute (leave running for a few minutes, Ctrl-C to stop)
npx wrangler tail bv-ct-index --format json | grep --line-buffered ct_tailer_tick

# b. Cursors advancing: updated_at moves and next_index grows; last_error empty for most logs
$D1 --command "SELECT log_id, kind, next_index, tree_size, updated_at, last_error, last_error_at FROM log_cursors ORDER BY updated_at DESC LIMIT 30"
$D1 --command "SELECT COUNT(*) AS logs, SUM(next_index IS NULL) AS never_read, SUM(last_error_at >= updated_at) AS erroring FROM log_cursors"

# c. Runs landing: tier-0 runs appear within minutes; tier 1 after the first :17 compaction, tier 2 after UTC midnight
$D1 --command "SELECT generation, tier, COUNT(*) AS runs, SUM(rows) AS rows, SUM(bytes) AS bytes FROM runs GROUP BY generation, tier ORDER BY generation, tier"

# d. Index meta: current_generation, index_started_at, fresh_through (must keep moving forward)
$D1 --command "SELECT k, v FROM meta"

# e. The day's ledger
$D1 --command "SELECT * FROM ops_ledger ORDER BY day DESC LIMIT 3"
```

What good looks like in the first hour:

- `ct_tailer_tick` lines show `killed:false`, `cursorsWritten` above zero, `precerts` in the thousands, `errors` small or empty.
  A `subrequests` count near 900 means the tick used its whole fetch budget; that is normal under load.
- `log_cursors.updated_at` is within the last few minutes for most logs. `never_read` is zero after a few ticks. A log whose
  `last_error_at` is not older than `updated_at` is currently erroring: one or two is normal, most of them is not.
- `runs` has tier-0 rows with `meta.fresh_through` within a couple of minutes of now, then tier-1 rows after the first `:17` mark.
  There is no `meta/index.json` object and no R2 listing endpoint in `wrangler`: the D1 `runs` table **is** the index of R2 objects.
  `r2_key` values look like `runs/t0/<ms>-<uuid>`; fetch one with `npx wrangler r2 object get bv-ct-index/<r2_key> --remote` if you
  must eyeball it (it is binary).
- Dashboard (Workers & Pages, `bv-ct-index`): no sustained error rate on the queue consumers, and the two queues drain rather than grow.

If a kill-switch or generation problem appears, see steps 9 and 10.

### 6a. Compaction stalled: tier 0 grows and tier 1 does not (SQ-362)

Seen on 2026-10-17: only the first `:17` cron after the 06:46Z go-live produced tier-1 runs. The planner made one T1 job per
clock hour with every T0 run of that hour. The go-live hour was a 14-minute partial hour: about 50 runs and 0.8M rows, and that
job fit. A full hour is about 235 runs and 3.4M rows. A T1 merge opens every input at once, because all T0 runs span the whole
keyspace. Measured in V8 on synthetic rows, that merge runs out of a 96 MB heap and takes about 34 s of CPU, so it cannot finish
inside the Worker's 128 MB isolate or its 30 s default CPU limit. The queue then retries it 3 times and drops it, since there is no
DLQ. The next hour re-plans the same oversized hours plus one more. The fix caps every T1 and T2 job at `MAX_JOB_INPUTS` (32) runs
and `MAX_JOB_ROWS` (1.5M) rows (`src/indexer/plan.ts`), and raises `limits.cpu_ms` to 300000. A 32-run job measured 4.5 s of CPU
and fit the 96 MB heap.

Open point: the 13:17Z tail showed no compact-consumer invocation at all, not failed ones. Confirm which it was with the probe
below. After the fix deploys, each `:17` cron logs one `ct_compaction_plan` line (`jobs`, `tiers`, `inputs`), and each job logs a
`ct_compaction_job` line before it starts. A job that then dies on a limit is still named in the tail.

Read-only probe (operator-run):

```bash
D1="npx wrangler d1 execute bv-ct-index-cursors --remote --config packages/bv-ct-index/.wrangler.migrate.jsonc"
# Job sizes the old planner would build: T0 runs and rows per clock hour.
$D1 --command "SELECT substr(created_at, 1, 13) AS hour, COUNT(*) AS runs, SUM(rows) AS rows FROM runs WHERE tier = 0 GROUP BY hour ORDER BY hour"
# Kill switch across ALL ledger rows (isKilled reads MAX(killed), not today's row only)
$D1 --command "SELECT MAX(killed) AS killed FROM ops_ledger"
# Queue backlog and consumer
npx wrangler queues info bv-ct-index-compact
# Across one :17 mark: the plan line, job starts, and any non-ok outcome
npx wrangler tail bv-ct-index --format json | grep --line-buffered -E 'ct_compaction_plan|ct_compaction_job|bv-ct-index-compact|exceeded'
```

Catch-up: no manual step. The first `:17` cron after the deploy plans every T0 run older than the last full hour. At about
235 runs an hour, that is about 8 jobs of at most 32 runs per backlog hour. For example, 30 backlog hours become about 220 jobs,
sent 100 per `sendBatch`. The consumer takes one job per invocation and scales out. Each job writes its own T1 runs, so tier 1 grows
and tier 0 drains to the current hour within that hour. A job re-planned by a later cron while it still waits in the queue is
harmless: the first swap wins and the duplicate returns `stale`. The T1 runs it writes are stamped with the cron time, so the whole
backlog reaches T2 at the next UTC midnight, in jobs capped the same way. Watch it with check c in step 6.

## 7. Benchmark and latency gate (before the repoint)

Both gates must pass before step 8. If either fails, **STOP**: that is the contract's "Reopen if" clause, and the repoint does not happen.

**7a. The benchmark.** Run `packages/bv-ct-index/bench/RUNBOOK.md` end to end unless its numbers are already recorded on the US-12
story. It deploys a throwaway `bv-ct-index-bench` Worker with its own bucket and database and deletes them at the end. Pass criteria,
from that file:

| Measure                                   | Pass     | Hard ceiling |
| ----------------------------------------- | -------- | ------------ |
| Query p95, in-Worker, placement off       | < 600 ms | 1500 ms      |
| Merge CPU (`cpuTime` from `wrangler tail`) | < 30 s   | 30 s         |
| Merge wall time                           | < 30 s   | 30 s         |
| Merge memory (`peakBytesEstimate`)        | < 100 MB | 128 MB       |

**7b. Latency of the real index.** Time `/enumerate` against the live index for at least five domains, including `govt.nz` (a
public suffix, a pure range scan) and a very large apex (`amazonaws.com`), plus ordinary ones. The sidecar has no public URL, so use
a remote dev session: it runs the same code on Cloudflare against the **real** R2 and D1 bindings, serves on localhost, and does not
fire the crons or consume the queues.

```bash
# Terminal 1 (leave running). .dev.vars is gitignored; delete it afterwards.
printf 'CT_INDEX_ADMIN_KEY=%s\n' "$CT_INDEX_ADMIN_KEY" > packages/bv-ct-index/.dev.vars
npx wrangler dev --remote --config packages/bv-ct-index/.wrangler.migrate.jsonc

# Terminal 2: 5 domains x 4 samples
for d in govt.nz amazonaws.com microsoft.com blackveilsecurity.com example.co.nz; do
  for i in 1 2 3 4; do
    curl -sS -o /dev/null -w "%{time_total} %{http_code} $d\n" \
      -H "authorization: Bearer $CT_INDEX_ADMIN_KEY" "http://localhost:8787/enumerate?domain=$d"
  done
done | tee latency.txt
sort -n latency.txt | awk '{ t[NR] = $1 } END { i = int(0.95 * NR); if (i < 0.95 * NR) i++; print "n=" NR " p95_s=" t[i] }'
awk '$2 != 200' latency.txt    # must print nothing
```

Pass: **p95 under 1.5 s and every status 200**. A `503` with `ct_index_timeout` means the API's own 1500 ms budget tripped, which
is a failure of this gate. The laptop round trip is inside the number, so it is conservative. The in-Worker figure is the one the
benchmark reports. Record the result with `story_log` on US-12.

This remote-dev path was written without being run against the account (the documentation ticket had no account access). If `wrangler dev
--remote` refuses this config (for example over the queue bindings), do not work around it by giving the sidecar a `workers.dev`
route or by repointing first: record the refusal on the US-12 story and ask for a decision.

## 8. Repoint `BV_CERTSTREAM`

`BV_CERTSTREAM` is a service binding. It lives in the **private overlay** `.dev/wrangler.deploy.jsonc` (gitignored; the public
`wrangler.jsonc` does not declare it). Change only the `service` field of the existing entry, from `bv-certstream-worker` to
`bv-ct-index`:

```jsonc
"services": [
  { "binding": "BV_CERTSTREAM", "service": "bv-ct-index" }
]
```

Overlay `services` merge by `binding` name (`scripts/lib/overlay-merge.mjs`), so only this entry changes. Then, in this order:

1. Make bv-mcp's key equal the sidecar's, unless you reused the existing value in step 3:
   `printf %s "$CT_INDEX_ADMIN_KEY" | npx wrangler secret put BV_CERTSTREAM_ADMIN_KEY --config .dev/wrangler.deploy.jsonc`
2. `npm run deploy:prod` (or `npm run deploy:prod:staged`, then `npm run deploy:prod:promote`, if you want the staged flow).
3. Verify through the product. Call `discover_subdomains` for a domain the index should know (use the owner key, see
   `bv-mcp-operations`), and look in `wrangler tail` for the `ct_source` log line: source `certstream` with outcome `ok`, not
   `http_error` (a 401 means the keys differ) and not `timeout`. Expect thin results for an apex whose certificates predate
   `indexStartedAt`: that is the forward-only index, not a fault.

bv-mcp spends up to 8 s on `/enumerate` and another 8 s on `/sans` of its 24 s budget, so a slow owned source starves crt.sh and
CertSpotter behind it. That is why the p95 gate in step 7 exists.

## 9. Rollback

- **Binding**: set the `service` back to `bv-certstream-worker` in `.dev/wrangler.deploy.jsonc`, restore the old
  `BV_CERTSTREAM_ADMIN_KEY` if you changed it in step 8, and `npm run deploy:prod`. The sidecar keeps running and indexing.
- **Sidecar deploy**: `npx wrangler rollback --name bv-ct-index`.
- **Index contents** (a bad compaction, a bad snapshot): roll the catalog back to a retained generation. The previous generation is
  kept for a week after each weekly snapshot.

  ```bash
  $D1 --command "SELECT generation, COUNT(*) AS runs FROM runs GROUP BY generation"
  $D1 --command "UPDATE meta SET v = '<generation to restore>' WHERE k = 'current_generation'"
  ```

  Pick a generation that has `runs` rows: pointing at one with none leaves the index empty for readers. This is one write and takes
  effect on the next request. Objects are only deleted when no generation references them, so the older
  generation's files are intact.

## 10. Kill switch and the ops ledger

`ops_ledger` has one row per UTC day (`r2_class_a`, `r2_class_b`, `d1_rows`, `killed`). **`killed = 1` on any row** stops every
writer (tailer, indexer, compaction planner and jobs, weekly snapshot). Reads continue, so bv-mcp keeps working on what is already
indexed. A kill survives UTC midnight until cleared. Queue messages wait: the indexer retries with a long delay, and a message survives about 3 hours of kill under `max_retries 3`.

```bash
# Stop all writers now
$D1 --command "INSERT INTO ops_ledger (day, killed) VALUES (date('now'), 1) ON CONFLICT (day) DO UPDATE SET killed = 1"
# Resume
$D1 --command "UPDATE ops_ledger SET killed = 0"
```

**There is no automatic spend ceiling.** Nothing compares the ledger to a threshold and flips `killed`: the switch is manual, so the
cost watch below has to be done by a person, or by a scheduled check someone adds later.

## 11. Cost watch

Estimate to compare against: **about $20 to $35 per month** (SQ-340, R2-backed forward-only index). It is an estimate from
a 58-second CT sample and ±30% volume, not a measurement. The first tick projected about 115M precerts/day against the ~41M the
estimate assumed (single-tick extrapolation, **unverified**), so check the real daily totals in the first days, not the first month.

Daily, for the first week and weekly after:

```bash
$D1 --command "SELECT day, r2_class_a, r2_class_b, d1_rows, killed FROM ops_ledger ORDER BY day DESC LIMIT 7"
```

Read the columns carefully, because they do not mean the same thing across writers:

- `r2_class_a` is the indexer's and compactor's R2 puts. This is the one that is billed as R2 Class A.
- `r2_class_b` is **not** R2 reads. The tailer adds its CT-log fetches and queue sends here.
- `d1_rows` mixes two measures: the tailer adds D1 rows read plus written, the other writers add an estimate of rows written. Use
  it as a trend, not a bill.

Price R2 against the current list price (Standard storage as checked 2026-10-17: Class A $4.50 per million, Class B $0.36 per
million, storage $0.015 per GB-month; free tier 1M Class A, 10M Class B, 10 GB-month per month; re-check the pricing page). At
that price a ledger `r2_class_a` of 1M per day (30M a month) is about $130 per month after the free tier. For R2 Class B (reads by queries), R2 storage, and **Queue
messages per day**, use the dashboard: R2 > `bv-ct-index` > Metrics, and Queues > `bv-ct-index-entries` and `bv-ct-index-compact` >
Metrics. If the projection for the month is well past the estimate, set the kill switch (step 10), then decide.

## 12. Fleet registration (cross-repo operator step)

This is a change in **bv-web-prod**, not here. bv-web-prod's `check:fleet-drift`, `check:fleet-ownership-labels` and the
worker-fleet census must know the Worker exists, or it reads as UNATTRIBUTED. The precedent is the other bv-mcp sidecars:
`bv-whois` and `bv-infra-probe` are recorded under `attributed` in `config/fleet/foreign-worker-attribution.json` (owner `bv-mcp`)
and appear in neither `config/fleet/deploy-manifest.json` nor `config/ops/technical-ownership.json`, because the deploy manifest
requires a one-to-one match with a wrangler config **on disk in bv-web-prod** and `bv-ct-index`'s config lives here. Add this under
`attributed` (checked against bv-web-prod at commit `e1574a574`; the checks themselves were not run from this repo):

```json
"bv-ct-index": {
	"owner": "bv-mcp",
	"evidence": "declared in bv-mcp packages/bv-ct-index (cloudflare.config.ts); bv-mcp service-binds it as BV_CERTSTREAM once the repoint lands; sibling of bv-whois and bv-infra-probe",
	"disposal": "NEVER DELETE after the repoint: it is discover_subdomains' primary CT source and a missing deployment blocks bv-mcp's next deploy (check:sidecar-freshness). It owns R2 bucket bv-ct-index, D1 bv-ct-index-cursors and queues bv-ct-index-entries and bv-ct-index-compact; the index is forward-only and cannot be rebuilt from the logs."
}
```

If bv-web-prod's gates still ask for the two files named in the original ticket, the manifest entry shape (schema
`config/fleet/deploy-manifest.schema.json`; `config` must name a real file in that repo, so add a stub only if that repo agrees
to hold one) and the ownership row are:

```json
{ "name": "bv-ct-index", "owner": "bv-mcp", "config": "<path of a config that exists in bv-web-prod>", "deployClass": "standalone", "dependsOn": [], "requiredSecrets": ["CT_INDEX_ADMIN_KEY"] }
```

```json
{
	"systemKey": "ct-names-index",
	"title": "Owned Certificate Transparency names index",
	"workerNames": ["bv-ct-index"],
	"technicalOwnerRef": null,
	"statusReason": "No owner review has occurred.",
	"evidence": null,
	"runbookUrl": null,
	"reviewDueAt": "2026-11-27"
}
```

`deployClass: "standalone"` and the `dependsOn` / `requiredSecrets` values are a proposal, not a measured fit; adopt only what
bv-web-prod's schema and checks accept.
