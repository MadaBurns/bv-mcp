# bv-ct-index benchmark runbook (operator-run, throwaway)

US-12 de-risk step (SQ-352). It measures two things on throwaway resources before `BV_CERTSTREAM` is repointed at the `bv-ct-index` sidecar (runbook step 7a):

- **Read path:** the latency of one query. A query is one D1 overlap SELECT on the real catalog schema, then up to 9 single-block R2 range GETs (at most 6 in flight), then decoding those blocks.
- **Compaction:** the time and memory of `mergeSortedRuns` over 4 runs holding about 800k rows in total, as a compaction job would run it inside a Worker.

Everything this runbook creates is scratch: the Worker `bv-ct-index-bench`, the R2 bucket `bv-ct-index-bench` and the D1 database `bv-ct-index-bench`. Step 6 deletes all three. None of it touches the `bv-ct-index` sidecar or its resources.

## Pass criteria

| Measure                                                                            | Pass     | Hard ceiling         |
| ---------------------------------------------------------------------------------- | -------- | -------------------- |
| Query p95, in-Worker (`/query` `ms.p95`), placement off                            | < 600 ms | 1500 ms              |
| Merge CPU (`cpuTime` from `wrangler tail`)                                         | < 30 s   | 30 s                 |
| Merge wall time (`curl` `time_total`)                                              | < 30 s   | 30 s                 |
| Merge memory (`peakBytesEstimate`), and the tail `outcome` is not `exceededMemory` | < 100 MB | 128 MB isolate limit |

If a measure misses its hard ceiling, that triggers the contract's "Reopen if" clause. Record the numbers on the US-12 story either way.

## Read this first

- **Run every command from the repo root and pass `--config packages/bv-ct-index/bench/wrangler.jsonc`.** Do NOT `cd packages/bv-ct-index/bench` and run `npx wrangler ... --config wrangler.jsonc`. `bench/` has no `package.json`, so `npx` runs wrangler from the nearest package root, `packages/bv-ct-index/`. A relative `--config wrangler.jsonc` then resolves to the REAL `bv-ct-index` sidecar config. This was measured on 2026-10-17: the dry-run listed the sidecar's INDEX, CURSORS, ENTRIES and COMPACT bindings.
- **Pass `--env=""` for the default run and `--env smart` for the smart-placement run.** The config defines one extra environment, so if you leave `--env` out, wrangler warns.
- **The in-Worker clock does not measure CPU.** A deployed Worker's clock only moves across I/O. Query times are dominated by D1 and R2 waits, so they are close to real. The merge's `mergeWallMs` is NOT CPU time. For the merge, take CPU from `wrangler tail` and wall time from `curl`.
- The bench sets `limits.cpu_ms = 300000`. A slow merge then reports its time rather than being killed at 30 s, so the < 30 s bar is judged from the measurement.
- Requires Node 22 and `npm ci` at the repo root.

## 1. Create the scratch resources

```bash
npx wrangler whoami                                   # confirm the BlackVeil account
npx wrangler deployments list --name bv-ct-index-bench # MUST fail: the Worker name must be unused before we create it
npx wrangler r2 bucket create bv-ct-index-bench
npx wrangler r2 bucket info bv-ct-index-bench         # record its location; create the prod bucket with the same hint
npx wrangler d1 create bv-ct-index-bench              # copy the printed database_id
```

Paste the id into the bench config locally. Do NOT commit this edit: step 6 restores the file.

```bash
sed -i '' 's/YOUR_BV_CT_INDEX_BENCH_D1_DATABASE_ID/<database_id from d1 create>/g' packages/bv-ct-index/bench/wrangler.jsonc
npx wrangler d1 migrations apply bv-ct-index-bench --remote --config packages/bv-ct-index/bench/wrangler.jsonc --env=""
```

The migrations are the sidecar's own (`packages/bv-ct-index/migrations`), so the bench reads the shipped catalog schema and index.

## 2. Deploy the bench Worker with placement off, and set its key

```bash
npx wrangler deploy --config packages/bv-ct-index/bench/wrangler.jsonc --env=""
export BENCH_URL=https://bv-ct-index-bench.<your-subdomain>.workers.dev   # printed by deploy
export BENCH_KEY=$(openssl rand -hex 24)
printf %s "$BENCH_KEY" | npx wrangler secret put BENCH_KEY --config packages/bv-ct-index/bench/wrangler.jsonc --env=""
curl -sS "$BENCH_URL/health"
```

Every route except `/health` needs `authorization: Bearer $BENCH_KEY`. Without a key set, every route answers 503.

## 3. Seed

```bash
curl -sS -X POST -H "authorization: Bearer $BENCH_KEY" -w '\ncurl_total_s=%{time_total}\n' \
  "$BENCH_URL/seed?rows=800000&runs=4" | tee seed.json
```

Expect 4 runs of about 187k rows and 4.8 MB each, about 19 MB in total. `d1Nul` must be `{"roundTrip":true,"rangeMatch":true}`. That confirms prod D1 keeps a `\x00` inside `key_lo` through bind, storage, read-back and a range comparison. Sibling keys depend on this, and it had not been verified on prod D1 before (story log #14). Re-seeding wipes the earlier runs first.

## 4. Run A: placement off, from this machine

Keep a tail open in a second terminal. Run it from the repo root too:

```bash
npx wrangler tail bv-ct-index-bench --format json > tail-A.jsonl
```

Then, in the first terminal:

```bash
curl -sS -H "authorization: Bearer $BENCH_KEY" -w '\ncurl_total_s=%{time_total}\n' "$BENCH_URL/query?n=500" | tee query-A.json
curl -sS -X POST -H "authorization: Bearer $BENCH_KEY" -w '\ncurl_total_s=%{time_total}\n' "$BENCH_URL/merge?inputs=4&fetch=block" | tee merge-A-block.json
curl -sS -X POST -H "authorization: Bearer $BENCH_KEY" -w '\ncurl_total_s=%{time_total}\n' "$BENCH_URL/merge?inputs=4&fetch=object" | tee merge-A-object.json
```

Stop the tail (Ctrl-C), then read CPU and outcome per request:

```bash
jq -c '{url: .event.request.url, outcome, cpuTime, wallTime}' tail-A.jsonl
```

If `cpuTime` comes back null, read CPU time for those invocations in the dashboard instead: Workers & Pages > bv-ct-index-bench > Observability.

To read the output:

- `query-A.json` gives:
  - `ms`: p50, p95, p99, max and mean for a whole query. This is the measure the pass bar applies to.
  - `d1Ms` and `r2Ms`: the same query time split into its D1 and R2 phases.
  - `distribution`: a histogram of query times.
  - `byKind`: the same figures split by query type. `apex` is a row-weighted apex, so hot apexes recur. `cold` is a uniform-random apex, usually absent. `suffix` is a public suffix such as `govt.nz`.
  - `blocks`: the number of R2 range GETs per query.
  - `truncatedQueries`: queries that hit the 9-block cap.
  - `colo`: the colo the Worker ran in.
- `merge-A-*.json` gives:
  - `outputRows` and `outputBytes`: what the merge wrote.
  - `blockReads`: the number of R2 range GETs. `fetch=block` reads one block per GET, about 1,450 GETs. `fetch=object` reads each run with a single GET.
  - `peakBytesEstimate`: memory held at the peak. It is counted by the bench, not measured from the heap: input blocks or whole objects, the decoded rows at 274 B per row, and twice the output, because `finish()` concatenates. An `exceededMemory` outcome in the tail is the authoritative failure.
  - The merge's true times are the tail's `cpuTime` and the `curl` `time_total`, not the in-Worker clock.

A client-side check of single-query latency includes the round trip to the Worker:

```bash
for i in $(seq 1 20); do curl -sS -o /dev/null -H "authorization: Bearer $BENCH_KEY" -w '%{time_total}\n' "$BENCH_URL/query?n=1"; done
```

## 5. Run B: the same Worker with smart placement

Run A runs in the colo nearest this machine, wherever the bucket is. Run B lets Cloudflare move the Worker next to R2 and D1, which gives the second region.

```bash
npx wrangler deploy --config packages/bv-ct-index/bench/wrangler.jsonc --env smart
```

The Worker name is the same, so `BENCH_KEY` carries over. Smart placement only places a Worker after it has seen traffic. Warm it up with a few `/query?n=50` calls over about 15 minutes, then check whether it has been placed:

```bash
curl -sSI -H "authorization: Bearer $BENCH_KEY" "$BENCH_URL/query?n=1" | grep -i cf-placement   # remote-XXX = placed elsewhere
```

Then repeat step 4 with the tail written to `tail-B.jsonl` and the outputs to `query-B.json` and `merge-B-*.json`. If you can reach a second network region, from another machine or over a VPN, a third Run A from there is worth recording too. The prod sidecar ships with placement OFF, so Run A is the representative read figure, and Run B shows how much placement would buy.

## 6. Record, then DELETE everything

Record the figures on the US-12 story with `story_log`: query p95, p99 and max for A and B, then merge cpuTime, wall time and peak bytes for both fetch modes, then `d1Nul`, the bucket location and the colos. Then tear everything down:

```bash
curl -sS -X POST -H "authorization: Bearer $BENCH_KEY" "$BENCH_URL/cleanup"   # expect remainingObjects: 0
npx wrangler delete --name bv-ct-index-bench
npx wrangler r2 bucket delete bv-ct-index-bench
npx wrangler d1 delete bv-ct-index-bench -y
git checkout -- packages/bv-ct-index/bench/wrangler.jsonc                    # restore the id placeholder
```

Confirm all three are gone:

```bash
npx wrangler deployments list --name bv-ct-index-bench   # must fail: Worker gone
npx wrangler r2 bucket list | grep -c bv-ct-index-bench  # must print 0
npx wrangler d1 list | grep -c bv-ct-index-bench         # must print 0
```

`grep -c` exits 1 when it prints 0. That is the expected result here, not a failure.

Cost: the seed is about 4 Class A puts and some D1 writes. Each `/query?n=500` is about 2,500 Class B range GETs and 500 D1 reads. Each merge is about 1,450 Class B GETs and 1 put. It is all well inside the free tiers, and it stops once the bucket is deleted.
