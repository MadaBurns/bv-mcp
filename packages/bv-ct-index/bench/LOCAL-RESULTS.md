# Local sanity run: NOT representative of R2 or D1

**These numbers prove that the harness works. They say nothing about production latency or CPU.** The run used `wrangler dev`, so R2 and D1 were miniflare's local emulation on disk, on one developer laptop. There was no network, no real R2 range GET and no real D1 round trip. The production numbers come from RUNBOOK.md.

- Date: 2026-10-17 (SQ-352).
- Toolchain: wrangler 4.148.0 at the repo root, Node 22.23.3, macOS.
- Command: `npx wrangler dev --config packages/bv-ct-index/bench/wrangler.jsonc --env "" --var BENCH_KEY:... --persist-to <scratch>`, after `d1 migrations apply --local` of `packages/bv-ct-index/migrations`.
- Locally the in-Worker clock advanced normally: 500 queries x 6.2 ms mean = 3.1 s, against curl's 3.12 s. A deployed Worker's clock does NOT advance during pure CPU (see RUNBOOK.md).

## Seed: `POST /seed?rows=800000&runs=4`

| Measure                                                         | Value                                                                                      |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Rows stored (800k drawn, duplicate keys within each run folded) | 750,068                                                                                    |
| Runs                                                            | 4, each about 187.5k rows, about 4.8 MB and 362-363 blocks                                 |
| Total bytes                                                     | 19,271,526 (25.7 B per row, compressed)                                                    |
| block_index BLOB per run                                        | 13.3-14.2 KB                                                                               |
| D1 NUL check (`d1Nul`)                                          | roundTrip true, rangeMatch true (local D1 only; prod is unverified until the runbook runs) |
| Wall (curl)                                                     | 3.46 s                                                                                     |

## Query: `GET /query?n=500`

| Measure                     | p50 | p95 | p99 | max |
| --------------------------- | --- | --- | --- | --- |
| Whole query (ms)            | 6   | 10  | 11  | 21  |
| D1 overlap SELECT (ms)      | 2   | 3   | 3   | 4   |
| R2 range GETs + decode (ms) | 4   | 8   | 9   | 19  |
| Blocks fetched per query    | 4   | 9   | 9   | 9   |

- By query kind, p95: apex 8 ms (n=407), cold 6 ms (n=44), suffix 11 ms (n=49).
- 81 of 500 queries hit the 9-block cap. These are hot apexes and public suffixes, which would page in the real API.
- Errors: 0. Runs per query: 4, because every seeded run spans the whole keyspace.

## Merge: `POST /merge?inputs=4`

| Measure                                                | fetch=block       | fetch=object        |
| ------------------------------------------------------ | ----------------- | ------------------- |
| Input rows / bytes                                     | 750,068 / 19.3 MB | 750,068 / 19.3 MB   |
| Output rows / bytes                                    | 650,671 / 15.8 MB | 650,671 / 15.8 MB   |
| R2 GETs                                                | 1,451 range GETs  | 4 whole-object GETs |
| Merge + encode wall (in-Worker)                        | 3,481 ms          | 2,677 ms            |
| Output put                                             | 152 ms            | 136 ms              |
| curl total                                             | 3.64 s            | 2.83 s              |
| peakBytesEstimate (counted by the bench, not measured) | 32.4 MB           | 51.6 MB             |

The rows dropped or folded (99,397) are the ~3% of seeded rows that were already expired, plus keys shared across runs.
