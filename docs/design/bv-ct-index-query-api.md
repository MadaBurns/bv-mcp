# bv-ct-index query API

The `bv-ct-index` sidecar answers the three routes bv-mcp already calls on its `BV_CERTSTREAM` binding.
Code: `packages/bv-ct-index/src/api/` (handler, auth) and `fetch` in `packages/bv-ct-index/src/index.ts`.
Every response is read from the run index through `IndexReader` (`src/indexer/read.ts`).

## Routes

All routes are `GET`, take `?domain=<hostname>`, and need `Authorization: Bearer <CT_INDEX_ADMIN_KEY>`.
`/health` is the only open route.

| Route                 | Reader call                                | Fields bv-mcp reads                                              |
| --------------------- | ------------------------------------------ | ---------------------------------------------------------------- |
| `/enumerate?domain=d` | `scan(d, {limit: 500})`                    | `subdomains[]`, `certificateCount`, `timedOut`, `cached`         |
| `/sans?domain=d`      | `siblings(apexOf(d), {limit: 500})`        | `names[]`, `certificateCount`, `timedOut`, `truncated`, `cached` |
| `/cert-meta?domain=d` | `scan(d, {limit: 1})`, exact-name row only | a non-empty string `issuer`                                      |

Additive fields (bv-mcp reads `coverage`, `truncated` and `entries[]` since SQ-345): `truncated` and `cursor` and `entries[]` on `/enumerate`, `apex` on `/sans`,
`firstSeen`, `notAfter` and `wildcard` on `/cert-meta`, and on all three a `coverage` object:

```json
{ "source": "bv-ct-index", "indexStartedAt": "...", "freshThrough": "...", "historyWindow": "forward-from", "truncated": false }
```

- `/enumerate` pages with `&cursor=<cursor from the previous page>`. A wildcard row (the index folds `*.x` into `x`
  with `wildcard: true`) is listed as both `x` and `*.x`. `certificateCount` is the number of distinct names read.
- A public suffix such as `govt.nz` is a plain range scan on `/enumerate`. On `/sans` it has no registrable apex, so
  the answer is a healthy empty list.
- `/cert-meta` returns `issuer: null` (HTTP 200) when the exact name was never seen; bv-mcp reads that as no answer.

## Status codes

| Status  | When                                                                                                        |
| ------- | ----------------------------------------------------------------------------------------------------------- |
| 200     | The index was read. Zero names is a valid answer, with `coverage` present.                                  |
| 400     | Missing or invalid `domain` (a hostname, no wildcard), or a cursor the reader rejects. Body: `{ "error" }`. |
| 401     | Missing or wrong bearer key, or `CT_INDEX_ADMIN_KEY` unset (fails closed). The compare is constant time.    |
| 404/405 | Unknown path / non-GET method (after auth).                                                                 |
| 503     | Any reader throw (D1 or R2 fault), the 1500 ms internal budget, or an index that has never been populated.  |

A fault is never an empty 200: bv-mcp treats any non-null answer as final, so an empty 200 on a fault would stop it
falling through to crt.sh. `503` bodies are `{ "error": "ct_index_unavailable" | "ct_index_timeout" | "index_not_ready" }`
and carry no internal detail.

## Not done here

Done since SQ-345: bv-mcp reads `truncated` and `coverage` and has a `forward-from` history window
(`src/lib/ct-coverage.ts`). A truncated, young (under 200 days) or stale (over 6 h) answer is partial, not final.
