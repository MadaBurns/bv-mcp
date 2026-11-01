# Detailed Analytics Capture Provisioning

Public-safe operator runbook for the enriched `mcp_access_log` analytics path
(queue-batched producer/consumer, gated PII depth, D1 report endpoints). Keep
real Cloudflare database IDs, queue names, encryption keys, account details, and
bearer tokens in ignored deployment notes — never in this repo.


## 1. Provision the access-log database FIRST

The `INTELLIGENCE_DB` binding holds `mcp_access_log` and `mcp_access_log_audit`.
The target database is `mcp-access-log-v1`, owned by bv-mcp (SQ-187). It
replaces `bv-intelligence`, bv-web-prod's database, on which bv-mcp is the only
remaining writer. `bv-intelligence` stays live until the
[§3a cut-over](../operator-runbook.md#3a-moving-the-access-log-to-mcp-access-log-v1-sq-187-cut-over)
and is decommissioned after it. The binding **name** is unchanged; only the
`database_name`/`database_id` behind it in the private overlay moves.

A new database gets the consolidated baseline, which already carries every
enrichment (0002) and `source` (0003) column:

```bash
npx wrangler d1 create mcp-access-log-v1 --location oc
npx wrangler d1 execute mcp-access-log-v1 --remote --file scripts/access-log/sql/0001_baseline.sql
npx wrangler d1 execute mcp-access-log-v1 --remote --file scripts/access-log/sql/0002_drop_unused_indexes.sql
```

`0002_drop_unused_indexes.sql` (SQ-500) drops the three `mcp_access_log` indexes
no query uses (`country`, `domain`, `ip_masked`). D1 bills each index entry as a
row written, on insert and again on the retention delete, so every logged call
costs 3 index entries instead of 6 afterwards. It is idempotent (`DROP INDEX IF
EXISTS`), so apply it to an existing database too. Its targets are `bv-intelligence`
(the live database until the [§3a cut-over](../operator-runbook.md#3a-moving-the-access-log-to-mcp-access-log-v1-sq-187-cut-over))
and `mcp-access-log-v1` (after it). The saving lands only once 0002 has been applied
to the database the `INTELLIGENCE_DB` binding currently resolves to. Apply it before a bulk
copy so the copy does not pay for the dead indexes either. The file lists, per
index, which query keeps or loses it.

Do **not** replay `scripts/intelligence/sql/0001`–`0003` on a new database. The
live table drifted from that chain (`ip_masked` is `NOT NULL`, and the index set
differs), and the baseline reproduces live, not the chain. Those files remain the
history of the old database. `scripts/intelligence/sql/0004_mcp_access_rollup.sql` is optional and
separate; the rollup is off.

To enable the rollup, apply `0004_mcp_access_rollup.sql` first, then set
`ANALYTICS_ROLLUP_INTERNAL=true`. The flag now reaches both the public `/mcp`
recorder and the internal door (`/internal/tools/{call,batch}`), which is the only
source of `source = 'internal'` traffic, so those rescans increment a daily counter
instead of inserting one `mcp_access_log` row each. While the flag is unset the
15-minute provisioning probe (`checkAccessRollupProvisioned`) does nothing; once it
is `true` and the table is missing, the probe alerts.

A deploy against an unmigrated database is refused.
`scripts/access-log-schema-preflight.mjs` runs in `deploy:prod`,
`deploy:prod:staged` and `scripts/deploy-private.mjs`, and fails the deploy unless
the database behind `INTELLIGENCE_DB` has every column the Worker writes. Without
it, every access-log insert would throw inside a fire-and-forget: total, silent
row loss. To move an existing deployment's rows across, follow
[operator-runbook.md §3a](../operator-runbook.md#3a-moving-the-access-log-to-mcp-access-log-v1-sq-187-cut-over).

## 2. Add the queue producer + consumer (private overlay)

The queue is **operator-deploy only**. Declare it in the ignored
`.dev/wrangler.deploy.jsonc` overlay (merged into `wrangler.production.jsonc` by
`scripts/inject-private-config.cjs` at deploy time). It is **not** committed and
**not** present on BSL self-hosts — absent → the producer falls back to an inline
insert (degraded: no PTR lookup), no regression.

```jsonc
{
  "queues": {
    "producers": [{ "binding": "MCP_ANALYTICS_QUEUE", "queue": "mcp-analytics-queue" }],
    "consumers": [
      {
        "queue": "mcp-analytics-queue",
        "max_batch_size": 50,
        "max_retries": 2
      }
    ]
  }
}
```

Notes:

- **No `dead_letter_queue`** — by design. Terminal failures drop fail-open so a
  raw IP never lingers in queue/DLQ storage. Pair that with the low
  `max_retries: 2`.
- `max_batch_size: 50` bounds the per-invocation PTR DNS subrequests well under
  the paid-plan ceiling and bounds how long any raw IP sits in the queue.

Create the queue first if it does not exist:

```bash
npx wrangler queues create mcp-analytics-queue
```

## 3. Set the operator config env vars (private overlay)

Add to the same ignored overlay (do **not** commit):

- **`ANALYTICS_PII_LEVEL`** — `coarse` | `standard` | `full`. Recommend `full`
  for BlackVeil-prod. **Leave unset on BSL self-hosts** → defaults to `coarse`
  (the minimum-capture, self-host-safe level).
- **`ANALYTICS_RETENTION_DAYS`** (optional) — overrides the default 90-day prune
  in the cron (`src/scheduled.ts`).

The `standard`+ levels also require `MCP_ACCESS_LOG_IP_ENCRYPTION_KEY` (+ version)
in the **consumer** env so the consumer can write `ip_ciphertext`. A
missing/invalid key disables ciphertext only (rows still written), fail-open.

## 4. Deploy

```bash
npm run deploy:prod
```

This runs `scripts/inject-private-config.cjs`, merging the public `wrangler.jsonc`
with the private overlay above, then the access-log schema preflight from §1
against the merged config.

## 5. PII-level reference

`ANALYTICS_PII_LEVEL` gates which columns the producer (inline fallback) and the
consumer populate. Each level is additive over the one before it (see design
§5.4).

| Level                  | Columns populated                                                                       |
| ---------------------- | --------------------------------------------------------------------------------------- |
| `coarse` (default)     | country, region, ASN / org, `ip_hash`, `ip_masked`. No city, lat/long, PTR, ciphertext. |
| `standard`             | coarse **+** `ip_ciphertext` (recoverable) **+** city.                                  |
| `full` (BlackVeil-prod) | standard **+** latitude / longitude **+** PTR reverse-DNS (`ptr_hostname`).             |

## 6. Privacy note

The raw client IP **transits the queue** (same Cloudflare trust boundary as the
Worker; messages are ephemeral and deleted on ack) so the consumer can compute
PTR and encrypt at rest. The raw IP is **never persisted** — only `ip_hash`,
`ip_masked`, and `ip_ciphertext` reach D1.

IP recovery is possible **only** via `GET /internal/analytics/forensics`, which
is strict-gated (credential-minting-tier bearer; 503 if `BV_WEB_INTERNAL_KEY`
unset, 401 on missing/wrong) and **self-audited** — every decrypt writes an
`analytics.forensics.decrypt` audit row recording who decrypted which window. The
bv-web dashboard reads only the safe `usage` (D1) and `geo` (AE) endpoints and
never calls `forensics`.
