# Detailed Analytics Capture Provisioning

Public-safe operator runbook for the enriched `mcp_access_log` analytics path
(queue-batched producer/consumer, gated PII depth, D1 report endpoints). Keep
real Cloudflare database IDs, queue names, encryption keys, account details, and
bearer tokens in ignored deployment notes — never in this repo.

Design reference: `docs/superpowers/specs/2026-06-26-detailed-analytics-capture-design.md`.

## 1. Apply the enrichment migration FIRST

Run the additive migration **before** deploying the enriched consumer. All new
columns are nullable, so this is safe on the existing populated table (existing
rows and the inline-fallback insert keep working). A lagging migration would
otherwise make the consumer's INSERT fail (logged, fail-open) rather than corrupt
data.

```bash
wrangler d1 execute bv-intelligence --remote --file scripts/intelligence/sql/0002_mcp_access_log_enrich.sql
```

`bv-intelligence` is a placeholder — substitute the project-approved private
`INTELLIGENCE_DB` database name.

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
with the private overlay above.

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
