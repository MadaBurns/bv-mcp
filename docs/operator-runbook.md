# Operator Runbook — bv-mcp platform operations

Platform-level procedures for anyone operating the hosted deployment. Tenant-level
operations (tenant D1 restore drills, erasure, quota sharding) live in
[tenant-ops-runbook.md](./tenant-ops-runbook.md). All commands assume Node 22+ and
repo root. Nothing here contains real IDs or hostnames — actual values live in the
operator secret manager.

## 1. Deploying (any operator, not just the primary)

Prerequisites:

1. `npm ci` on Node 22+.
2. `npx wrangler login` against the production Cloudflare account.
3. Reconstruct `.dev/wrangler.deploy.jsonc` (gitignored, machine-local). It is the
   private overlay merged over the public `wrangler.jsonc` by
   `scripts/inject-private-config.cjs`, and must supply every private binding kind
   the script enumerates (vars, kv_namespaces, r2_buckets, services,
   durable_objects, queues, d1_databases, analytics_engine_datasets). The
   authoritative copy of this file's current contents is stored in the operator
   secret manager under `bv-mcp/deploy-overlay`; KV/D1/queue IDs can be
   re-derived from the Cloudflare dashboard if the secret-manager copy is stale
   (stale KV IDs → wrangler 422 on deploy).
4. Secrets (`wrangler secret list` to see which are set): BV_API_KEY,
   OAUTH_SIGNING_SECRET, BV_WEB_INTERNAL_KEY, BV_RECON_KEY, BV_TLS_PROBE_KEY,
   BV_BROWSER_RENDERER_KEY, KV_ENVELOPE_KEY, MCP_ACCESS_LOG_IP_ENCRYPTION_KEY,
   BV_DOH_TOKEN, CF_ANALYTICS_TOKEN. Values in the secret manager; secrets
   survive deploys (only re-`put` when rotating).

Deploy:

    npm run deploy:prod

Verify (MANDATORY after every deploy):

    curl -s https://<worker-host>/mcp -X POST -H 'content-type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"deploy-check","version":"0"}}}' \
      | grep -o '"version":"[^"]*"'

The reported serverInfo version must match `package.json`.

## 2. Rolling back a bad deploy

Workers keeps prior versions. Fastest path:

    npx wrangler deployments list          # find the last-good version id
    npx wrangler rollback                  # interactive; or pass the version id

Caveats:

- Rollback restores CODE + bound config as of that version; it does NOT revert
  KV/D1 data or secrets. If the bad deploy ran a D1 migration, see §3.
- If the bad deploy came from a bad overlay (not bad code), fix
  `.dev/wrangler.deploy.jsonc` and redeploy forward instead.
- After rollback, re-run the §1 verification and re-deploy forward from a fixed
  commit as soon as possible — rollback is a stopgap, not a state.

## 3. D1 backup & restore (INTELLIGENCE_DB, BRAND_AUDIT_DB)

Posture: **D1 Time Travel is the primary recovery mechanism** (30-day
point-in-time window on the paid plan, zero standing cost), with monthly manual
exports as a belt-and-braces archive.

Point-in-time restore (DESTRUCTIVE — restores the whole DB to the bookmark):

    npx wrangler d1 time-travel info <db-name> --timestamp <unix-or-iso>
    npx wrangler d1 time-travel restore <db-name> --bookmark <bookmark-id>

Monthly export (store in the operator vault, not the repo):

    npx wrangler d1 export <db-name> --remote --output <db-name>-$(date +%Y%m%d).sql

Restore rehearsal (do quarterly; ~15 min):

1. `npx wrangler d1 create restore-drill-tmp`
2. `npx wrangler d1 execute restore-drill-tmp --remote --file <latest-export>.sql`
3. Row-count sanity: `npx wrangler d1 execute restore-drill-tmp --remote --command "SELECT count(*) FROM mcp_access_log"`
4. `npx wrangler d1 delete restore-drill-tmp`
5. Log the drill date + outcome in the operator vault.

Note: the access-log retention cron hard-DELETEs rows past
`ANALYTICS_RETENTION_DAYS`; enable `ANALYTICS_ARCHIVE_ENABLED=true` +
`MCP_ACCESS_LOG_ARCHIVE` R2 binding if pre-deletion archiving is wanted.

## 4. Spend monitoring (operator console — one-time setup)

- [ ] Cloudflare dashboard → Notifications → create **Usage Based Billing**
      alerts for: Workers requests, Workers subrequests, D1 rows read/written,
      R2 storage + Class A ops, Queues operations, Browser Rendering usage.
      Route to the ops email + the alert webhook.
- [ ] Set a monthly account **billing threshold** notification.
- [ ] Record thresholds chosen + date configured in the operator vault.

In-app levers if spend spikes: `GLOBAL_DAILY_TOOL_LIMIT` env var (clamped [10000, 5000000] once the runtime wiring for it has shipped — verify with `grep -n "options.globalDailyLimit ?? GLOBAL_DAILY_TOOL_LIMIT" src/mcp/execute.ts` before relying on it during an incident), per-tool `FREE_TOOL_DAILY_LIMITS`, `SCAN_TIMEOUT_MS`. Queue-heavy features degrade to `unprovisioned` if their
bindings are removed from the overlay — the blunt but immediate kill switch.

## 5. Queue dead-lettering (decision record + optional setup)

- `MCP_ANALYTICS_QUEUE`: **deliberately no DLQ** — messages carry raw IP
  pre-encryption; a DLQ would persist raw PII outside the encrypt path. Failed
  messages drop (fail-open). Do not add a DLQ here.
- `BRAND_AUDIT_QUEUE` / `BRAND_AUDIT_PDF_QUEUE`: currently `max_retries: 3` then
  drop; the stuck-job reaper marks orphaned audits failed. To add DLQs:

      npx wrangler queues create brand-audit-dlq
      # then in .dev/wrangler.deploy.jsonc, on each consumer:
      #   "dead_letter_queue": "brand-audit-dlq"

  and add DLQ depth to the §4 notification set. Until then, this is a recorded,
  accepted tradeoff: a dropped brand-audit job surfaces as a failed audit the
  customer can re-run.

## 6. R2 report retention (operator console — one-time setup)

Brand-report PDFs currently never expire. Set a bucket lifecycle rule (align
with the customer-facing retention promise; 180 days suggested):

    npx wrangler r2 bucket lifecycle add <brand-reports-bucket> --expire-days 180

Verify: `npx wrangler r2 bucket lifecycle list <brand-reports-bucket>`.

## 7. Alerting dead-man switch (operator console — one-time setup)

The 15-min cron self-alerts through the webhook when its AE queries fail, but
nothing external notices if the cron itself stops or the webhook config is
unset. Set up an external heartbeat:

- [ ] Cloudflare dashboard → the worker → Settings → Triggers: confirm the cron
      trigger exists after every deploy (the overlay must carry it).
- [ ] Configure a Cloudflare **Health Check** (or healthchecks.io ping) against
      `GET /health` with alerting to the ops email.

## 8. Secret rotation quick reference

| Secret | Rotate with | Coordinate |
| ------ | ----------- | ---------- |
| `BV_WEB_INTERNAL_KEY` | `npx wrangler secret put BV_WEB_INTERNAL_KEY` | Set the SAME value in bv-web-prod first (it is the caller); brief 401 window is expected |
| `BV_API_KEY` | `npx wrangler secret put BV_API_KEY` | Update Claude Desktop MCPB extension/connector configs |
| `OAUTH_SIGNING_SECRET` | `npx wrangler secret put OAUTH_SIGNING_SECRET` | Invalidates ALL outstanding OAuth JWTs — customers re-consent |
| `MCP_ACCESS_LOG_IP_ENCRYPTION_KEY` | `npx wrangler secret put ...` + bump `MCP_ACCESS_LOG_IP_KEY_VERSION` | Old ciphertexts need the old key retained in the vault for forensics |

## 9. Incident quick path

1. Symptom triage: `npx wrangler tail` (live) / Workers dashboard logs.
2. Bad deploy → §2 rollback. Data damage → §3 Time Travel.
3. Cost/abuse spike → §4 levers.
4. Leaked secret → §8 rotation, then check `/internal/analytics/forensics`
   (strict bearer) for misuse windows.
5. Post-incident: note timeline + actions in the operator vault.
