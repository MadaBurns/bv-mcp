# Tenant Operations Runbook

> Platform-level operations (deploy, rollback, restore, spend): see [operator-runbook.md](./operator-runbook.md).

Public-safe reference for the tenant pipeline. Keep real tenant IDs, customer
names, Cloudflare resource IDs, private queue/database names, and emergency
procedures in ignored operator notes, not in this repository.

## Provisioning

Use the tenant provisioning CLI with placeholder IDs in examples:

```bash
npm run tenants:provision -- \
  --super-tenant=super-tenant-example \
  --sub-tenant=tenant-example \
  --display-name="Example Tenant" \
  --dry-run
```

Dry-run prints the planned Cloudflare and registry operations. When run without
`--dry-run`, the command creates a tenant database, applies migrations, inserts
registry rows, and prints the raw tenant API key once. Store real keys in an
approved secret manager only.

Private deployment bindings belong in `.dev/wrangler.deploy.jsonc`, which is
ignored and merged into `wrangler.production.jsonc` at deploy time.

## Production Overlay Gates

`npm run deploy:prod` runs `scripts/inject-private-config.cjs` before Wrangler.
The injector must fail closed unless the private overlay provides these
production safety vars:

- `OAUTH_ISSUER`: `https://dns-mcp.blackveilsecurity.com`.
- `REJECT_QUERY_API_KEY`: `true`, so hosted production ignores URL credentials.
- `REQUIRE_PRODUCTION_BINDINGS`: `true`, so `/health?deep=1` degrades on missing
  tenant, brand-audit, queue, storage, or alert bindings.
- `ALERT_WEBHOOK_URL`: non-empty. Keep the real webhook URL in the ignored
  overlay or secret manager, never in tracked docs.

Run `npm run deploy:prod` from a clean checkout. If the injector rejects the
overlay, fix the private deployment config instead of bypassing the gate.

## Scheduled Work

Tenant jobs are handled by scheduled handlers:

| Job | Cadence | Handler |
|---|---|---|
| Analytics and fuzzing alert sweep | every 15 minutes | `handleFuzzingScan` |
| Tenant weekly rescan dispatch | weekly | `handleTenantWeeklyRescan` |
| Tenant cycle-alert sweep | every 15 minutes | `handleTenantCycleAlerts` |

Cron expressions live in `wrangler.jsonc`. Avoid running duplicate dispatchers
for the same tenant cycle.

## Alerts

Cycle alerts are sent to `ALERT_WEBHOOK_URL` when a completed cycle differs
from its baseline. See `src/schemas/tenant-alerts.ts` for the payload schema.

General triage:

- Critical findings gained: urgent operator review.
- Severity increased on customer-owned domains: notify the owning team.
- Only lost findings: usually no action.
- Repeated webhook hashes with the same cycle ID: inspect webhook delivery.

## Audit Log

Cross-tenant `/internal/tenants/*` calls write audit rows through
`recordAuditEvent`. Use placeholder tenant IDs in shared docs:

```bash
npx wrangler d1 execute <tenant-registry-db> --remote \
  --command "SELECT timestamp, action, sub_tenant_id, resource_id, outcome FROM audit_events WHERE sub_tenant_id='tenant-example' ORDER BY timestamp DESC LIMIT 50;"
```

Treat unexpected anonymous internal-route audit rows as an authentication
configuration issue.

## Queue Troubleshooting

The queue consumer in `src/tenants/queue-consumer.ts` is idempotent and
fail-soft. Common checks:

| Symptom | Likely cause | Action |
|---|---|---|
| Cycle stalls below expected total | Consumer timeout or exhausted retries | Inspect queue-category findings for the cycle. |
| Alert never fires for first cycle | No baseline yet | Wait for the next completed cycle. |
| Webhook failures repeat | Receiver outage | Fix receiver, then re-trigger deliberately. |
| Duplicate cycle/domain rows | Schema drift | Verify the unique index migration. |

## Rate Limits

Per-tenant limits live in `src/tenants/per-tenant-rate-limit.ts`. The limiter is
KV-backed and fail-soft in local development when `RATE_LIMIT` is unbound. Use
tenant scope/tier data, not hardcoded customer identifiers, when changing
limits.

## Data Lifecycle and Recovery

Use bounded, operator-owned procedures for tenant data. Keep real identifiers and
export locations in ignored notes.

- retention: access-log rows are pruned by the scheduled job according to
  `ANALYTICS_RETENTION_DAYS` or the 90-day default. Tenant scan/finding retention
  should be set per contract in the private tenant inventory before provisioning.
- export: use D1 export or read-only SQL against placeholder tenant IDs first,
  then write customer exports only to approved private storage. Do not commit
  exports, generated reports, PDFs, CSC output, or tenant databases.
- erasure: deactivate the `sub_tenants` row, revoke tenant keys, stop scheduled
  scans, delete or tombstone per-tenant D1 data under the approved retention
  policy, then record the operator action in the registry audit log.
- restore drill: at least once per release window that changes tenant schema or
  migrations, restore a synthetic tenant backup into a disposable D1 database,
  run the tenant schema/audit tests, and verify a queued scan can complete.

## Cost Governance

Quota changes must be explicit and audited. The public quota maps in
`src/lib/config.ts` are the SSOT for daily tool limits; brand audit has an
additional monthly quota in `src/lib/brand-audit-quota.ts`.

- identity-secops tools are paid-only and capped per principal because they proxy
  Microsoft Graph-backed M365 reads through bv-web.
- brand audit writes are capped daily and monthly; async starts debit quota at
  submission time, not in the queue consumer.
- weekly tenant rescans cap active-tenant and due-domain enumeration per tick.
- alert on quota-coordinator fallback, tail exceptions, and repeated queue
  failures before raising any cap.

## QuotaCoordinator sharding cutover

The per-IP / per-principal quota counters can be sharded off the single
`global-quota-coordinator` Durable Object onto `QUOTA_SHARD_COUNT` (16) instances
to lift the single-DO throughput ceiling. This is **disabled by default** and
gated behind a feature flag.

Bindings (`vars`, plus one secret):

- `QUOTA_SHARDING_ENABLED` — set to the exact string `"true"` to enable. Unset or
  anything else keeps every quota check on the singleton (today's behavior).
- `QUOTA_SHARD_SALT` — a deploy-time secret mixed into the shard-key hash so an
  IP-range / botnet operator cannot precompute which addresses map to a shard.
  Store it in the secret manager; do not commit it.

**One-time cutover relaxation (must be signed off before flipping).** There is no
dual-read. The instant routing moves to the shards, every per-IP / per-principal
counter reads from a fresh, zeroed shard, so each counter grants up to **one extra
window of allowance, once**:

- `tool-daily` → up to **one full extra day** of per-tool free quota for every free
  caller.
- per-IP minute / hour rate limits → up to one extra minute / hour.
- The **global-daily cost ceiling does NOT reset** — it stays on the singleton and
  remains exact.

Because the free-tier per-IP / per-tool caps are the abuse control, the relaxation
is bounded but real. Treat the flip as a release gate.

Cutover procedure:

1. Ship the code with the flag OFF (a normal release). Behavior is unchanged.
2. Deploy dark via `npm run deploy:prod` (rebuild dns-checks first). Flag still OFF.
3. Pick a **low-traffic window**. Set `QUOTA_SHARDING_ENABLED=true` (and
   `QUOTA_SHARD_SALT`) and redeploy (or update the runtime var).
4. Watch the `degradation` analytics dataset (`quota_coordinator_fallback`
   component) and the `rate_limit` analytics for the next windows.
5. **Rollback lever:** if shards misbehave or the degradation rate spikes, set
   `QUOTA_SHARDING_ENABLED=false` — routing returns to the singleton with no code
   redeploy.

`QUOTA_SHARD_COUNT` is a **frozen constant** for the life of a deployment. Changing
it (or the salt) re-maps every caller's shard and strands its in-flight counter —
that is the SAME windowed-relaxation event as the initial flip, not a hot edit.
Schedule it the same way and run `resetQuotaCoordinatorState()` to sweep stranded
shard counters if needed.

## Security Notes

- Do not commit real tenant IDs, target lists, queue names, database IDs, bearer
  tokens, webhook URLs, or production-only binding values.
- Keep generated production config ignored.
- Use synthetic domains under reserved namespaces such as `example.test` for
  tests, fixtures, and docs.
- Internal route examples should use placeholders and require
  `BV_WEB_INTERNAL_KEY` from the environment.
