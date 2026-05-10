# Tenant operations runbook

Operator + on-call reference for the tenant enterprise pipeline (Phases 0–6).
Audience: anyone provisioning sub-tenants, responding to alerts, or
debugging production. Read CLAUDE.md (esp. **Bindings**, **Internal
routes**, **Analytics & Observability**) first.

---

## 1. Provision a new sub-tenant

The CLI handles D1 creation + migrations + registry insert + API key.

```bash
npm run tenants:provision -- \
  --super-tenant=super-tenant-1 \
  --sub-tenant=tenant-pilot-1 \
  --display-name="Pilot Tenant 1" \
  --dry-run
```

Dry-run prints every wrangler call + INSERT. Re-run without `--dry-run`
to commit. The mint:

- Creates a `tenant-db-tenant-pilot-1` D1 (Cloudflare API).
- Applies every `src/tenants/db/migrations/tenant/*.sql` against it.
- Inserts a `sub_tenants` row in the registry D1.
- Generates a 64-hex API key (`crypto.randomBytes(32)`), stores
  `sha256(key)` in `tenant_keys`, prints the raw key **once** to
  stdout. **Save it now — never shown again.**
- Emits the wrangler binding stanza you must paste into
  `.dev/wrangler.deploy.jsonc` under `d1_databases`.

**After mint** — paste the binding, then `npm run deploy:private`. The
new tenant is live on the next request.

**Rotation** — re-run the script with the same `--sub-tenant` after
deleting the existing `tenant_keys` row. (No automated rotation yet.)

---

## 2. Cron schedule

| Trigger | Cadence | Handler | Source |
|---|---|---|---|
| Analytics + fuzzing alert sweep | every 15 min | `handleFuzzingScan` | `src/scheduled.ts` |
| Tenant weekly rescan dispatch | Sun 02:00 UTC | `handleTenantWeeklyRescan` | `src/tenants/scheduled-handlers.ts` |
| Tenant cycle-alert sweep | every 15 min | `handleTenantCycleAlerts` | `src/tenants/scheduled-handlers.ts` |

Wrangler config: `wrangler.jsonc` under `[triggers.crons]`. Never run two
weekly dispatchers concurrently — duplicate cycles inflate audit + queue
load. The `tenant_cycles` registry row prevents double-alerting via
`alert_sent_at` partial index.

---

## 3. Reading the alerts

The cycle-alert sweep posts JSON to `ALERT_WEBHOOK_URL` (Slack/Discord)
when a completed cycle's findings differ from the prior cycle.

Schema: `src/schemas/tenant-alerts.ts` → `TenantCycleAlertSchema`. Key fields:

- `totals.deltas` — total finding changes vs baseline.
- `totals.by_severity` — counts grouped (critical → info).
- `highlights[]` — top 20 deltas, severity-descending, with `delta:
  'gained' | 'lost' | 'severity_changed'`.
- `webhook_url_hash` — FNV-1a of the webhook URL itself (lets you dedup
  alerts across multiple receivers without leaking the URL).

**Triage rules:**

- ≥1 `critical gained` → page on-call.
- `severity_changed` upward (e.g. medium → high) on a customer-public
  domain → notify SOC.
- All `lost` deltas → no action; customers fixed something.
- `webhook_url_hash` repeats with identical `current_cycle_id` → check
  `tenant_cycles.alert_outcome`, the alerter is retrying because the prior
  attempt got `webhook_failed`.

---

## 4. Audit log

Every cross-tenant `/internal/tenants/*` call writes to `audit_events` in the
**registry** D1 via `recordAuditEvent`. Read with:

```bash
npx wrangler d1 execute tenant-registry --remote \
  --command "SELECT timestamp, action, sub_tenant_id, resource_id, outcome FROM audit_events WHERE sub_tenant_id='tenant-pilot-1' ORDER BY timestamp DESC LIMIT 50;"
```

Indexed dimensions for fast filtering: `(super_tenant_id, timestamp
DESC)`, `(sub_tenant_id, timestamp DESC)`, `(actor_principal, timestamp
DESC)`, `(action, timestamp DESC)`.

`actor_principal` — `keyHash(bearer)` for service-binding callers,
`'anonymous'` only if the request escaped the auth gate (should not
occur when `REQUIRE_INTERNAL_AUTH=true` is live; treat any 'anonymous'
row as an alert).

`actorTier` is currently hardcoded `'partner'` for all internal-route
callers. OAuth-tier propagation is a tracked TODO; do not rely on this
field for entitlement decisions.

---

## 5. Scanner queue troubleshooting

The queue consumer (`src/tenants/queue-consumer.ts`) is idempotent and
fail-soft:

| Symptom | Likely cause | Action |
|---|---|---|
| `tenant_cycles.completed_total` stalls below `expected_total` | Consumer hitting per-message timeout (20s) | Inspect `findings` rows with `category='queue'` for that cycle — `severity:high, title:'queue_dlq'` rows mark domains that exhausted retries. |
| Alert never fires for a cycle | No baseline cycle exists | First-cycle behaviour; `alert_outcome='skipped_no_baseline'`. Subsequent cycles will alert. |
| Webhook 5xx loops | Receiver outage | `alert_sent_at` is set even on `webhook_failed` outcome to prevent retry storms — re-trigger manually after fix: `UPDATE tenant_cycles SET alert_sent_at=NULL WHERE id='...';` |
| Duplicate scan rows for `(cycle_id, domain)` | Should not happen — UNIQUE index `idx_scans_cycle_domain_unique` enforces this | If it occurs: D1 schema drift. Check the migration applied successfully via `wrangler d1 execute --command "SELECT sql FROM sqlite_master WHERE name='idx_scans_cycle_domain_unique'"`. |

**Manually drain a stuck cycle**: queue messages older than 7 days are
auto-DLQ'd by the consumer. Force a re-dispatch by:

```bash
# 1. Mark cycle complete to stop the alert sweep waiting on it
npx wrangler d1 execute tenant-registry --remote \
  --command "UPDATE tenant_cycles SET completed_total=expected_total, alert_outcome='manual_drain' WHERE id='<cycle_id>';"
# 2. Re-trigger weekly dispatcher manually if needed (hits next Sunday 02:00 UTC otherwise)
```

---

## 6. Per-tenant rate limits

Limits live in `src/tenants/per-tenant-rate-limit.ts` `PER_TENANT_QUOTAS`:

| Tier | scans/day | portfolio req/min | report req/min |
|---|---|---|---|
| `default` | 100 000 | 30 | 60 |
| `enterprise` | 2 500 000 | 120 | 300 |

KV-backed, fail-soft. When `RATE_LIMIT` KV is unbound (e.g.
`wrangler dev`), the limiter returns `allowed:true`. To override per
sub-tenant, either bump the tier in `tenant_keys.scope` or override the
quota constant for a custom build.

429 responses include `Retry-After` (seconds until window reset) and a
`'denied'` audit row.

---

## 7. Capacity & cost

Empirical (from `reports/tenant-calibration-*.json`):

- Warm-cache scan: ~130ms p50.
- Mixed-portfolio cold scan: ~12.5s p50, ~25s p95.
- 2.5M domains @ concurrency 50 × 20: ~8.7h sustained.

Cost-driver checks before a new pilot:

- D1 row writes: ~16 findings × 100K domains × 4 cycles/month = 6.4M
  rows/month per tenant. Free-tier ceiling is 100M total writes; budget
  accordingly.
- Queue messages: 1 per domain per cycle. CF Queues bills per million.
- Worker invocations: scan + persistence ~ 1.5 invocations / domain / cycle.

---

## 8. On-call escalation

| Severity | Trigger | Page? |
|---|---|---|
| **P0** | `/health` returns non-200 for >2 min | Yes — operator + on-call SRE. |
| **P1** | Cycle-alert webhook persistently `webhook_failed` (≥3 consecutive cycles) | Operator only. |
| **P2** | DLQ row count for a single cycle exceeds 5 % of `expected_total` | Triage Mon AM. |
| **P3** | Audit row `actor_principal='anonymous'` on `/internal/tenants/*` | Investigate auth-gate config; do NOT page. |

Logs: `npx wrangler tail bv-dns-security-mcp --format json` for
near-real-time. Analytics dashboards: see `src/lib/analytics-queries.ts`.

---

## 9. Deprecated / known gaps

- **OAuth-tier audit attribution** — `actorTier` hardcoded `'partner'`.
  Tracked.
- **No automated key rotation** — mint a new tenant_keys row + delete
  the old manually.
- **No bv-web admin UI yet** — Phase 5 lives in the bv-web repo. Use
  wrangler CLI + this runbook.
- **Phase 6 fingerprint pre-flight is always active** — manual and queued scans via `POST /internal/tenants/scan` automatically skip execution if the domain's DNS fingerprint is unchanged and a scan exists from the last 24h. Use `force_refresh: true` in the API to bypass it.
