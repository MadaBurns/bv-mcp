# Tenant Global — Scalable Architecture Design

**Status:** internal design doc, gitignored. Not for distribution.
**Date:** 2026-05-09
**Companion to:** `redacted-tenant-Call-Prep.md`, `Tenant-Capacity-and-Discovery-Design.md`
**Author:** Adam (founder) + Claude

---

## TL;DR

A Cloudflare-native multi-tenant scanner sitting behind the existing bv-mcp Worker. Per-customer D1 isolation, shared scanner pool, queue-driven batch processing, weekly monitoring runs, and on-demand registrar-discovery. Designed for **Tenant = super-tenant managing 50–500 sub-tenants × 5K–50K domains each (median customer)** with the headline 2.5M-domain customer treated as the upper bound.

| Property | Target | How |
|---|---|---|
| **Scale** | 50M domains/month aggregate | Workers + Queues, horizontal isolate-per-batch |
| **Cost** | <$0.0001 / domain-scan amortised | Aggressive cache, idle-fallback DoH, tiered storage |
| **Latency (initial scan)** | p95 < 24h for any portfolio ≤ 2.5M | Concurrency=50, 20 batches, 80 scans/sec sustained |
| **Latency (monitoring delta)** | p95 < 1h per 100K-domain customer | Differential re-scan, only re-run changed-DNS records |
| **Security** | Per-customer data isolation | One D1 per sub-tenant + per-tenant API keys |
| **Reliability** | 99.5% scan-completion / 99.9% API-availability | Promise.allSettled, partial-result writes, retry queues |

**Verdict:** all four properties (robust / scalable / cheap / secure) are achievable on Cloudflare's stack today without spinning up dedicated infrastructure. Build is **~5 weeks for v1** building on the current scanner.

---

## 1. Use cases (in priority order)

| # | Use case | Trigger | Output | Frequency |
|---|---|---|---|---|
| 1 | **Initial portfolio audit** | Tenant onboards a new customer | Per-domain scan + risk-graded report | One-shot |
| 2 | **Ongoing monitoring** | Cron (weekly default) | Delta report: what changed, what's new, alerts | Continuous |
| 3 | **Registrar discovery** | Tenant requests, or scheduled monthly | Candidate domains owned at non-Tenant registrars + their risk | On-demand |
| 4 | **Compliance mapping** | Tenant renewal pitch | NIST/PCI/SOC2/CIS heatmap | On-demand |
| 5 | **Lookalike / typosquat detection** | Brand protection product | List of candidates + active-mail signal | Weekly |
| 6 | **Real-time API access** | Tenant's customer-facing portal embeds our data | JSON API + webhook for changes | Live |
| 7 | **Per-customer SaaS tier** | Tenant resells direct access | Tenant dashboard + report exports | On-demand |
| 8 | **Bulk certificate-expiry alerts** | DNS hygiene service add-on | Slack/email notification | Continuous |

Use cases 1–3 are the **must-haves** for the Tenant pitch. 4–8 are upsells from the same data store.

---

## 2. Architectural overview

```
                           ┌──────────────────────────────┐
                           │  Tenant Account Manager Portal  │
                           │  (Tenant's existing UI)         │
                           └──────┬───────────────────────┘
                                  │  HTTPS + OAuth (super-tenant token)
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│  bv-web admin-v3 (Cloudflare Workers)                        │
│  /admin-v3/business.tenant.<route>.tsx                          │
│  - tenant management (Tenant's customer list)                   │
│  - portfolio upload (CSV / API)                              │
│  - report download                                            │
│  - discovery requests                                         │
│  - billing / metering                                        │
└──────────┬───────────────────────────────────────────────────┘
           │  Service binding (BV_MCP)
           ▼
┌─────────────────────────────────────────────────────────────┐
│  bv-mcp NEW: enterprise-orchestrator (Cloudflare Workers)    │
│  /internal/tenant/<endpoint>                                    │
│  - tenant resolution                                         │
│  - portfolio chunking (100 domains per batch)                │
│  - dispatch to scanner queue                                 │
│  - aggregate results                                         │
│  - serve reports (JSON / CSV / PDF stub)                     │
└─────┬─────────────────────────────────┬─────────────────────┘
      │                                  │
      │  Cloudflare Queue                │  Cloudflare D1 (one DB per tenant)
      ▼                                  ▼
┌──────────────────┐              ┌──────────────────────┐
│ scanner-queue-A  │              │ tenant_<id>_results  │
│ scanner-queue-B  │              │   - domains          │
│ scanner-queue-N  │              │   - scans            │
│ (auto-scaled)    │              │   - findings         │
└─────┬────────────┘              │   - discoveries      │
      │                            │   - alerts          │
      ▼                            └──────────────────────┘
┌─────────────────────────────────┐         ▲
│  bv-mcp scanner Worker (existing)│        │
│  /internal/tools/batch          │         │  result-writer
│  - scan_domain × N parallel     │─────────┘
│  - delegates DoH to BV_DOH       │
│  - emits results to writer queue │
└─────────────────────────────────┘
                                   ┌──────────────────────┐
                                   │  Shared registry D1  │
                                   │  - tenants           │
                                   │  - tenant_keys       │
                                   │  - billing_events    │
                                   │  - global metadata   │
                                   └──────────────────────┘
```

### 2.1 Component responsibilities

| Component | Lives in | Purpose |
|---|---|---|
| **bv-web admin** | bv-web Worker | UI + auth + tenant management |
| **enterprise-orchestrator** | new bv-mcp Worker (or new repo) | Per-customer batch coordination |
| **scanner queue** | Cloudflare Queues | Decouples ingestion from scanning, retries |
| **scanner Worker** | existing bv-mcp `/internal/tools/batch` | Actual `scan_domain` execution |
| **result-writer** | new bv-mcp Worker (queue consumer) | Persists to per-tenant D1 |
| **per-tenant D1** | Cloudflare D1 (one per sub-tenant) | Customer-isolated storage |
| **shared registry D1** | Cloudflare D1 | Tenant metadata, keys, billing |
| **DoH origin** | self-hosted (existing `BV_DOH_ENDPOINT`) | Bypasses public-resolver rate limits |

### 2.2 Why Cloudflare Queues (not direct service binding)

- **Backpressure:** orchestrator can dispatch 1M batch messages without blocking; scanner pool consumes at sustainable rate.
- **Retries:** Queues auto-retry on consumer error. Failed scans stay in DLQ for inspection rather than disappearing.
- **Decoupling:** scanner scaling independent from API request rate — orchestrator can be slow without dropping work.
- **Cost:** Queues are $0.40/million ops, immaterial vs scan cost.

### 2.3 Why per-tenant D1 (not shared schema)

- **Security:** Per-tenant DB binding means a bug in one tenant's code path can't read another tenant's data. Cloudflare's binding model enforces this at the platform level.
- **Compliance:** Clear data-residency / right-to-delete story (drop the DB).
- **Performance:** Each tenant's queries are isolated; no `WHERE tenant_id = ?` join hot-spots.
- **D1 quota:** **10 GB per database** (Cloudflare current). 2.5M domains × ~2 KB/scan-row = 5 GB — fits one big customer per DB. Median customer (50k domains, 1y weekly history) ~8 GB — also fits. **Headline customer (2.5M weekly for 1y) ~260 GB — needs sharding or R2 archival** (§5.3).
- **Disaster recovery:** Per-tenant point-in-time recovery via Cloudflare's automatic backups.

**Trade-off:** schema migrations need to fan-out across N databases. Mitigation: migration runner script + canary tenant.

**Adapter pattern (prior art: `webitte-hosting/emdash`):** wrap D1/R2/KV bindings with tenant-prefix-stamping adapters rather than passing `tenant_id` through every call. Pattern below: each tenant Worker has a `TENANT_PREFIX` env injected by the platform deployer, and adapters auto-stamp every read/write.

```ts
// src/tenant/adapters/tenant-d1.ts (planned)
export function tenantD1(binding: D1Database, prefix: string) {
  return {
    prepare: (sql: string) => binding.prepare(sql), // SQL is per-tenant DB, no prefix needed
    // For shared registry queries that need tenant scoping:
    select: (table: string) => binding.prepare(`SELECT * FROM ${prefix}_${table}`),
  };
}
export function tenantR2(binding: R2Bucket, prefix: string) {
  return {
    put: (k: string, v: ReadableStream) => binding.put(`${prefix}/${k}`, v),
    get: (k: string) => binding.get(`${prefix}/${k}`),
    list: (opt?: R2ListOptions) => binding.list({ ...opt, prefix: `${opt?.prefix ?? ''}${prefix}/` }),
  };
}
```

### 2.4 Tenant routing (prior art: `Cephra-dev/Cephra-Auth`)

Two complementary mechanisms:

1. **API-key based** (default): the bearer token resolves to a `super_tenant_id` + optional `sub_tenant_id`. Used by Tenant's portal and our service-binding clients.
2. **Hostname based** (Phase 2): customer-facing portal at `auth.tenant-acme.bv-mcp.com` → routes to Tenant A. Required for OAuth flows where users authenticate directly against bv-mcp without going through Tenant. Matches the `Cephra-Auth` pattern.

Hostname routing also enables **per-tenant JWKS** at `https://tenant-acme.bv-mcp.com/.well-known/jwks.json` so external systems can verify tokens we mint without round-tripping through us.

---

## 3. Data model

### 3.1 Shared registry D1

```sql
-- shared schema (one DB across all super-tenants)
CREATE TABLE super_tenants (
  id TEXT PRIMARY KEY,                    -- e.g. 'redacted-tenant'
  name TEXT NOT NULL,
  api_key_hash TEXT NOT NULL,             -- SHA-256 of API key
  d1_binding_prefix TEXT NOT NULL,        -- 'tenant_'  → wrangler binding `tenant_<sub_tenant_id>`
  rate_limit_per_minute INTEGER DEFAULT 1000,
  active BOOLEAN DEFAULT true,
  created_at INTEGER NOT NULL,
  metadata TEXT                            -- JSON blob: contact, billing, etc.
);

CREATE TABLE sub_tenants (
  id TEXT PRIMARY KEY,                    -- e.g. 'tenant-acme-corp'
  super_tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  d1_db_id TEXT NOT NULL,                 -- Cloudflare D1 database UUID
  domain_count INTEGER DEFAULT 0,
  scan_schedule TEXT,                     -- cron expression or null (one-shot only)
  scan_quota_per_month INTEGER,
  active BOOLEAN DEFAULT true,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (super_tenant_id) REFERENCES super_tenants(id)
);

CREATE TABLE tenant_keys (
  key_hash TEXT PRIMARY KEY,
  super_tenant_id TEXT NOT NULL,
  sub_tenant_id TEXT,                     -- NULL = super-tenant-wide access
  scope TEXT NOT NULL,                    -- 'read'|'admin'|'scan'
  expires_at INTEGER,
  revoked_at INTEGER,
  last_used_at INTEGER,
  FOREIGN KEY (super_tenant_id) REFERENCES super_tenants(id)
);

CREATE TABLE billing_events (
  id TEXT PRIMARY KEY,
  super_tenant_id TEXT NOT NULL,
  sub_tenant_id TEXT,
  event_type TEXT NOT NULL,               -- 'scan'|'discovery'|'monitoring'
  count INTEGER NOT NULL,
  cost_cents INTEGER,
  occurred_at INTEGER NOT NULL,
  FOREIGN KEY (super_tenant_id) REFERENCES super_tenants(id)
);

CREATE INDEX idx_billing_lookup ON billing_events(super_tenant_id, occurred_at);
```

### 3.2 Per-tenant D1

```sql
-- per-sub-tenant schema (one DB per customer)
CREATE TABLE domains (
  domain TEXT PRIMARY KEY,                -- normalised lowercase
  source TEXT NOT NULL,                   -- 'csv-upload'|'api'|'discovery'
  added_at INTEGER NOT NULL,
  last_scanned_at INTEGER,
  last_score INTEGER,
  last_grade TEXT,
  -- monitoring fields
  watch BOOLEAN DEFAULT true,
  watch_interval_hours INTEGER DEFAULT 168, -- weekly
  -- discovery fields
  is_candidate BOOLEAN DEFAULT false,     -- true = found via discovery, not seeded
  discovery_signals TEXT,                 -- JSON: ['ns','rua','dkim',...]
  discovery_confidence REAL               -- 0.0–1.0
);

CREATE TABLE scans (
  id TEXT PRIMARY KEY,                    -- UUID
  domain TEXT NOT NULL,
  scan_at INTEGER NOT NULL,
  score INTEGER,
  grade TEXT,
  maturity_stage INTEGER,
  finding_count INTEGER,
  result_json TEXT,                       -- compressed full ScanScore
  cycle_id TEXT,                          -- groups scans from one batch run
  FOREIGN KEY (domain) REFERENCES domains(domain)
);

CREATE INDEX idx_scans_domain_time ON scans(domain, scan_at DESC);
CREATE INDEX idx_scans_cycle ON scans(cycle_id);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  category TEXT NOT NULL,                 -- 'spf'|'dmarc'|...
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  detail TEXT,
  metadata TEXT,                          -- JSON
  FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE INDEX idx_findings_domain_severity ON findings(domain, severity);

CREATE TABLE alerts (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  alert_type TEXT NOT NULL,               -- 'score_drop'|'expired'|'new_finding'|'discovery'
  triggered_at INTEGER NOT NULL,
  resolved_at INTEGER,
  detail TEXT,
  delivered_to TEXT,                      -- webhook|email|slack
  delivered_at INTEGER
);

CREATE INDEX idx_alerts_active ON alerts(triggered_at DESC) WHERE resolved_at IS NULL;
```

**Storage estimate per sub-tenant:**

| Volume | Domains | Scans (1 year, weekly) | Findings (avg 5/scan) | Total D1 |
|---|---|---|---|---|
| Small customer | 5,000 | 260,000 (~520MB) | 1.3M (~260MB) | ~800 MB |
| Median customer | 50,000 | 2.6M (~5.2GB) | 13M (~2.6GB) | ~8 GB ⚠️ over D1 5GB free |
| Tenant headline | 2,500,000 | 130M (~260GB) | 650M (~130GB) | 🔴 needs **R2 archival + D1 hot tier** |

**Tiered storage:**
- D1: hot data (last 90 days of scans, all live findings, all alerts)
- R2: cold archive (scans > 90 days old, compressed JSON.gz)
- Workers KV: real-time deltas + alert dedup window

For the Tenant headline customer, we'd shard the per-tenant DB or move to a single D1 holding only summary rows + R2 for full history.

---

## 4. Pipeline design

### 4.1 Initial portfolio audit (use case 1)

```
1. Tenant uploads portfolio (CSV → API: /internal/tenant/portfolio)
   ↓
2. Orchestrator validates + dedups + chunks into 100-domain batches
   ↓
3. For each chunk:
   - Enqueue { tenant_id, cycle_id, batch_id, domains[] } to scanner queue
   ↓
4. Scanner-queue consumer (auto-scaled isolate pool):
   - Per message: POST to /internal/tools/batch with the 100 domains
   - Receives { results[], summary } from existing batch endpoint
   - Enqueues { tenant_id, cycle_id, batch_id, results[] } to writer queue
   ↓
5. Writer-queue consumer (single isolate per tenant for D1 write serialisation):
   - Inserts scans + findings into per-tenant D1
   - Updates domains.last_scanned_at, last_score
   - Emits cycle_progress event
   ↓
6. When all batches in cycle_id done:
   - Generate report (R2 archive + signed download URL)
   - Webhook callback to Tenant's portal
```

**Throughput knobs:**

| Knob | Default | Max | Effect |
|---|---|---|---|
| `scan_concurrency` (per batch) | 25 | 50 | Increases in-flight DoH queries |
| `concurrent_batches` | 10 | 50 | Increases batch endpoint parallelism |
| `queue_consumer_count` | 4 | 16 | Increases isolate fan-out |
| `batch_size` | 100 | 500 | Larger batches = fewer queue messages but longer wall-time |

### 4.2 Continuous monitoring (use case 2)

Cron-trigger every Sunday 02:00 UTC iterates over all active sub-tenants, checks `domains.watch_interval_hours` against `last_scanned_at`, enqueues stale ones.

**Differential optimisation:**
- Hash the previous scan's DNS records (NS/MX/A/TXT) into a `dns_fingerprint` field.
- On re-scan, do a quick `/internal/tools/call` for a single light check first (e.g. `check_ns`).
- If `dns_fingerprint` matches: skip the full scan, mark as "no change", emit a `silent` event.
- If different: run the full `scan_domain`.

This drops re-scan cost by ~80% for stable portfolios.

### 4.3 Registrar discovery (use case 3)

See `Tenant-Capacity-and-Discovery-Design.md` §2 for full design. Plugs into this architecture as:
- Discovery orchestrator: takes seed domains, spawns 6 signal correlator workers in parallel.
- Each signal correlator hits CT logs / RDAP / DNS as needed (cached aggressively).
- Candidates flow into the same scanner queue with `is_candidate=true` flag.
- Result writer marks findings + confidence in per-tenant D1.

### 4.4 Real-time API (use case 6)

```
GET /api/tenant/v1/customers/<sub_tenant_id>/domains
  - paginated, supports ?since=<timestamp> for delta queries
GET /api/tenant/v1/customers/<sub_tenant_id>/domains/<domain>
GET /api/tenant/v1/customers/<sub_tenant_id>/alerts?status=open
POST /api/tenant/v1/customers/<sub_tenant_id>/scan  (on-demand re-scan)
POST /api/tenant/v1/customers/<sub_tenant_id>/portfolio  (bulk upload)
```

Auth via per-customer API keys minted from the registry D1. Rate-limited per-tenant (default 1,000 RPM). Webhook deliveries on alert events.

---

## 5. Cost model

### 5.1 Per-domain unit cost (cold path)

| Resource | Qty | CF cost (paid plan) | Cost per domain |
|---|---|---|---|
| Workers requests (orchestrator + queue + writer) | ~3 | $0.30/1M | $0.0000009 |
| Workers CPU (~12.5s wall, ~2s billable) | 2s | $0.02/million CPU-ms | $0.00004 |
| KV reads (cache misses on scan_domain) | 17 | $0.50/1M | $0.0000085 |
| KV writes (cache populate) | 17 | $5.00/1M | $0.000085 |
| D1 row writes (scan + findings) | ~5 | $1.00/1M | $0.000005 |
| Queue ops (in + out + ack) | 3 | $0.40/1M | $0.0000012 |
| Analytics Engine writes | 1 | included | $0 |
| DoH queries | 16 | self-hosted | $0 |
| **Subtotal per cold scan** | — | — | **~$0.0001 / domain** |

### 5.2 Volume scenarios

| Scenario | Domains | Cold-path cost | Plus monthly base | All-in |
|---|---|---|---|---|
| Demo (5K customer) | 5,000 | $0.50 | $5/mo CF base | ~$6/mo |
| Median customer (50K) | 50,000 | $5 / scan | weekly = $20/mo | $25/mo |
| Headline customer (2.5M, weekly) | 10M scans/mo | $1,000/mo | + $50 base | ~$1,050/mo |
| Tenant aggregate (50 customers × 50K avg, weekly) | 130M scans/mo | $13,000/mo | + base | ~$13,500/mo |

**With differential monitoring (-80% on weekly re-scans):** Tenant aggregate drops to **~$2,800/mo at 130M domain-month aggregate**.

### 5.3 Cost optimisation levers (in order of impact)

1. **Differential scanning** (described in 4.2): -80% on monitoring re-scans. **Highest impact.**
2. **Aggressive cache TTL for batch context**: bump `cacheTtlSeconds` to 3600 for batch jobs (currently 300). Reduces KV writes on hot domains within a cycle.
3. **R2 cold archive**: scans > 90 days move to R2 ($0.015/GB/mo vs D1 ~$0.75/GB/mo). For 100GB historical: $1.50/mo vs $75/mo.
4. **DoH caching at scanner**: cache resolver responses for 60s within a scanner isolate (currently per-scan). Saves DoH queries on shared-platform domains.
5. **Skip Tier-3 checks on monitoring re-scans**: only re-run Tier-1 (DMARC/DKIM/SPF/DNSSEC/SSL) checks weekly; Tier-2/3 monthly. Saves ~50% per scan.
6. **Free CF Workers tier where possible**: if a sub-tenant fits in 100K req/day, run on free tier (each tenant Worker is independent).

### 5.4 Pricing model for Tenant

Suggested wholesale → retail:

| Service | Wholesale to Tenant | Tenant retail to customer |
|---|---|---|
| One-shot audit | $0.05/domain | $0.20–0.50/domain |
| Monitoring (per domain/month) | $0.02/month | $0.10–0.25/month |
| Discovery run | $0.50/seed domain | $2–5/seed domain |
| Real-time API | tiered per-RPM | bundled with monitoring |

For a 50K-domain median customer on monitoring: wholesale $1,000/mo, Tenant retails at $5–12K/mo. **Margin: 80–90%.**

---

## 6. Security architecture

### 6.1 Tenant isolation

| Layer | Enforcement | Failure mode |
|---|---|---|
| Network | Cloudflare service binding (no public route) | If breached: rate-limited at edge |
| Auth | Per-tenant API key (32-byte) | If leaked: revoke via registry D1 |
| Storage | Per-sub-tenant D1 binding | If misrouted: query fails (binding doesn't exist) |
| Runtime | Tenant-id is in the queue message, not the API call | Wrong tenant-id → no D1 binding for that ID → 404 |
| Audit | Every cross-tenant operation logged | Compliance reporting + post-incident review |

### 6.2 Authentication & authorisation

- **Super-tenant token (Tenant):** issued at integration time. Carries access to ALL sub-tenants.
- **Sub-tenant tokens:** scoped to a single customer. Tenant mints these via the admin API.
- **OAuth** (Phase 2): for Tenant's customer-facing portal where end-users authenticate directly.
- **Zero standing privilege:** No long-lived super-tokens in production secrets — rotated weekly via cron + alerting.

### 6.3 Data classification

| Data | Sensitivity | Storage | Retention |
|---|---|---|---|
| Domain name (public DNS) | Public | per-tenant D1 | indefinite |
| Scan score / grade | Customer-confidential | per-tenant D1 | 1 year hot, R2 cold archive 5 years |
| Scan finding detail | Customer-confidential | per-tenant D1 | same |
| Discovery candidates | Customer-confidential | per-tenant D1 | same |
| Tenant API keys | Secret | shared registry D1 (hashed) | until revoked |
| Billing events | Tenant-internal | shared registry D1 | 7 years (tax) |
| Per-IP scanner logs | Internal | Analytics Engine (hashed IPs only) | 30 days |

### 6.4 Network security

- All traffic between Tenant's portal and bv-web is HTTPS with Origin allowlist.
- Internal queue messages are within Cloudflare's network only.
- Outbound DoH uses self-hosted endpoint over private CF tunnel (not public internet).
- Outbound HTTPS probes (HTTP-security check, MTA-STS, BIMI) use `safeFetch` with SSRF guards.

### 6.5 Compliance posture

| Standard | Approach |
|---|---|
| **GDPR** (EU customers) | Right-to-delete = drop tenant D1; data-residency tracked in `super_tenants.metadata` |
| **SOC2 Type II** | Audit-trail in shared D1; access logging at every API; quarterly external review (Year 2) |
| **ISO 27001** | Future. Required by some Tenant enterprise customers; budget for assessor |
| **Tenant's own contractual obligations** | Subordinate DPA between Tenant and us; mirror their customer DPAs |

---

## 7. Reliability & operations

### 7.1 Failure modes

| Failure | Detection | Recovery |
|---|---|---|
| **Single scan fails** | `Promise.allSettled` in `/internal/tools/batch` | Partial result returned, individual scan marked `error: <kind>` |
| **Queue consumer crashes** | CF Queue auto-retry (3 attempts) | Auto-retry; DLQ after 3 failures |
| **D1 write timeout** | Try/catch + analytics emit | Re-enqueue write; alert if DLQ > threshold |
| **DoH origin down** | Existing fallback (CF DoH primary, Google fallback) | Auto-fallback; alert if both down >5min |
| **Tenant DB corrupted** | D1 query errors | Restore from CF point-in-time backup; resume |
| **Cycle stuck (some batches missing)** | Cron health-check: any cycle > 24h old + incomplete | Auto-requeue missing batches; alert ops |
| **Malicious tenant tries cross-tenant access** | Routing layer rejects unknown sub-tenant ID | 404 + audit log + alert ops |

### 7.2 SLOs

| Metric | Target | Measurement window |
|---|---|---|
| Initial portfolio scan completion | 95% within 24h, 99% within 72h | Per-cycle |
| Monitoring re-scan freshness | 95% within `watch_interval_hours + 24h` | Daily aggregate |
| API request availability | 99.9% | Monthly |
| API request p95 latency | 200ms | Monthly |
| Scan result accuracy (vs canonical scan) | 99% (manual sample of 100/month) | Monthly |
| Data durability | 11 9s (D1 + R2 native) | — |

### 7.3 Backup & disaster recovery

- D1: automatic point-in-time backups (CF native).
- R2: cross-region replication enabled (paid extra ~$0.005/GB/mo).
- Tenant API keys: encrypted at rest in registry D1.
- Code: GitHub + tagged releases (we already do this).
- Runbook: `docs/tenant-runbook.md` — gitignored, includes recovery procedures.

### 7.4 Monitoring stack

- **Per-tenant dashboards:** bv-web admin route `business.tenant.tenant-health.tsx` showing scan freshness, error rate, alert volume.
- **Aggregate dashboards:** existing `business.mcp-usage.tsx` extended with Tenant-specific metrics (sub-tenants count, monthly scans).
- **Alerts:**
  - Tenant has no scan completion in last 7d → page ops
  - Cycle DLQ > 10 messages → page ops
  - DoH error rate > 5% over 1h → page ops
  - Tenant approaching quota → email Tenant account manager
- **Metrics emitted to existing Analytics Engine** (extends current 4 event types with `tenant`, `super_tenant`, `cycle_id` blobs).

---

## 8. Build sequence

### Phase 0 — Foundation (today, ~1 hour)

- [ ] Bump `partner.scan_domain` quota to 2.5M (or add `enterprise_scale` tier) — `src/lib/config.ts` 2-line change. Ship as v2.10.13.
- [ ] Mint a Tenant-specific API key + add OWNER_ALLOW_IPS entry.
- [ ] **Verify** — calibration run (200 domains via `tenant-scale-chaos.py`). Update §1.2 of capacity doc with measured numbers.

### Phase 1 — Multi-tenant foundation (week 1)

- [ ] **`bv-mcp` new module: `src/tenant/`** — orchestrator endpoints `/internal/tenant/portfolio`, `/internal/tenant/scan`, `/internal/tenant/report/<cycle_id>`.
- [ ] **Shared registry D1** — schema migration + Drizzle models.
- [ ] **Per-tenant D1 templating** — script to provision a new D1 per sub-tenant with the schema.
- [ ] Tests: end-to-end cycle for a 100-domain test tenant.

### Phase 2 — Scanner queue (week 2)

- [ ] **Cloudflare Queue: `bv-scanner-queue`** — provisioned via wrangler.
- [ ] **Queue consumer** — calls existing `/internal/tools/batch`, enqueues results.
- [ ] **Writer queue + consumer** — D1 inserts.
- [ ] Tests: chaos test (kill consumer mid-run, verify re-delivery).

### Phase 3 — Monitoring + differential (week 3)

- [ ] **Cron handler** in `src/scheduled.ts` for weekly re-scan dispatch.
- [ ] **DNS fingerprint logic** — single-check pre-flight, skip on no-change.
- [ ] **Alerts table** + webhook delivery via existing `ALERT_WEBHOOK_URL` plumbing.
- [ ] Tests: simulate 7-day cycle on a test tenant.

### Phase 4 — Discovery (week 4)

- [ ] Build `discover_brand_domains` tool per `Tenant-Capacity-and-Discovery-Design.md` §2.
- [ ] Wire into orchestrator: `/internal/tenant/discover/<sub_tenant_id>`.
- [ ] Integrate candidates into the scan pipeline (auto-add to portfolio with `is_candidate=true`).

### Phase 5 — bv-web admin UI (week 5)

- [ ] Routes: `business.tenant.tenants.tsx`, `business.tenant.tenant.<id>.tsx`, `business.tenant.discovery.tsx`, `business.tenant.alerts.tsx`.
- [ ] Service-binding client extension for Tenant endpoints.
- [ ] CSV upload, report download, on-demand actions.

### Phase 6 — Hardening + GA (week 6)

- [ ] Per-tenant rate limiting in registry D1.
- [ ] Audit log for every cross-tenant operation.
- [ ] Runbook + on-call procedures.
- [ ] Pilot with 1 Tenant customer on the public portfolio.
- [ ] Soft launch.

---

## 9. Risks & open questions

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Tenant's customer count grows beyond CF account D1 limit | Med (1 year out) | Med | Migrate to D1-as-a-tenant-pool model with hash-based sharding |
| Self-hosted DoH origin saturates at >50M queries/day | Low (need 200K customers to hit) | High | Add second region; CF DoH as auto-fallback already wired |
| Tenant wants on-prem deployment | Med | High | Document `npm run deploy:private` already supports this; offer enterprise license |
| Customer data residency: EU-only customers need EU storage | Med | Med | CF D1 has region preferences; document residency in registry D1 |
| Discovery false-positive rate spooks customers | High in early pilot | Med | Confidence threshold (>0.8) for auto-include; manual review queue for 0.5–0.8 |
| Pricing race-to-bottom with another DNS-security vendor | Med | High | Differentiate on discovery + compliance mapping (uniquely ours) |
| Cloudflare cost surge on pricing changes | Low | Med | Multi-cloud DR plan: Worker source code is portable, queue pattern is generic |
| Tenant churns / partnership ends | Med | High | Diversify: same architecture serves direct enterprise customers without changes |

---

## 10. Prior art / external research

External validation found via parallel searches against GitHub + Reddit (2026-05-09). Architecture choices below are deliberately conservative — patterns the community has already de-risked.

### 10.1 Multi-tenant Workers patterns

| Project | What it confirms | Where we use it |
|---|---|---|
| **`webitte-hosting/emdash`** | Prefix-stamping adapter pattern: wrap D1/R2/KV bindings with tenant-id-aware proxies, no `WHERE tenant_id = ?` filtering needed. `env.TENANT_ID` injected at deploy. | §2.3 — `tenantD1()`, `tenantR2()` adapter helpers |
| **`Cephra-dev/Cephra-Auth`** | Per-tenant D1 + hostname-based routing + per-tenant JWKS endpoint. Service-binding-RPC + HTTP from "any service". Cron cleanup pattern. | §2.4 — hostname routing for Phase 2 |
| **`Norky101/multi-tenant-saas-webhook-processor`** | Webhook fan-out across tenants on Workers + D1. | §4.4 — webhook delivery on alert events |
| **r/CloudFlare: "How are per-tenant DBs intended to be used"** (Cloudflare staff comment) | D1 designed for horizontal scale-out across tenants. **10 GB/database** soft limit. Recommended: one DB per tenant up to ~5,000 tenants per account. | §2.3, §3 |
| **r/CloudFlare: "Dynamic Workflows: durable execution that follows the tenant"** | ~300-line library that routes `Cloudflare Workflows` per tenant at runtime — alternative to Queues for stateful, long-running batch jobs (e.g. our portfolio audit). Worth evaluating for monitoring cycles in Phase 3. | §2.2 — alternative pipeline option |

### 10.2 Domain-discovery prior art

| Project | Technique | Where we use it |
|---|---|---|
| **`bit4woo/teemo`** (1k⭐) | **Subject Alternative Name (SAN) cert clustering.** Query crt.sh for every customer domain; extract every SAN in the matched certs; those are co-owned. Plus search-engine recon (Bing/Baidu/DuckDuckGo) and 10 third-party sources (DNSdumpster, Netcraft, PassiveDNS, Sitedossier, etc.). | New Tier-1 signal #4 in `Tenant-Capacity-and-Discovery-Design.md` §2.2 — SAN correlator |
| **`bit4woo/domain_hunter_pro`** (2.1k⭐) | Sub-domain + similar-domain hunting at red-team scale. Scoring via search-engine result count. | Lookalike-detection v2 (existing `check_lookalikes` enhanced) |
| **`AlephNullSK/dnsgen`** (1k⭐) | DNS name permutation tool — generates likely subdomain candidates from a base domain. | Discovery scoping: generate likely brand-domain candidates pre-search |
| **`urbanadventurer/urlcrazy`** (672⭐) | Typo-squat generator with 14 variation algorithms (homoglyph, hyphenation, vowel-swap, etc.). | `check_lookalikes` already does this; cross-check our coverage against urlcrazy's algorithm list |
| **`hostinginfo.gg`** (small project, sibling of bv-mcp) | Domain security & performance scanner. Single-tenant. | Confirms our SPF/DMARC/DKIM check categorisation is competitive |

### 10.3 Commercial benchmarks (for pricing)

| Vendor | What they offer | Their claimed pricing |
|---|---|---|
| DomainTools | Reverse-WHOIS API + monitoring | $7,500–25,000/yr enterprise |
| WhoisXMLAPI | Reverse-WHOIS, RDAP, DNS API | ~$0.10/lookup retail |
| RiskIQ (Microsoft Defender XDR) | Brand protection + asset discovery | enterprise-only, ~$50–200K/yr |
| SecurityTrails | Historical DNS + reverse-WHOIS | $200–2,000/mo |
| Red Sift OnDMARC | DMARC monitoring (no discovery) | $500–5,000/mo |

Our wholesale-to-Tenant at $0.02–0.05/domain-month bundles **scanning + monitoring + discovery + DMARC reporting** — a single bundle that DomainTools + Red Sift + a custom recon vendor would charge $10–50k/yr for. **Pricing power: competitive moat is the integration, not any single technique.**

### 10.4 Design decisions taken from prior art

1. **Adopted prefix-stamping adapters** over `WHERE tenant_id = ?` filtering (emdash). Stronger isolation, fewer footguns.
2. **Adopted hostname-based tenant routing** for Phase 2 portal (Cephra-Auth). Better UX than API-key-only.
3. **Added SAN clustering** as Tier-1 discovery signal (teemo). High-confidence, low-cost.
4. **Kept Cloudflare Queues** as primary pipeline (not Workflows) for v1. Workflows is newer and the team is less battle-tested with it. **Re-evaluate at v2** based on monitoring cycle complexity.
5. **Kept per-tenant D1** with R2 cold-archive escape hatch for the headline-customer case (D1 10GB ceiling).

---

## 11. What this lets us pitch Tenant

> **"We can ingest your entire customer portfolio — 50 to 50,000 domains per customer, up to 2.5M for your top accounts — and deliver a per-customer DNS-security audit within 24 hours. Then we monitor every domain weekly and surface any change. We can also discover domains your customers own at other registrars, surface DNS hygiene issues you can fix as a renewal play, and embed all of this into your customer portal via API. Cost to you: $0.02–0.05 per domain-month at wholesale. Margin to you: 80–90%."**

Concrete deliverables for a 60-min Tenant follow-up:
1. **Architecture diagram** (this doc, §2)
2. **Cost calculator spreadsheet** (extract from §5)
3. **Live demo** of a portfolio audit on `tenantglobal.com`'s own public DNS (already-cached scan)
4. **Discovery POC** on a publicly-known M&A target of Tenant (e.g. their parent's domains)
5. **Pricing proposal** with three commercial models (wholesale/retail-share/usage-based)

---

*Working doc — refine before sharing externally. All Tenant-specific numbers in §5 and §10 are estimates; replace with measured data after the calibration run in Phase 0.*
