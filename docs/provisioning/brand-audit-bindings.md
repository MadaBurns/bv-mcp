# Brand-Audit Bindings (v2.19.0 + Phase-3 v2.20.0)

The `brand_audit_batch_start` async path needs production-only resources: one D1
database, two Cloudflare Queues (primary `brand-audit-queue` and the v2.20.0
PDF render queue `brand-audit-pdf-queue`), one R2 bucket, and one service
binding to `bv-browser-renderer` (Phase 3, v2.20.0+).

These bindings live in `.dev/wrangler.deploy.jsonc` (gitignored) and are merged
into `wrangler.production.jsonc` at deploy time by `scripts/inject-private-config.cjs`.
The public `wrangler.jsonc` template intentionally omits all production resource
bindings (KV, D1, queues, R2) — see CLAUDE.md "Production Injection Workflow".

## Resources to provision (one-time)

```bash
# D1 — single global database, not per-tenant
npx wrangler d1 create brand-audit-v1

# Primary queue (Phase 2)
npx wrangler queues create brand-audit-queue

# PDF render queue (Phase 3, v2.20.0+ — separate so PDF render doesn't gate audit completion)
npx wrangler queues create brand-audit-pdf-queue

# R2 — Phase 3 PDF rendering writes to this bucket
npx wrangler r2 bucket create bv-brand-reports

# BV_BROWSER_RENDERER service binding (Phase 3) — no provisioning command;
# the bv-browser-renderer Worker must already be deployed in the same account.
# Wire it in .dev/wrangler.deploy.jsonc under `services:`.
```

Capture the D1 `database_id` from the create-output and insert below.

## `.dev/wrangler.deploy.jsonc` snippet

Add to the existing private deploy config under the same shape as `BV_SCANNER_QUEUE`:

```jsonc
{
  "d1_databases": [
    // ... existing TENANT_REGISTRY_DB, TENANT_DB_TENANT_PILOT_1 entries ...
    {
      "binding": "BRAND_AUDIT_DB",
      "database_name": "brand-audit-v1",
      "database_id": "<from-create-output>"
    }
  ],
  "queues": {
    "producers": [
      // ... existing BV_SCANNER_QUEUE entry ...
      { "binding": "BRAND_AUDIT_QUEUE", "queue": "brand-audit-queue" },
      { "binding": "BRAND_AUDIT_PDF_QUEUE", "queue": "brand-audit-pdf-queue" }
    ],
    "consumers": [
      // ... existing bv-scanner-queue consumer ...
      {
        "queue": "brand-audit-queue",
        "max_batch_size": 5,
        "max_batch_timeout": 30,
        "max_retries": 3
      },
      {
        "queue": "brand-audit-pdf-queue",
        "max_batch_size": 1,
        "max_batch_timeout": 30,
        "max_retries": 3
      }
    ]
  },
  "r2_buckets": [
    { "binding": "BRAND_REPORTS", "bucket_name": "bv-brand-reports" }
  ],
  "services": [
    // ... existing BV_WEB, BV_WHOIS, BV_CERTSTREAM entries ...
    { "binding": "BV_BROWSER_RENDERER", "service": "bv-browser-renderer" }
  ]
}
```

## Schema apply (one-time, after D1 create)

The Drizzle schema in `src/lib/db/brand-audit-schema.ts` is the source of truth.
The repo does not commit migration SQL — apply the schema manually:

```sql
-- brand-audit-v1 schema (v2.19.0)
CREATE TABLE IF NOT EXISTS brand_audits (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
  total_targets INTEGER NOT NULL,
  completed_targets INTEGER NOT NULL DEFAULT 0,
  format TEXT NOT NULL CHECK (format IN ('json','markdown','both')),
  results_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_brand_audits_owner ON brand_audits(owner_id, created_at);

CREATE TABLE IF NOT EXISTS brand_audit_targets (
  audit_id TEXT NOT NULL REFERENCES brand_audits(id),
  target TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
  result_json TEXT,
  pdf_r2_key TEXT,
  error TEXT,
  created_at INTEGER NOT NULL,
  completed_at INTEGER,
  PRIMARY KEY (audit_id, target)
);

-- Phase 4 (v2.21.0) — recurring monitor watches
CREATE TABLE IF NOT EXISTS brand_audit_watches (
  id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  interval TEXT NOT NULL CHECK (interval IN ('daily','weekly','monthly')),
  webhook_url TEXT,
  last_run_at INTEGER,
  last_classification_hash TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_brand_audit_watches_owner ON brand_audit_watches(owner_id, created_at);
CREATE INDEX IF NOT EXISTS idx_brand_audit_watches_due ON brand_audit_watches(active, last_run_at);
```

Apply via:

```bash
npx wrangler d1 execute brand-audit-v1 --file=- --remote <<'SQL'
<paste above>
SQL
```

## Verification post-deploy

```bash
# Confirm tables exist
npx wrangler d1 execute brand-audit-v1 --remote --command \
  "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"

# Confirm queue exists
npx wrangler queues list | grep brand-audit-queue

# Smoke test the producer (after deploy)
curl -sX POST https://dns-mcp.blackveilsecurity.com/mcp \
  -H 'Authorization: Bearer <DEV_KEY>' \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"brand_audit_batch_start","arguments":{"domains":["apple.com"]}}}'
```

The first call should return `{ auditId, queuedAt, targetCount: 1, etaSeconds: ~180 }`.
Poll with `brand_audit_status` until `status: 'completed'`.
