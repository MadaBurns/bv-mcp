# Brand-Audit Bindings (v2.19.0+)

The `brand_audit_batch_start` async path needs production-only resources: one D1
database, one Cloudflare Queue, and one R2 bucket (R2 actually consumed by Phase
3 PDF rendering — declared now for forward-compat).

These bindings live in `.dev/wrangler.deploy.jsonc` (gitignored) and are merged
into `wrangler.production.jsonc` at deploy time by `scripts/inject-private-config.cjs`.
The public `wrangler.jsonc` template intentionally omits all production resource
bindings (KV, D1, queues, R2) — see CLAUDE.md "Production Injection Workflow".

## Resources to provision (one-time)

```bash
# D1 — single global database, not per-tenant
npx wrangler d1 create brand-audit-v1

# Queue
npx wrangler queues create brand-audit-queue

# R2 (forward-compat; only Phase 3 PDF rendering writes to it)
npx wrangler r2 bucket create bv-brand-reports
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
      { "binding": "BRAND_AUDIT_QUEUE", "queue": "brand-audit-queue" }
    ],
    "consumers": [
      // ... existing bv-scanner-queue consumer ...
      {
        "queue": "brand-audit-queue",
        "max_batch_size": 5,
        "max_batch_timeout": 30,
        "max_retries": 3
      }
    ]
  },
  "r2_buckets": [
    { "binding": "BRAND_REPORTS", "bucket_name": "bv-brand-reports" }
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
