# Brand-Audit Binding Provisioning

Public-safe checklist for the `brand_audit_batch_start` async path. Keep real
Cloudflare database IDs, queue names, bucket names, service names, and account
details in ignored deployment notes.

## Required Resources

Provision private production resources for:

- `BRAND_AUDIT_DB` D1 database.
- `BRAND_AUDIT_QUEUE` producer and consumer queue.
- `BRAND_AUDIT_PDF_QUEUE` producer and consumer queue.
- `BRAND_REPORTS` R2 bucket.
- `BV_BROWSER_RENDERER` service binding.

Use project-approved private names when running Wrangler, for example:

```bash
npx wrangler d1 create <brand-audit-db-name>
npx wrangler queues create <brand-audit-queue-name>
npx wrangler queues create <brand-audit-pdf-queue-name>
npx wrangler r2 bucket create <brand-reports-bucket-name>
```

## Private Wrangler Snippet

Add the resulting bindings to `.dev/wrangler.deploy.jsonc`. That file is
ignored and merged into `wrangler.production.jsonc` by
`scripts/inject-private-config.cjs` during deployment.

```jsonc
{
  "d1_databases": [
    {
      "binding": "BRAND_AUDIT_DB",
      "database_name": "<brand-audit-db-name>",
      "database_id": "<cloudflare-d1-id>"
    }
  ],
  "queues": {
    "producers": [
      { "binding": "BRAND_AUDIT_QUEUE", "queue": "<brand-audit-queue-name>" },
      { "binding": "BRAND_AUDIT_PDF_QUEUE", "queue": "<brand-audit-pdf-queue-name>" }
    ],
    "consumers": [
      {
        "queue": "<brand-audit-queue-name>",
        "max_batch_size": 5,
        "max_batch_timeout": 30,
        "max_retries": 3
      },
      {
        "queue": "<brand-audit-pdf-queue-name>",
        "max_batch_size": 1,
        "max_batch_timeout": 30,
        "max_retries": 3
      }
    ]
  },
  "r2_buckets": [
    { "binding": "BRAND_REPORTS", "bucket_name": "<brand-reports-bucket-name>" }
  ],
  "services": [
    { "binding": "BV_BROWSER_RENDERER", "service": "<renderer-worker-service>" }
  ]
}
```

## Schema Apply

The source of truth is `src/lib/db/brand-audit-schema.ts`. Apply the schema to
the private D1 database using a local SQL file or an operator-only runbook:

```bash
npx wrangler d1 execute <brand-audit-db-name> --remote --file <schema.sql>
```

The queue resume store requires this table in the same D1 database:

```sql
CREATE TABLE IF NOT EXISTS brand_audit_steps (
  audit_id TEXT NOT NULL REFERENCES brand_audits(id),
  target TEXT NOT NULL,
  step TEXT NOT NULL CHECK (step IN ('discovery', 'registrar_enrichment', 'classification')),
  status TEXT NOT NULL CHECK (status IN ('completed', 'partial', 'failed')),
  payload_json TEXT,
  error TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (audit_id, target, step)
);
```

## Verification

After deployment:

```bash
npx wrangler d1 execute <brand-audit-db-name> --remote --command \
  "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"

npx wrangler queues list
```

Smoke test with synthetic domains and a non-committed bearer token:

```bash
curl -sX POST "$BV_MCP_URL" \
  -H "Authorization: Bearer $BV_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"brand_audit_batch_start","arguments":{"domains":["example.test"]}}}'
```
