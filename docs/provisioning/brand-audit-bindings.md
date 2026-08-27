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
- Existing `BV_WEB` service binding for the exact first-party Brand Drift receiver.
- `BV_MCP_BRAND_WEBHOOK_KEY` secret, shared only with `bv-web-prod` and at least
  32 UTF-8 bytes. Keep it distinct from every other internal capability.

Use project-approved private names when running Wrangler, for example:

```bash
npx wrangler d1 create <brand-audit-db-name>
npx wrangler queues create <brand-audit-queue-name>
npx wrangler queues create <brand-audit-pdf-queue-name>
npx wrangler r2 bucket create <brand-reports-bucket-name>
npx wrangler secret put BV_MCP_BRAND_WEBHOOK_KEY --name bv-dns-security-mcp
```

The same generated value must be set on `bv-web-prod` through that repository's
operator-gated secret workflow before either endpoint is deployed. Never place
the value in this file, a Wrangler `vars` block, shell history, or logs.

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
			"database_id": "<cloudflare-d1-id>",
		},
	],
	"queues": {
		"producers": [
			{ "binding": "BRAND_AUDIT_QUEUE", "queue": "<brand-audit-queue-name>" },
			{ "binding": "BRAND_AUDIT_PDF_QUEUE", "queue": "<brand-audit-pdf-queue-name>" },
		],
		"consumers": [
			{
				"queue": "<brand-audit-queue-name>",
				"max_batch_size": 5,
				"max_batch_timeout": 30,
				"max_retries": 3,
			},
			{
				"queue": "<brand-audit-pdf-queue-name>",
				"max_batch_size": 1,
				"max_batch_timeout": 30,
				"max_retries": 3,
			},
		],
	},
	"r2_buckets": [{ "binding": "BRAND_REPORTS", "bucket_name": "<brand-reports-bucket-name>" }],
	"services": [{ "binding": "BV_BROWSER_RENDERER", "service": "<renderer-worker-service>" }],
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
-- Production schema (brand-audit-v1) — verified 2026-05-19. The CHECK constraints
-- on `step` and `status` are intentionally absent in production; the original
-- hand-rolled CREATE (from the 2026-05-18 brand_audit_steps migration session)
-- omitted them, and we rely on the TypeScript / Zod layer for value validation.
-- Phase-N additions to BrandAuditPipelineStep don't require D1 DDL as long as
-- this asymmetry persists. If a future operator wants registry-side validation,
-- ALTER the table to add the CHECK clauses and update this file in lock-step.
CREATE TABLE IF NOT EXISTS brand_audit_steps (
  audit_id TEXT NOT NULL REFERENCES brand_audits(id),
  target TEXT NOT NULL,
  step TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_json TEXT,
  error TEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (audit_id, target, step)
);
```

The watch webhook path also requires the durable outbox columns below. Apply
[`scripts/brand-audit/sql/0001_watch_webhook_outbox.sql`](../../scripts/brand-audit/sql/0001_watch_webhook_outbox.sql)
exactly once **before** deploying consumer code that selects them:

```bash
npx wrangler d1 execute <brand-audit-db-name> --remote \
  --file scripts/brand-audit/sql/0001_watch_webhook_outbox.sql
```

This is an operator-gated production D1 mutation. The deployment must remain
blocked until `PRAGMA table_info(brand_audit_watches)` shows both
`last_classification_result_json` and `pending_webhook_json`. The former is the
full result matching `last_classification_hash`; the latter is the exact
pending `{ payload, currentResult }` envelope replayed after delivery failure.
Both `npm run deploy:prod` and `scripts/deploy-private.mjs` run
`scripts/brand-audit-schema-preflight.mjs` before Wrangler publish. That gate is
read-only and fails closed when the binding, query, or either column is absent;
it never applies the migration for the operator.

## Verification

After deployment:

```bash
npx wrangler d1 execute <brand-audit-db-name> --remote --command \
  "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"

npx wrangler d1 execute <brand-audit-db-name> --remote --command \
  "SELECT name FROM pragma_table_info('brand_audit_watches') WHERE name IN ('last_classification_result_json', 'pending_webhook_json') ORDER BY name"

npx wrangler queues list
```

### Legacy owner migration gate

After the canonical OAuth-principal migration, clients reconcile their own
legacy 16-hex and `tenant:<id>` owner rows when they next authenticate. The
authenticated web removal path can also adopt an exact historical `anonymous`
watch by matching its high-entropy webhook-token fingerprint. No other
database-only mapping is trustworthy.

For a token-proven anonymous watch with an existing classification hash,
adoption persists the exact matching completed-target result as its canonical
baseline before changing owner. The lookup deliberately does not require the
parent audit to be terminal because the legacy flow could store the watch hash
before a later counter/finalization failure. A missing exact digest fails the
adoption closed; it is never replaced with the newest unrelated result.

**Release prerequisite:** before enabling the new principal scheme in
production, run both read-only inventories below. Record the counts in the
release evidence and repeat them after the reconciliation grace period.

```bash
npx wrangler d1 execute <brand-audit-db-name> --remote --command \
  "SELECT owner_id, COUNT(*) AS active_watch_count, MIN(created_at) AS oldest_created_at, MAX(last_run_at) AS newest_last_run_at FROM brand_audit_watches WHERE active = 1 AND ((length(owner_id) = 16 AND owner_id NOT GLOB '*[^0-9a-f]*') OR owner_id LIKE 'tenant:%') GROUP BY owner_id ORDER BY active_watch_count DESC, owner_id"

npx wrangler d1 execute <brand-audit-db-name> --remote --command \
  "SELECT COUNT(*) AS anonymous_active_watch_count, MIN(created_at) AS oldest_created_at, MAX(last_run_at) AS newest_last_run_at FROM brand_audit_watches WHERE active = 1 AND owner_id = 'anonymous'"
```

The first query must return no rows and the anonymous count must be zero before
the migration is considered closed. Do not bulk-reassign any remaining owner:
there is no safe inference from an old hash, tenant label, domain, or webhook
URL to the new authenticated principal. Let verified clients reconcile or adopt
their exact rows first.

After the documented grace period, any remainder is an orphan and must not keep
running under a shared or ambiguous principal. With explicit production-write
approval, disable (do not delete) only those active legacy rows, then rerun both
inventories and retain their output as release evidence:

```bash
npx wrangler d1 execute <brand-audit-db-name> --remote --command \
  "UPDATE brand_audit_watches SET active = 0 WHERE active = 1 AND (owner_id = 'anonymous' OR owner_id LIKE 'tenant:%' OR (length(owner_id) = 16 AND owner_id NOT GLOB '*[^0-9a-f]*'))"
```

This is an operator-gated production mutation. Never run it as an automated
deploy step, and never replace it with a bulk reassignment. The inactive rows
remain available for incident review and deliberate customer recovery.

Smoke test with synthetic domains and a non-committed bearer token:

```bash
curl -sX POST "$BV_MCP_URL" \
  -H "Authorization: Bearer $BV_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"brand_audit_batch_start","arguments":{"domains":["example.test"]}}}'
```
