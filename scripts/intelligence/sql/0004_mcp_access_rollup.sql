-- scripts/intelligence/sql/0004_mcp_access_rollup.sql
-- Migration: low-cardinality access-log rollup counter (Phase 1, decision #2).
-- Target binding: INTELLIGENCE_DB (D1)
-- Provisioning (operator-run, idempotent — run BEFORE flipping ANALYTICS_ROLLUP_INTERNAL=true;
-- otherwise the UPSERT references a non-existent table and the increment fails-soft to a no-op):
--   wrangler d1 execute <intelligence-db-name> --remote --file scripts/intelligence/sql/0004_mcp_access_rollup.sql
--
-- Internal/automated rescan traffic (source='internal') carries null key_hash and
-- ip_hash='unknown' — near-zero forensic value at near-total volume. Instead of a
-- per-event mcp_access_log row, that traffic increments a counter keyed on a small
-- set of low-cardinality dimensions. Authenticated EXTERNAL /mcp traffic keeps its
-- faithful per-event rows. `bucket_day` is the unix-day (floor(epoch_seconds / 86400)).
-- Dimension columns are NOT NULL (the producer coalesces nulls to 'unknown') so the
-- composite primary key actually collapses duplicates — SQLite treats NULLs as
-- distinct in a unique index, which would otherwise defeat the rollup.
--
-- Runtime write pattern (see incrementAccessRollup in src/mcp/execute.ts):
--   INSERT INTO mcp_access_rollup (bucket_day, tool_name, source, status, auth_tier, client_type, country, count)
--   VALUES (?, ?, ?, ?, ?, ?, ?, 1)
--   ON CONFLICT (bucket_day, tool_name, source, status, auth_tier, client_type, country)
--   DO UPDATE SET count = count + 1;

CREATE TABLE IF NOT EXISTS mcp_access_rollup (
	bucket_day  INTEGER NOT NULL,
	tool_name   TEXT NOT NULL,
	source      TEXT NOT NULL,
	status      TEXT NOT NULL,
	auth_tier   TEXT NOT NULL,
	client_type TEXT NOT NULL,
	country     TEXT NOT NULL,
	count       INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (bucket_day, tool_name, source, status, auth_tier, client_type, country)
);

CREATE INDEX IF NOT EXISTS idx_mcp_access_rollup_bucket_day ON mcp_access_rollup (bucket_day);
