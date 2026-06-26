-- scripts/intelligence/sql/0002_mcp_access_log_enrich.sql
-- Migration: enrich mcp_access_log with geo / network / customer dimensions.
-- Target binding: INTELLIGENCE_DB (D1)
-- Provisioning (operator-run, idempotent — run BEFORE deploying the enriched consumer):
--   wrangler d1 execute <intelligence-db-name> --remote --file scripts/intelligence/sql/0002_mcp_access_log_enrich.sql
-- All columns nullable for backward-compat with existing rows + the inline-fallback insert.

ALTER TABLE mcp_access_log ADD COLUMN city          TEXT;
ALTER TABLE mcp_access_log ADD COLUMN region        TEXT;
ALTER TABLE mcp_access_log ADD COLUMN latitude      TEXT;
ALTER TABLE mcp_access_log ADD COLUMN longitude     TEXT;
ALTER TABLE mcp_access_log ADD COLUMN asn           INTEGER;
ALTER TABLE mcp_access_log ADD COLUMN as_org        TEXT;
ALTER TABLE mcp_access_log ADD COLUMN ptr_hostname  TEXT;
ALTER TABLE mcp_access_log ADD COLUMN key_hash      TEXT;
ALTER TABLE mcp_access_log ADD COLUMN client_type   TEXT;
ALTER TABLE mcp_access_log ADD COLUMN colo          TEXT;
ALTER TABLE mcp_access_log ADD COLUMN session_hash  TEXT;
ALTER TABLE mcp_access_log ADD COLUMN method        TEXT;
ALTER TABLE mcp_access_log ADD COLUMN transport     TEXT;
ALTER TABLE mcp_access_log ADD COLUMN status        TEXT; -- tool outcome pass|fail|error|unknown (distinct from rate_limited)

CREATE INDEX IF NOT EXISTS idx_mcp_access_log_key_created ON mcp_access_log (key_hash, created_at);
CREATE INDEX IF NOT EXISTS idx_mcp_access_log_country     ON mcp_access_log (country);

-- Forensics self-audit trail. Co-located in INTELLIGENCE_DB (NOT the tenants registry
-- `audit_events`, which is a separate D1) so the /internal/analytics/forensics handler —
-- which already binds INTELLIGENCE_DB — can record every IP re-identification without a
-- cross-subsystem binding. `scope` is JSON {days, ipHashFilter, keyHashFilter, resultCount}.
CREATE TABLE IF NOT EXISTS mcp_access_log_audit (
	id          TEXT PRIMARY KEY,
	created_at  INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
	actor       TEXT NOT NULL,
	action      TEXT NOT NULL,
	ip_hash     TEXT,
	scope       TEXT,
	outcome     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mcp_access_log_audit_created ON mcp_access_log_audit (created_at);
