-- Migration: mcp_access_log
-- Target binding: INTELLIGENCE_DB (D1)
-- Provisioning (operator-run, idempotent):
--   wrangler d1 execute <intelligence-db-name> --remote --file scripts/intelligence/sql/0001_mcp_access_log.sql
--
-- Records every public `tools/call` for abuse-investigation — including
-- rejected / rate-limited calls AND unauthenticated callers (unauth → null
-- `key_hash`, attributed by `ip_hash` only). Privacy
-- model: only the FNV-1a-hashed `i_<hex>` IP is stored by default; the masked
-- last-octet form (`a.b.c.xxx`) is operator-readable for fingerprint pivoting;
-- the AES-GCM-encrypted ciphertext is gated on
-- `MCP_ACCESS_LOG_IP_ENCRYPTION_KEY` and only decryptable with the key version
-- recorded alongside it. PII-gated columns (`ANALYTICS_PII_LEVEL`): `user_agent`
-- is NULL at the `coarse` default and only populated at `standard`/`full` (same
-- tier as `ip_ciphertext`/`city`). 90-day retention is enforced by the cron in
-- `src/scheduled.ts`.

CREATE TABLE IF NOT EXISTS mcp_access_log (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
	ip_hash         TEXT NOT NULL,
	ip_masked       TEXT,
	tool_name       TEXT NOT NULL,
	domain          TEXT NOT NULL,
	country         TEXT,
	user_agent      TEXT,
	response_ms     INTEGER,
	rate_limited    INTEGER NOT NULL DEFAULT 0,
	ip_ciphertext   TEXT,
	ip_key_version  TEXT
);

CREATE INDEX IF NOT EXISTS idx_mcp_access_log_created_at ON mcp_access_log (created_at);
CREATE INDEX IF NOT EXISTS idx_mcp_access_log_tool_domain ON mcp_access_log (tool_name, domain);
CREATE INDEX IF NOT EXISTS idx_mcp_access_log_ip_hash ON mcp_access_log (ip_hash);
