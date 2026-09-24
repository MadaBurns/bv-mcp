-- scripts/access-log/sql/0001_baseline.sql
-- Baseline: mcp_access_log + mcp_access_log_audit, consolidated from the LIVE schema.
-- Target binding: INTELLIGENCE_DB (D1)
-- Target database: mcp-access-log-v1 (bv-mcp-owned; replaces the decommissioned bv-intelligence)
-- Provisioning (operator-run, ONCE, against a freshly created EMPTY database):
--   npx wrangler d1 create mcp-access-log-v1 --location oc
--   npx wrangler d1 execute mcp-access-log-v1 --remote --file scripts/access-log/sql/0001_baseline.sql
-- Deliberately NOT idempotent: plain CREATE, no IF NOT EXISTS, so a re-run against a populated database
-- errors instead of silently no-oping over a drifted schema. A remote --file import rolls back as a whole
-- on failure, so a failed first run leaves the database empty and can simply be retried.
--
-- The statements below are the DDL recorded from bv-intelligence's sqlite_master on 2026-09-24
-- (SQ-183 plan section 2), reproduced verbatim. They are NOT a replay of scripts/intelligence/sql/0001-0003,
-- which no longer reproduce the live table:
--   * ip_masked is NOT NULL live; 0001 leaves it nullable.
--   * live has idx_mcp_access_log_domain and idx_mcp_access_log_ip_masked; the repo chain creates neither.
--   * the repo chain creates idx_mcp_access_log_created_at and idx_mcp_access_log_tool_domain; live has neither.
--   * created_at is the 10th column live, and its default is the uncast strftime('%s', 'now'); the INTEGER
--     affinity stores it as an integer. Keep it as recorded - this file mirrors live, it does not tidy it.
-- The 0004 rollup table (mcp_access_rollup) is deliberately NOT here: it was never applied live and
-- ANALYTICS_ROLLUP_INTERNAL is off. Apply scripts/intelligence/sql/0004_mcp_access_rollup.sql separately only
-- if the operator decides to enable the rollup.
--
-- Deploy gate: scripts/access-log-schema-preflight.mjs (run by deploy:prod, deploy:prod:staged and
-- scripts/deploy-private.mjs) refuses to ship while the database behind INTELLIGENCE_DB lacks any column
-- the Worker writes. Column contract: scripts/access-log/columns.mjs.

CREATE TABLE mcp_access_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ip_hash TEXT NOT NULL, ip_masked TEXT NOT NULL,
  tool_name TEXT NOT NULL, domain TEXT NOT NULL, country TEXT, user_agent TEXT, response_ms INTEGER,
  rate_limited INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
  ip_ciphertext TEXT, ip_key_version TEXT, city TEXT, region TEXT, latitude TEXT, longitude TEXT,
  asn INTEGER, as_org TEXT, ptr_hostname TEXT, key_hash TEXT, client_type TEXT, colo TEXT,
  session_hash TEXT, method TEXT, transport TEXT, status TEXT, source TEXT);
CREATE INDEX idx_mcp_access_log_country ON mcp_access_log (country);
CREATE INDEX idx_mcp_access_log_created ON mcp_access_log(created_at);
CREATE INDEX idx_mcp_access_log_domain ON mcp_access_log(domain, created_at);
CREATE INDEX idx_mcp_access_log_ip_hash ON mcp_access_log(ip_hash, created_at);
CREATE INDEX idx_mcp_access_log_ip_masked ON mcp_access_log(ip_masked, created_at);
CREATE INDEX idx_mcp_access_log_key_created ON mcp_access_log (key_hash, created_at);
CREATE TABLE mcp_access_log_audit (id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s', 'now') AS INTEGER)),
  actor TEXT NOT NULL, action TEXT NOT NULL, ip_hash TEXT, scope TEXT, outcome TEXT NOT NULL);
CREATE INDEX idx_mcp_access_log_audit_created ON mcp_access_log_audit (created_at);
