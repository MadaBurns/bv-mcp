-- scripts/access-log/sql/0002_drop_unused_indexes.sql
-- Drops the three mcp_access_log secondary indexes that no query in this repo uses (SQ-500).
-- Target binding: INTELLIGENCE_DB (D1)
-- Target database: bv-intelligence while it is still live (before the operator-runbook §3a cut-over),
--   then mcp-access-log-v1 once the binding points there. Apply it to whichever database the binding
--   resolves to at the time; the saving only lands once this file has run against the LIVE database.
-- Provisioning (operator-run, idempotent, after 0001_baseline.sql on a new database):
--   npx wrangler d1 execute <bv-intelligence | mcp-access-log-v1> --remote --file scripts/access-log/sql/0002_drop_unused_indexes.sql
--
-- Why: D1 bills every index entry as a row written, on insert and again on the retention DELETE
-- (and the archive pass reads the table). Every logged call paid for six secondary indexes; only
-- three of them serve a query. Dropping the other three removes 3 of the 7 rows written per insert
-- (and 3 of the 7 touched per delete) with no read path affected.
--
-- Reader audit (every statement that reads or deletes from mcp_access_log; src/ and scripts/):
--   idx_mcp_access_log_created      KEPT  retention DELETE / archive SELECT (created_at < ?),
--                                         /internal/analytics/usage window, the client-ip header audit,
--                                         the rollup probe's 24h COUNT.
--   idx_mcp_access_log_key_created  KEPT  /internal/analytics/usage?key_hash=, /internal/analytics/forensics
--                                         key_hash filter, POST /internal/analytics/erase by key_hash.
--   idx_mcp_access_log_ip_hash      KEPT  /internal/analytics/forensics ip_hash filter and POST
--                                         /internal/analytics/erase by ip_hash. Erasure is a data-subject
--                                         right, so it keeps its index rather than scanning the table.
--   idx_mcp_access_log_country      DROP  nothing filters or groups on country; the geo rollups read
--                                         Analytics Engine, not this table.
--   idx_mcp_access_log_domain       DROP  nothing filters on domain; it is only ever selected.
--   idx_mcp_access_log_ip_masked    DROP  ip_masked appears only inside a SUM(CASE ...) in the client-ip
--                                         header audit, which is bounded by created_at, never in a WHERE.
--
-- IF EXISTS so a database that never carried one of them (the repo's older intelligence chain created
-- neither domain nor ip_masked) applies cleanly. 0001_baseline.sql is left as recorded: it mirrors the
-- schema the database was created with, and this file brings it forward.

DROP INDEX IF EXISTS idx_mcp_access_log_country;
DROP INDEX IF EXISTS idx_mcp_access_log_domain;
DROP INDEX IF EXISTS idx_mcp_access_log_ip_masked;
