-- scripts/intelligence/sql/0003_mcp_access_log_source.sql
-- Migration: add the request-source dimension to mcp_access_log.
-- Target binding: INTELLIGENCE_DB (D1)
-- Provisioning (operator-run, idempotent — run BEFORE deploying the source-tagging producer;
-- otherwise the INSERT references a non-existent `source` column and every access-log write throws):
--   wrangler d1 execute <intelligence-db-name> --remote --file scripts/intelligence/sql/0003_mcp_access_log_source.sql
-- `source` is nullable and NOT backfilled — the ~88k existing rows stay NULL. Queries treat
-- NULL as the public path via COALESCE(source, 'public'). Values:
--   'public'   — the public /mcp path (recordMcpAccessLog default)
--   'internal' — the service-binding /internal/tools/* path (bv-web-forwarded scans)

ALTER TABLE mcp_access_log ADD COLUMN source TEXT;
