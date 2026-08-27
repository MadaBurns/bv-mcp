-- Durable Brand Drift webhook outbox.
-- Apply exactly once to BRAND_AUDIT_DB before deploying consumer code that
-- selects these columns. Production D1 writes remain operator-gated.

ALTER TABLE brand_audit_watches ADD COLUMN last_classification_result_json TEXT;
ALTER TABLE brand_audit_watches ADD COLUMN pending_webhook_json TEXT;
