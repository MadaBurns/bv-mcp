# Async batch scan provisioning

The `batch_scan_start`, `batch_scan_status`, and `batch_scan_findings` tools require the `ASYNC_BATCH_QUEUE` producer binding and the existing `SCAN_CACHE` KV binding. Results expire after seven days. Access is always checked against the authenticated principal that created the job.

Merge [`wrangler.async-batch-queues.json`](./wrangler.async-batch-queues.json) into the private deployment overlay. Before deployment, provision `async-batch-scan-queue` and `async-batch-scan-dlq` through the approved operator workflow. Do not commit account IDs or generated private Wrangler configuration.

The consumer uses batches of one and Cloudflare retries at most three times. Exhausted messages are retained in the DLQ for operator recovery. Queue creation and production deployment are intentionally outside repository setup and must be performed only with approved credentials.
