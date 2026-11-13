# Async batch scan provisioning

The `batch_scan_start`, `batch_scan_status`, and `batch_scan_findings` tools require the `ASYNC_BATCH_QUEUE` producer binding and the existing `SCAN_CACHE` KV binding. Results expire after seven days. Access is always checked against the authenticated principal that created the job.

Merge [`wrangler.async-batch-queues.json`](./wrangler.async-batch-queues.json) into the private deployment overlay. Before deployment, provision `async-batch-scan-queue` and `async-batch-scan-dlq` through the approved operator workflow. Do not commit account IDs or generated private Wrangler configuration.

The consumer uses batches of one and Cloudflare retries at most three times. Exhausted messages are retained in the DLQ for operator recovery. Queue creation and production deployment are intentionally outside repository setup and must be performed only with approved credentials.

The DLQ is a recovery store only; nothing consumes it. A consumer killed on every delivery (isolate eviction, CPU, memory or subrequest limits) cannot write a terminal state, so `batch_scan_status` and `batch_scan_findings` apply a read-path deadline: a queued or running job not updated for `ASYNC_BATCH_STALE_AFTER_MS` (12 minutes, derived from the lease, retry delay and attempt count in `src/tools/batch-scan-async.ts`) is returned as `failed` with `error: "consumer_abandoned"`, and that terminal state is persisted best-effort so later reads agree.
