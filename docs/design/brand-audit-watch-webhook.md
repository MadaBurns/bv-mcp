# Brand-Audit Watch Webhook — Authoritative Wire-Format Reference (C3)

**Frozen 2026-06-22 by coordinator. Schema version: 1.**

This document is the authoritative reference for the drift-detection webhook
emitted by `bv-dns-security-mcp` when a brand-audit watch detects a
classification change. The Zod schema (`src/schemas/brand-audit-watch-webhook.ts`)
is the machine-checkable SSOT; this doc is the human-readable companion.

Downstream consumers (customer webhook receivers, **bv-web-prod G1 alert
receiver**) parse this payload. Any wire-format change requires:
1. A `schemaVersion` bump in `BrandAuditWatchWebhookPayloadSchema`.
2. A coordinator review of the frozen C3 contract (`contracts-frozen.md §C3`).
3. A G1-side update to the receiver in bv-web-prod.

---

## How a watch fires

`register_brand_audit_watch` (tool in `src/tools/brand-audit-watch.ts`) inserts
a row into `brand_audit_watches` with `last_classification_hash = NULL`. The
scheduled cron enqueues a brand-audit run for each active watch; on completion
the queue consumer calls `deliverWatchWebhookIfShifted`
(`src/queue/brand-audit-consumer.ts`).

**No domain-ownership check is performed here.** The anti-enumeration owner
check for arming a watch lives in bv-web-prod (G1), at the call site — not in
`register_brand_audit_watch`. This is a deliberate design decision (C3 §arming).

---

## Delivery conditions

- Fires when `computeClassificationHash(currentResult) ≠ last_classification_hash`.
- Does NOT fire when the hash is stable (no drift).
- Fires on the **first completed audit after registration** — when
  `last_classification_hash IS NULL` — even though there is technically no
  "previous" state to diff against. In this case `previousHash: null` and
  `changes.added` is populated with the entire current candidate set.
- For logging-only watches (no `webhook_url`), drift is detected and the new
  hash is persisted, but no HTTP delivery is made.
- Delivery is **best-effort**: a 4xx/5xx response or a network error does NOT
  mark the audit as failed; customers can re-derive state via
  `brand_audit_get_report`.

---

## Payload — frozen C3 shape (schemaVersion 1)

POST to `webhook_url`. `Content-Type: application/json`. HTTPS-only
(`safeFetch`, SSRF-validated). No extra auth headers — auth is in the URL token.

```ts
{
  schemaVersion: 1;            // Literal — bump on any wire change
  watchId: string;             // ID of the brand_audit_watches row
  auditId: string;             // ID of the brand_audits row that triggered this
  target: string;              // Watched domain (e.g. "apple.com")
  interval: 'daily' | 'weekly' | 'monthly';  // Watch cadence
  detectedAt: number;          // Epoch ms (worker clock at delivery time)
  previousHash: string | null; // SHA-256 hex of prior classification; null on first-ever delivery
  currentHash: string;         // SHA-256 hex of current classification
  changes: {
    added:    Array<{ domain: string; bucket: Bucket }>;
    removed:  Array<{ domain: string; bucket: Bucket }>;
    modified: Array<{ domain: string; bucket: Bucket; previousBucket?: Bucket }>;
  };
}

// Bucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation'
```

### Field semantics

| Field | Notes |
|---|---|
| `schemaVersion` | Always `1`. Receivers MUST check and reject unknown versions. |
| `watchId` | Treat as **untrusted** for security decisions — bv-web G1 looks up the watch by URL token, not by this field. |
| `auditId` | Use with `brand_audit_get_report` to fetch the full report. |
| `target` | The domain as stored at registration time (lowercased, no trailing dot). |
| `interval` | The cadence the customer registered with. |
| `detectedAt` | Worker clock at the point `deliverWatchWebhookIfShifted` ran. |
| `previousHash` | `null` on first-ever delivery (watch just registered). Receivers MUST handle null. |
| `currentHash` | 64-char lowercase hex SHA-256. Stable for the same candidate+bucket set regardless of result order. |
| `changes.added` | Candidates present in current run but not in previous classification. On first delivery, equals the full current candidate set. |
| `changes.removed` | Candidates present in previous classification but absent now. Empty on first delivery. |
| `changes.modified` | Candidates whose `bucket` changed. `previousBucket` is always set for modified entries. Empty on first delivery. |

---

## Classification hash algorithm

`computeClassificationHash` (`src/lib/brand-audit-classification-diff.ts`):

1. Extract `(domain, bucket)` tuples from `result.findings` where `metadata.candidate` and `metadata.bucket` are strings.
2. Sort tuples lexicographically by `domain`.
3. Join as `domain1:bucket1|domain2:bucket2|…`.
4. SHA-256 the UTF-8 bytes. Return 64-char lowercase hex.

The hash is order-independent and summary-row-independent. Two results with
identical candidate+bucket sets always produce the same hash.

---

## Receiver guidance (bv-web-prod G1 / customer webhooks)

1. **Verify `schemaVersion === 1`** — reject and log any unknown version rather
   than silently parsing.
2. **Handle `previousHash: null`** — this is the normal initial event after a
   watch registers. Treat it as "full current state" using `changes.added`.
3. **Treat `watchId` as untrusted** — look up the watch by the URL token, not
   by `watchId`.
4. **Fetch full detail via `brand_audit_get_report(auditId)`** when needed —
   the webhook carries only the diff, not the full result JSON.
5. **Tolerate empty `changes` arrays** — an audit could theoretically detect
   hash drift while all three change arrays are empty (hash function collision or
   future bucket rename); don't hard-fail on that.

---

## Test coverage

| Test file | What it locks |
|---|---|
| `test/contracts/brand-audit-watch-webhook.contract.test.ts` | Schema accepts/rejects correct shape; **emitter round-trip**: real `processBrandAuditMessage` produces a `BrandAuditWatchWebhookPayloadSchema`-valid payload for both drift and first-ever delivery |
| `test/audits/brand-audit-watch-webhook.audit.test.ts` | Every documented top-level field exists; `schemaVersion` is literal 1 |
| `test/chaos/brand-audit-webhook-delivery.chaos.test.ts` | Failure modes: webhook 500, hash-before-delivery ordering, no-url watch, cross-owner spoof, no-drift suppression, first-ever `added` population |
