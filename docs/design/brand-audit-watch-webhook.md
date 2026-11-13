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
- Delivery failure does NOT mark the audit as failed. The exact notification is
  kept in the watch outbox for the next tick, and customers can independently
  re-derive state via `brand_audit_get_report`.
- Delivery is **at least once**, not exactly once. The classification hash
  advances only after a 2xx response. Before the POST, the consumer stores an
  exact `{ payload, currentResult }` envelope in `pending_webhook_json` using a
  compare-and-swap against the prior hash. A timeout/non-2xx leaves that outbox
  entry intact; the next watch run replays the original stored payload instead
  of recomputing against a newer completed audit. The 2xx
  CAS atomically advances the hash, stores the matching full-result baseline,
  and clears the outbox. If that recovery tick already contains a newer
  classification, the consumer immediately stages and delivers the next diff
  from the recovered baseline in the same invocation; ordered alerts never wait
  for another daily/weekly/monthly interval. A crash between the 2xx and CAS can produce a duplicate.
  Receivers must deduplicate with `watchId + auditId + currentHash`.
- A stale concurrent delivery can still reach a receiver, but its CAS cannot
  overwrite a newer stored classification. Receivers should treat `detectedAt`
  and `currentHash` as ordering/idempotency inputs rather than arrival order.

---

## Payload — frozen C3 shape (schemaVersion 1)

POST to `webhook_url`. `Content-Type: application/json`. HTTPS-only. Customer
URLs use `safeFetch` (SSRF-validated) and receive no internal authentication
header; their auth remains the URL token. The exact BlackVeil receiver
(`https://www.blackveilsecurity.com/api/webhooks/brand-drift`) is a special
first-party path: delivery uses the private `BV_WEB` service binding and a
dedicated `BV_MCP_BRAND_WEBHOOK_KEY` bearer. The bearer is never attached to
any other origin/path, and redirects are never followed.

Each of `changes.added`, `changes.removed`, and `changes.modified` is bounded
at 200 rows, matching the producer pipeline's maximum candidate set. The UTF-8
encoded request body is bounded at 256 KiB on both producer and first-party
receiver. The producer validates both limits before staging the durable outbox,
so an undeliverable oversized event cannot permanently block later alerts.

```ts
{
	schemaVersion: 1; // Literal — bump on any wire change
	watchId: string; // ID of the brand_audit_watches row
	auditId: string; // ID of the brand_audits row that triggered this
	target: string; // Watched domain (e.g. "apple.com")
	interval: 'daily' | 'weekly' | 'monthly'; // Watch cadence
	detectedAt: number; // Epoch ms (worker clock at delivery time)
	previousHash: string | null; // SHA-256 hex of prior classification; null on first-ever delivery
	currentHash: string; // SHA-256 hex of current classification
	changes: {
		added: Array<{ domain: string; bucket: Bucket }>;
		removed: Array<{ domain: string; bucket: Bucket }>;
		modified: Array<{ domain: string; bucket: Bucket; previousBucket?: Bucket }>;
	}
}

// Bucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation' | 'impersonationSurface'
```

### Field semantics

| Field              | Notes                                                                                                                           |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `schemaVersion`    | Always `1`. Receivers MUST check and reject unknown versions.                                                                   |
| `watchId`          | Treat as **untrusted** for security decisions — bv-web G1 looks up the watch by URL token, not by this field.                   |
| `auditId`          | Use with `brand_audit_get_report` to fetch the full report.                                                                     |
| `target`           | The domain as stored at registration time (lowercased, no trailing dot).                                                        |
| `interval`         | The cadence the customer registered with.                                                                                       |
| `detectedAt`       | Worker clock at the point `deliverWatchWebhookIfShifted` ran.                                                                   |
| `previousHash`     | `null` on first-ever delivery (watch just registered). Receivers MUST handle null.                                              |
| `currentHash`      | 64-char lowercase hex SHA-256. Stable for the same candidate+bucket set regardless of result order.                             |
| `changes.added`    | Candidates present in current run but not in previous classification. On first delivery, equals the full current candidate set. |
| `changes.removed`  | Candidates present in previous classification but absent now. Empty on first delivery.                                          |
| `changes.modified` | Candidates whose `bucket` changed. `previousBucket` is always set for modified entries. Empty on first delivery.                |

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

## Origin signature (optional, caller-supplied URLs)

The URL token proves nothing about who is calling it. When the operator has
enabled signing, every delivery to a caller-supplied `webhook_url` carries one
extra header, so a receiver can check that the request came from this service
and that the body was not altered in transit:

```
X-Blackveil-Signature: t=<unix seconds>,v1=<lowercase hex>
```

- `t` is the Unix time in seconds at which the delivery attempt was signed. A
  replayed outbox entry is signed again, so `t` always reflects the latest
  attempt.
- `v1` is HMAC-SHA256 over the ASCII string `<t>.` followed by the exact request
  body bytes, hex-encoded in lowercase. The signature is computed over the same
  string that is sent, never a re-serialisation.
- The HMAC key is the per-watch signing secret, used as its 64-character hex
  text (its UTF-8 bytes), not decoded to raw bytes.

The first-party BlackVeil receiver path is not signed; it keeps its dedicated
service-binding bearer.

### How the per-watch secret works

Nothing is stored per watch and there is no schema change. The per-watch secret
is derived on demand as `hex(HMAC-SHA256(server secret, label + watchId))`,
where the server secret is the Worker secret `WATCH_WEBHOOK_SIGNING_SECRET` and
the label is the fixed string `blackveil:brand-audit-watch-webhook:v1:`. Each
watch therefore has its own key, and the same watch always has the same key.

`register_brand_audit_watch` returns the secret once, as `signingSecret` in the
result (with a one-sentence note that it is shown only at registration), and only
for a watch that has a `webhook_url`. `list_brand_audit_watches` and every other
read never return it. The server secret, the derived key and signatures are
never logged.

### How a receiver verifies a delivery

1. Read the raw request body bytes before any JSON parsing.
2. Parse `t` and `v1` from the `X-Blackveil-Signature` header; reject a header
   that does not match the format above.
3. Reject the request if `t` is older (or further in the future) than a
   tolerance you choose. Five minutes is a sensible starting point.
4. Compute HMAC-SHA256 with the watch's `signingSecret` as the key over
   `<t>.<raw body>` and hex-encode it in lowercase.
5. Compare it with `v1` using a constant-time comparison. Reject on mismatch.

Signature checks do not replace the idempotency guidance below: delivery is
still at least once, so deduplicate with `watchId + auditId + currentHash`.

### Operator step to enable it

Signing is off by default and the secret is never required for a deploy.

1. Generate a strong value of at least 32 bytes (for example
   `openssl rand -base64 48`) that is different from every other secret on the
   Worker.
2. `npx wrangler secret put WATCH_WEBHOOK_SIGNING_SECRET` and deploy.

If the value is unset, empty, shorter than 32 bytes or equal to another
security-critical secret, signing stays off: deliveries are sent exactly as
before with no signature header, and registration returns no `signingSecret`.

Watches registered before the secret was set are signed as soon as it is set,
because their keys are derived rather than stored. Their owners did not receive
a secret at registration, so they must re-register the watch to obtain one.
Rotating the server secret changes every derived key; owners need to re-register
to get new secrets.

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
6. **Accept the documented bounds** — up to 200 entries in each change array
   and up to 256 KiB of encoded JSON. Reject anything larger.

---

## Test coverage

| Test file                                                   | What it locks                                                                                                                                                                                                                                           |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `test/contracts/brand-audit-watch-webhook.contract.test.ts` | Schema accepts/rejects correct shape and the exact 200/201 boundary; **emitter round-trip**: real `processBrandAuditMessage` produces a `BrandAuditWatchWebhookPayloadSchema`-valid payload for both drift and first-ever delivery                      |
| `test/audits/brand-audit-watch-webhook.audit.test.ts`       | Every documented top-level field exists; `schemaVersion` is literal 1                                                                                                                                                                                   |
| `test/chaos/brand-audit-webhook-delivery.chaos.test.ts`     | Failure modes: durable failed→unchanged and failed-H1→current-H2 ordered replay, 200-row pending recovery, stale-parent exact-hash recovery, concurrent stale CAS, no-url watch, cross-owner spoof, no-drift suppression, first-ever `added` population |
