// SPDX-License-Identifier: BUSL-1.1

/**
 * Published wire-format contract for brand-audit watch webhook deliveries.
 *
 * When the scheduled cron tick detects classification drift on a watched
 * domain (the SHA-256 of the sorted candidate+bucket tuples differs from
 * `last_classification_hash`), the worker POSTs this payload to the watch's
 * `webhook_url` via `safeFetch` (SSRF-validated).
 *
 * Shared between producer (this worker) and downstream consumers (customer
 * webhook receivers, bv-web alert UI). Locked here to prevent silent drift.
 *
 * Subset semantics:
 *   - `added`   — candidates surfaced in the current run but absent from the
 *                 previous classification hash
 *   - `removed` — candidates that were present last time but no longer surface
 *   - `modified` — candidates whose bucket changed (e.g. shadowIt → consolidated
 *                 after a registrar update)
 *
 * Each entry is the bucket-tagged candidate domain — full result_json is NOT
 * sent over the webhook (cost + payload size). Subscribers can fetch the full
 * report via `brand_audit_get_report` using the included `auditId`.
 */

import { z } from 'zod';

export const BrandAuditBucketSchema = z.enum(['consolidated', 'shadowIt', 'indeterminate', 'impersonation']);

export const BrandAuditWatchDiffEntrySchema = z.object({
	domain: z.string().min(1).max(253),
	bucket: BrandAuditBucketSchema,
	previousBucket: BrandAuditBucketSchema.optional(),
});

export const BrandAuditWatchWebhookPayloadSchema = z.object({
	/** Schema version — bump on any wire-format change. Subscribers MUST check. */
	schemaVersion: z.literal(1),
	/** Watch row that triggered this delivery. */
	watchId: z.string().min(1).max(64),
	/** Most-recent audit that produced the new classification. */
	auditId: z.string().min(1).max(64),
	/** Domain being watched. */
	target: z.string().min(1).max(253),
	/** Interval the watch was registered with. */
	interval: z.enum(['daily', 'weekly', 'monthly']),
	/** Epoch ms when the diff was detected (worker clock). */
	detectedAt: z.number().int().nonnegative(),
	/** SHA-256 hex of the previous classification — null on first-ever delivery. */
	previousHash: z.string().regex(/^[a-f0-9]{64}$/).nullable(),
	/** SHA-256 hex of the current classification. */
	currentHash: z.string().regex(/^[a-f0-9]{64}$/),
	changes: z.object({
		added: z.array(BrandAuditWatchDiffEntrySchema),
		removed: z.array(BrandAuditWatchDiffEntrySchema),
		modified: z.array(BrandAuditWatchDiffEntrySchema),
	}),
});

export type BrandAuditWatchWebhookPayload = z.infer<typeof BrandAuditWatchWebhookPayloadSchema>;
export type BrandAuditWatchDiffEntry = z.infer<typeof BrandAuditWatchDiffEntrySchema>;
