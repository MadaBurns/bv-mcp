// SPDX-License-Identifier: BUSL-1.1
import { z } from 'zod';
import { DomainSchema } from './primitives';

/**
 * Inter-service contract for the Tenant (Continuous Security Compliance) cycle-diff
 * alert payload pushed to ALERT_WEBHOOK_URL by the Wave D cron handler.
 *
 * Phase 3 ships only the producer half (this schema + diff + webhook delivery).
 * Cron wiring lives in src/scheduled.ts (Wave D) and is not modified here.
 *
 * Hard rules:
 *   - Severity is the canonical 5-level enum, normalised case-insensitively.
 *   - `title` is bounded and stripped of control characters (mirrors src/lib/log.ts
 *     `sanitizeString`) so a malicious DNS record cannot inject newlines/ANSI
 *     sequences into the operator's chat client.
 *   - `webhook_url_hash` is FNV-1a truncated to 16 lowercase hex chars — the
 *     same shape we already use for keyHash/principalIdHash. The raw URL never
 *     appears in the payload (it's already in the env var).
 *   - `highlights` is capped at 20 entries by the producer (computeCycleDiff)
 *     and re-asserted here as a defensive ceiling.
 *
 * `.passthrough()` is project convention — consumers may receive future fields
 * without breaking; producers must not rely on stripping behaviour.
 */

export const TENANT_SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type TenantSeverity = (typeof TENANT_SEVERITY_LEVELS)[number];

const SeverityLowercase = z
	.string()
	.transform((s) => s.trim().toLowerCase())
	.pipe(z.enum(TENANT_SEVERITY_LEVELS));

const DeltaKindSchema = z.enum(['gained', 'lost', 'severity_changed']);

/** Strip control chars (matches src/lib/log.ts:sanitizeString) and bound length. */
const SANITIZED_CONTROL_RE = /[\x00-\x08\x0a-\x1f\x7f]/g;
const SanitizedTitleSchema = z
	.string()
	.transform((s) => s.replace(SANITIZED_CONTROL_RE, ' '))
	.pipe(z.string().min(1).max(200));

/**
 * One finding-level delta between the current cycle and the prior baseline.
 * `severity_changed` carries `previous_severity`; `gained` / `lost` do not need it.
 */
export const TenantFindingDeltaSchema = z
	.object({
		domain: DomainSchema,
		category: z.string().min(1).max(64),
		severity: SeverityLowercase,
		title: SanitizedTitleSchema,
		delta: DeltaKindSchema,
		previous_severity: SeverityLowercase.optional(),
		cycle_id: z.string().min(1).max(128),
		scan_at: z.number().int().nonnegative(),
	})
	.passthrough();

export type TenantFindingDelta = z.infer<typeof TenantFindingDeltaSchema>;

const SeverityCountSchema = z
	.object({
		critical: z.number().int().nonnegative().default(0),
		high: z.number().int().nonnegative().default(0),
		medium: z.number().int().nonnegative().default(0),
		low: z.number().int().nonnegative().default(0),
		info: z.number().int().nonnegative().default(0),
	})
	.passthrough();

const TotalsSchema = z
	.object({
		domains_scanned: z.number().int().nonnegative(),
		deltas: z.number().int().nonnegative(),
		by_severity: SeverityCountSchema,
	})
	.passthrough();

/**
 * Top-level tenant cycle-diff alert payload.
 *
 * Highlights are the top-N (≤20) deltas ordered critical → info. The producer
 * (`computeCycleDiff`) is responsible for ordering; this schema only enforces
 * the ceiling.
 */
export const TenantCycleAlertSchema = z
	.object({
		type: z.literal('tenant_cycle_diff'),
		emitted_at: z.number().int().nonnegative(),
		super_tenant_id: z.string().min(1).max(128),
		sub_tenant_id: z.string().min(1).max(128),
		current_cycle_id: z.string().min(1).max(128),
		baseline_cycle_id: z.string().min(1).max(128).nullable(),
		totals: TotalsSchema,
		highlights: z.array(TenantFindingDeltaSchema).max(20),
		webhook_url_hash: z.string().regex(/^[a-f0-9]{16}$/),
	})
	.passthrough();

export type TenantCycleAlert = z.infer<typeof TenantCycleAlertSchema>;

/**
 * FNV-1a hash truncated/padded to 16 lowercase hex chars. Stable across isolates
 * and runtimes (no Web Crypto async). Same algorithm shape as the existing
 * principalIdHash / keyHash convention so schemas line up.
 */
export function hashWebhookUrl(url: string): string {
	let hash = 0x811c9dc5;
	const normalized = url.trim().toLowerCase();
	for (let i = 0; i < normalized.length; i += 1) {
		hash ^= normalized.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193);
	}
	const hex = (hash >>> 0).toString(16);
	return hex.padStart(16, '0').slice(0, 16);
}
