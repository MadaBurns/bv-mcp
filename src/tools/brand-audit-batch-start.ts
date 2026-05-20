// SPDX-License-Identifier: BUSL-1.1

/**
 * brand_audit_batch_start — producer for the async brand-audit flow.
 *
 * Validates the domain list (max 50, deduplicated, non-empty), optionally consumes
 * per-tier monthly quota atomically at enqueue time (so a partial-failure batch
 * can't refund quota), writes the parent `brand_audits` row to D1, then enqueues
 * one `{ auditId, target }` message per target onto BRAND_AUDIT_QUEUE.
 *
 * Returns a `CheckResult` whose summary metadata carries `{ auditId, queuedAt,
 * targetCount, etaSeconds }`. The caller polls with `brand_audit_status` and
 * fetches results with `brand_audit_get_report` once status → 'completed'.
 *
 * Failure modes:
 *   - Empty/invalid domain list → `invalidInput` finding, no quota consumed
 *   - Over 50 domains → `batchTooLarge` finding, no quota consumed
 *   - Quota exceeded (when enforceQuota dep is wired) → `quotaExceeded` finding,
 *     no D1 write
 *   - D1 parent or child insert fails → `persistenceFailure` finding, no queue.send
 *     fires (caller can safely retry — no half-written state visible to consumers)
 *   - queue.send fails for SOME targets mid-loop → `partialEnqueue` finding listing
 *     `failedToEnqueue: [{ target, error }]`. The audit row's status is flipped to
 *     `'failed'` so the polling tool stops claiming progress against targets that
 *     no consumer will pick up.
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import type { BrandAuditFormat } from '../lib/db/brand-audit-schema';

const CATEGORY = 'brand_discovery';

/** Hard cap on targets per batch. Aligns with Phase 2 plan §scope. */
const MAX_TARGETS_PER_BATCH = 50;

/**
 * ETA per target. Tier-1 brand audits average ~3 min wall clock (40+ candidates
 * × RDAP fanout). Used for the response so the caller can poll at a reasonable
 * interval rather than tight-looping.
 */
const ETA_SECONDS_PER_TARGET = 180;

export interface BrandAuditBatchStartOptions {
	format?: BrandAuditFormat;
	min_confidence?: number;
	depth?: 'standard' | 'deep';
	planner_mode?: 'off' | 'observe' | 'enforce';
	brand_aliases?: string[];
	candidate_domains?: string[];
	/**
	 * Threaded onto the queue message so the consumer can route discovery
	 * through the tiered pipeline. Explicit caller value always wins over
	 * env BRAND_AUDIT_DISCOVERY_MODE_DEFAULT on the consumer side.
	 */
	discovery_mode?: 'classic' | 'tiered';
}

export type EnforceBrandAuditQuota = (count: number) => Promise<{
	allowed: boolean;
	remaining?: number;
	limit?: number;
	retryAfterMs?: number;
}>;

export interface BrandAuditQueueMessage {
	auditId: string;
	target: string;
	format: BrandAuditFormat;
	min_confidence?: number;
	depth?: 'standard' | 'deep';
	planner_mode?: 'off' | 'observe' | 'enforce';
	brand_aliases?: string[];
	candidate_domains?: string[];
	/** Per-target discovery mode override. Consumer threads to runBrandAuditPipeline. */
	discovery_mode?: 'classic' | 'tiered';
}

export interface BrandAuditQueueProducer {
	send(message: BrandAuditQueueMessage, options?: { contentType?: 'json' }): Promise<void>;
}

/** Injectable deps. Production wiring threads env bindings; tests pass mocks. */
export interface BrandAuditBatchStartDeps {
	db: D1Database;
	queue: BrandAuditQueueProducer;
	enforceQuota?: EnforceBrandAuditQuota;
	/** UUID generator override for deterministic tests. */
	generateId?: () => string;
	/** Clock override for deterministic tests. */
	now?: () => number;
}

function buildErrorResult(
	flag: 'invalidInput' | 'batchTooLarge' | 'quotaExceeded' | 'persistenceFailure',
	message: string,
	extra: Record<string, unknown> = {},
): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Brand audit batch start: ${flag}`, 'high', message, {
			[flag]: true,
			...extra,
		}),
	]);
}

function normaliseDomains(input: readonly string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (const raw of input) {
		if (typeof raw !== 'string') continue;
		const norm = raw.trim().toLowerCase().replace(/\.$/, '');
		if (!norm || seen.has(norm)) continue;
		seen.add(norm);
		out.push(norm);
	}
	return out;
}

export async function brandAuditBatchStart(
	domains: readonly string[],
	options: BrandAuditBatchStartOptions,
	ownerId: string,
	deps: BrandAuditBatchStartDeps,
): Promise<CheckResult> {
	if (!Array.isArray(domains) || domains.length === 0) {
		return buildErrorResult('invalidInput', 'Empty or invalid domain list.');
	}

	if (domains.length > MAX_TARGETS_PER_BATCH) {
		return buildErrorResult(
			'batchTooLarge',
			`Batch size ${domains.length} exceeds the per-call cap of ${MAX_TARGETS_PER_BATCH}.`,
			{ submittedCount: domains.length, cap: MAX_TARGETS_PER_BATCH },
		);
	}

	const targets = normaliseDomains(domains);
	if (targets.length === 0) {
		return buildErrorResult('invalidInput', 'No usable targets after normalisation.');
	}

	const enforce = deps.enforceQuota;
	if (enforce) {
		const verdict = await enforce(targets.length);
		if (!verdict.allowed) {
			const retryHint =
				typeof verdict.retryAfterMs === 'number'
					? ` retry after ${Math.ceil(verdict.retryAfterMs / 1000)}s`
					: '';
			return buildErrorResult(
				'quotaExceeded',
				`Monthly quota of ${verdict.limit ?? 0} targets reached for this principal.${retryHint}`,
				{
					target: ownerId,
					limit: verdict.limit ?? 0,
					remaining: verdict.remaining ?? 0,
					retryAfterMs: verdict.retryAfterMs,
					requested: targets.length,
				},
			);
		}
	}

	const auditId = (deps.generateId ?? defaultGenerateId)();
	const now = (deps.now ?? Date.now)();
	const format: BrandAuditFormat = options.format ?? 'both';

	try {
		await deps.db
			.prepare(
				'INSERT INTO brand_audits (id, owner_id, status, total_targets, completed_targets, format, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			)
			.bind(auditId, ownerId, 'queued', targets.length, 0, format, now, now)
			.run();

		for (const target of targets) {
			await deps.db
				.prepare(
					'INSERT INTO brand_audit_targets (audit_id, target, status, created_at) VALUES (?, ?, ?, ?)',
				)
				.bind(auditId, target, 'queued', now)
				.run();
		}
	} catch (err) {
		return buildErrorResult(
			'persistenceFailure',
			`Failed to persist brand audit row: ${err instanceof Error ? err.message : String(err)}`,
			{ auditId },
		);
	}

	const enqueued: string[] = [];
	const failedToEnqueue: { target: string; error: string }[] = [];
	for (const target of targets) {
		try {
			await deps.queue.send(
				{
					auditId,
					target,
					format,
					min_confidence: options.min_confidence,
					depth: options.depth,
					planner_mode: options.planner_mode,
					brand_aliases: options.brand_aliases,
					candidate_domains: options.candidate_domains,
					discovery_mode: options.discovery_mode,
				},
				{ contentType: 'json' },
			);
			enqueued.push(target);
		} catch (err) {
			failedToEnqueue.push({
				target,
				error: err instanceof Error ? err.message : String(err),
			});
		}
	}

	// On any enqueue failure, mark the audit `failed` so the polling tool stops
	// claiming progress against targets that no consumer will ever pick up.
	// The audit row + per-target rows already exist; we flip parent.status only.
	if (failedToEnqueue.length > 0) {
		try {
			await deps.db
				.prepare("UPDATE brand_audits SET status = 'failed', updated_at = ? WHERE id = ?")
				.bind(now, auditId)
				.run();
		} catch {
			// Best-effort — the partialEnqueue finding still surfaces the truth to the caller.
		}
	}

	const etaSeconds = ETA_SECONDS_PER_TARGET * Math.max(1, Math.ceil(enqueued.length / 5));
	const isPartial = failedToEnqueue.length > 0;
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			isPartial
				? `Brand audit batch partially queued: ${enqueued.length}/${targets.length} target(s)`
				: `Brand audit batch queued: ${targets.length} target(s)`,
			isPartial ? 'medium' : 'info',
			`auditId=${auditId} queuedAt=${new Date(now).toISOString()} etaSeconds=${etaSeconds}`,
			{
				summary: true,
				auditId,
				queuedAt: now,
				targetCount: enqueued.length,
				etaSeconds,
				format,
				targets: enqueued,
				...(isPartial && {
					partialEnqueue: true,
					failedToEnqueue,
					requestedCount: targets.length,
				}),
			},
		),
	]);
}

function defaultGenerateId(): string {
	return crypto.randomUUID();
}
