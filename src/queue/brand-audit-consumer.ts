// SPDX-License-Identifier: BUSL-1.1

/**
 * Cloudflare Queue consumer for the brand-audit batch flow.
 *
 * Each message is `{ auditId, target, format, min_confidence? }` (produced by
 * `brand_audit_batch_start`). For each message we:
 *
 *   1. **Idempotency check** — SELECT status FROM brand_audit_targets WHERE
 *      audit_id=? AND target=?. If already 'completed' or 'failed', ack the
 *      message and return — Cloudflare Queues can deliver the same message N
 *      times on retry, so re-running brandAuditSingle would double-count and
 *      waste budget.
 *   2. **Status flip → 'running'** with started_at timestamp.
 *   3. Call `brandAuditSingle(target, ...)` — the same orchestrator that powers
 *      the sync surface. Wall time per target ≈ 3 min for tier-1 brands.
 *   4. **Status flip → 'completed'** with result_json + completed_at, OR
 *      `'failed'` with error string. Use a transient-error guard so a D1 hiccup
 *      mid-write maps to `retry`, not `ack` (Cloudflare will redeliver).
 *   5. **Counter tick** — atomic UPDATE brand_audits SET completed_targets =
 *      completed_targets + 1. If post-tick completed_targets === total_targets,
 *      mark the audit `completed` and stamp completed_at.
 *
 * Phase 3 will additionally enqueue to the PDF queue on completion when
 * `format ∈ {markdown, both}` requests a PDF rendering. v2.19.0 only stores the
 * result_json blob.
 */

import { z } from 'zod';
import { brandAuditSingle as defaultBrandAuditSingle } from '../tools/brand-audit-single';
import type { CheckResult } from '../lib/scoring';

/** Cloudflare Queues redelivery budget: keep messages alive for at most 5 min total. */
export const BRAND_AUDIT_MESSAGE_TIMEOUT_MS = 300_000;

/** Wire format for a brand-audit queue message. Validated on the consumer side as defense in depth. */
export const BrandAuditQueueMessageSchema = z.object({
	auditId: z.string().min(1).max(64),
	target: z.string().min(1).max(253),
	format: z.enum(['json', 'markdown', 'both']),
	min_confidence: z.number().min(0).max(1).optional(),
});

export type BrandAuditQueueMessage = z.infer<typeof BrandAuditQueueMessageSchema>;

export interface BrandAuditConsumerDeps {
	db: D1Database;
	/** Injectable for tests. */
	brandAuditSingle?: (target: string, options: { format?: 'json' | 'markdown' | 'both'; min_confidence?: number }) => Promise<CheckResult>;
	/** Clock override for tests. */
	now?: () => number;
}

interface TargetStatusRow {
	status: 'queued' | 'running' | 'completed' | 'failed';
	completed_at: number | null;
}

interface AuditCounterRow {
	completed_targets: number;
	total_targets: number;
}

/**
 * Process a single message body. Returns:
 *   - `'ack'` — message handled (success, idempotent skip, or unrecoverable error)
 *   - `'retry'` — transient infrastructure failure; Cloudflare should redeliver
 */
export async function processBrandAuditMessage(
	rawBody: unknown,
	deps: BrandAuditConsumerDeps,
): Promise<'ack' | 'retry'> {
	const parsed = BrandAuditQueueMessageSchema.safeParse(rawBody);
	if (!parsed.success) {
		// Malformed payload — never recoverable by retry. Drop.
		return 'ack';
	}
	const message = parsed.data;
	const now = (deps.now ?? Date.now)();
	const single = deps.brandAuditSingle ?? defaultBrandAuditSingle;

	// 1. Idempotency check.
	let existing: TargetStatusRow | null;
	try {
		existing = (await deps.db
			.prepare(
				'SELECT status, completed_at FROM brand_audit_targets WHERE audit_id = ? AND target = ? LIMIT 1',
			)
			.bind(message.auditId, message.target)
			.first()) as TargetStatusRow | null;
	} catch {
		return 'retry';
	}

	if (!existing) {
		// Target row missing — producer should have inserted it. Treat as
		// unrecoverable (don't loop the queue) but don't fan out work either.
		return 'ack';
	}

	if (existing.status === 'completed' || existing.status === 'failed') {
		// Duplicate delivery of a terminal-state row. Ack without re-running.
		return 'ack';
	}

	// 2. Status flip → 'running'.
	try {
		await deps.db
			.prepare(
				"UPDATE brand_audit_targets SET status = 'running' WHERE audit_id = ? AND target = ? AND status = 'queued'",
			)
			.bind(message.auditId, message.target)
			.run();
	} catch {
		return 'retry';
	}

	// 3. Run the orchestrator with a hard timeout. Tier-1 brands average ~3 min
	// per target; we cap at BRAND_AUDIT_MESSAGE_TIMEOUT_MS (5 min) so a single
	// stuck WHOIS / RDAP chain can't ride out the Worker's full retry budget.
	// On timeout the target row flips to `failed` with a structured error rather
	// than mysteriously remaining in `running`.
	let result: CheckResult | null = null;
	let runtimeError: string | null = null;
	try {
		result = await Promise.race([
			single(message.target, {
				format: message.format,
				min_confidence: message.min_confidence,
			}),
			new Promise<never>((_, reject) =>
				setTimeout(
					() => reject(new Error(`brand_audit_single timed out after ${BRAND_AUDIT_MESSAGE_TIMEOUT_MS}ms`)),
					BRAND_AUDIT_MESSAGE_TIMEOUT_MS,
				),
			),
		]);
	} catch (err) {
		runtimeError = err instanceof Error ? err.message : String(err);
	}

	// 4. Status flip → 'completed' | 'failed'. Treat D1 write failure here as
	// retryable (Cloudflare redelivers; idempotency check up top short-circuits).
	const finalStatus = runtimeError ? 'failed' : 'completed';
	const resultJson = result ? JSON.stringify(result) : null;
	const errorString = runtimeError ? sanitizeErrorString(runtimeError) : null;

	try {
		await deps.db
			.prepare(
				'UPDATE brand_audit_targets SET status = ?, result_json = ?, error = ?, completed_at = ? WHERE audit_id = ? AND target = ?',
			)
			.bind(finalStatus, resultJson, errorString, now, message.auditId, message.target)
			.run();
	} catch {
		return 'retry';
	}

	// 5. Counter tick — bump completed_targets and check finalization.
	try {
		await deps.db
			.prepare(
				'UPDATE brand_audits SET completed_targets = completed_targets + 1, updated_at = ? WHERE id = ?',
			)
			.bind(now, message.auditId)
			.run();

		const counter = (await deps.db
			.prepare(
				'SELECT completed_targets, total_targets FROM brand_audits WHERE id = ? LIMIT 1',
			)
			.bind(message.auditId)
			.first()) as AuditCounterRow | null;

		if (counter && counter.completed_targets >= counter.total_targets) {
			await deps.db
				.prepare(
					"UPDATE brand_audits SET status = 'completed', completed_at = ?, updated_at = ? WHERE id = ?",
				)
				.bind(now, now, message.auditId)
				.run();
		}
	} catch {
		// Counter-tick failure leaves the audit row stale but the target row is
		// already terminal — manual reconciliation via a scheduled cleanup
		// (Phase 4). We still ack to avoid re-running brandAuditSingle.
		return 'ack';
	}

	return 'ack';
}

/** Strip newlines / runaway-length from error strings before persisting. */
function sanitizeErrorString(raw: string): string {
	return raw.replace(/[\r\n\t]+/g, ' ').slice(0, 500);
}

/** Cloudflare Queue consumer entrypoint — fans out to `processBrandAuditMessage` per message. */
export async function handleBrandAuditQueue(
	batch: MessageBatch<unknown>,
	deps: BrandAuditConsumerDeps,
): Promise<void> {
	for (const message of batch.messages) {
		const verdict = await processBrandAuditMessage(message.body, deps);
		if (verdict === 'retry') {
			message.retry();
		} else {
			message.ack();
		}
	}
}
