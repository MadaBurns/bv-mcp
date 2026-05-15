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
import type { CheckResult, Finding } from '../lib/scoring';

/** Cloudflare Queues redelivery budget: keep messages alive for at most 5 min total. */
export const BRAND_AUDIT_MESSAGE_TIMEOUT_MS = 300_000;

/** Wire format for a brand-audit queue message. Validated on the consumer side as defense in depth. */
export const BrandAuditQueueMessageSchema = z.object({
	auditId: z.string().min(1).max(64),
	target: z.string().min(1).max(253),
	format: z.enum(['json', 'markdown', 'both']),
	min_confidence: z.number().min(0).max(1).optional(),
	/** Set when the message originated from the watch cron — drives post-completion diff/webhook. */
	watchId: z.string().min(1).max(64).optional(),
	/** Bound at enqueue time so the consumer doesn't need a D1 round-trip to look up the watch's owner. */
	ownerId: z.string().min(1).max(128).optional(),
});

export type BrandAuditQueueMessage = z.infer<typeof BrandAuditQueueMessageSchema>;

export interface BrandAuditConsumerDeps {
	db: D1Database;
	/** Injectable for tests. */
	brandAuditSingle?: (target: string, options: { format?: 'json' | 'markdown' | 'both'; min_confidence?: number }) => Promise<CheckResult>;
	/** Clock override for tests. */
	now?: () => number;
	/**
	 * Optional fanout to the PDF render queue. When present AND the message
	 * requested a PDF (`format ∈ {markdown, both}`), the consumer enqueues a
	 * follow-up `{ auditId, target, format }` after persisting the result.
	 * Absent in dev / unprovisioned environments — primary completion still
	 * succeeds; PDF rendering just doesn't happen.
	 */
	pdfQueue?: { send(message: { auditId: string; target: string; format: 'json' | 'markdown' | 'both' }, options?: { contentType?: 'json' }): Promise<void> };
	/**
	 * Optional webhook delivery function. When set + the message carries a
	 * watchId + the new classification differs from the watch's previous
	 * `last_classification_hash`, the consumer POSTs the diff payload here.
	 * Returns true on 2xx delivery, false on failure (never throws).
	 * Defaults to a `safeFetch`-wrapped POST in production.
	 */
	deliverWebhook?: (url: string, payload: unknown) => Promise<boolean>;
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

	// 4a. Fanout: enqueue PDF render when one was requested AND the target
	// completed (don't bother on `failed`). Best-effort — if the PDF queue
	// binding is unavailable or send throws, we swallow and proceed; the
	// primary completion is the durability boundary, not PDF render.
	if (finalStatus === 'completed' && deps.pdfQueue && (message.format === 'markdown' || message.format === 'both')) {
		try {
			await deps.pdfQueue.send(
				{ auditId: message.auditId, target: message.target, format: message.format },
				{ contentType: 'json' },
			);
		} catch {
			// swallow — PDF rendering is enrichment, not part of the
			// audit's durability contract
		}
	}

	// 4b. Watch webhook delivery (v2.21.1+). When this message originated from
	// the cron watch handler (carries watchId), compute the classification hash
	// vs the watch's `last_classification_hash` and POST a diff webhook if
	// shifted. Best-effort — webhook failure does NOT mark the audit failed;
	// just logged-and-skipped so customers can re-derive from get-report.
	if (finalStatus === 'completed' && result !== null && message.watchId) {
		try {
			await deliverWatchWebhookIfShifted({
				db: deps.db,
				watchId: message.watchId,
				auditId: message.auditId,
				target: message.target,
				ownerId: message.ownerId ?? null,
				current: result,
				now,
				deliverWebhook: deps.deliverWebhook ?? defaultDeliverWebhook,
			});
		} catch {
			// Same fail-soft posture as PDF fanout.
		}
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

// ----------------------------------------------------------------------------
// v2.21.1: watch webhook delivery on classification drift
// ----------------------------------------------------------------------------

interface DeliverWatchWebhookArgs {
	db: D1Database;
	watchId: string;
	auditId: string;
	target: string;
	ownerId: string | null;
	current: CheckResult;
	now: number;
	deliverWebhook: (url: string, payload: unknown) => Promise<boolean>;
}

interface WatchSlim {
	id: string;
	owner_id: string;
	domain: string;
	interval: 'daily' | 'weekly' | 'monthly';
	webhook_url: string | null;
	last_classification_hash: string | null;
}

/**
 * Compute the new classification hash, compare to the watch row's previous
 * value, and (if shifted) POST a diff webhook + persist the new hash.
 *
 * Fail-soft throughout: any D1 read/write failure or non-2xx webhook response
 * is swallowed by the caller's `try {} catch {}`. Customers can re-derive the
 * current state by calling `brand_audit_get_report` directly — webhook is
 * convenience, not the durability boundary.
 */
async function deliverWatchWebhookIfShifted(args: DeliverWatchWebhookArgs): Promise<void> {
	const watch = (await args.db
		.prepare(
			'SELECT id, owner_id, domain, interval, webhook_url, last_classification_hash FROM brand_audit_watches WHERE id = ? LIMIT 1',
		)
		.bind(args.watchId)
		.first()) as WatchSlim | null;
	if (!watch) return;

	// Defense in depth: confirm the message's ownerId matches the watch row's
	// owner. If they diverge, drop — something is wrong upstream.
	if (args.ownerId !== null && watch.owner_id !== args.ownerId) return;

	const { computeClassificationHash, computeDiff } = await import('../lib/brand-audit-classification-diff');
	const currentHash = await computeClassificationHash(args.current);

	// No drift → just persist the (possibly-first) hash so future ticks have a baseline.
	if (watch.last_classification_hash === currentHash) {
		return;
	}

	// Stamp the new hash immediately — even if the webhook fails downstream,
	// we don't want to re-fire on every redelivery of the same completed message.
	await args.db
		.prepare('UPDATE brand_audit_watches SET last_classification_hash = ? WHERE id = ?')
		.bind(currentHash, args.watchId)
		.run();

	if (!watch.webhook_url) {
		// Logging-only watch — drift detected but no delivery target.
		return;
	}

	// Fetch the previous CheckResult if we had a prior hash, so we can compute
	// the actual diff (added/removed/modified). On first-ever delivery
	// (previous_hash null), we can't compute a meaningful diff — send the
	// current state as a one-shot "initial classification" event.
	let previousResult: CheckResult | null = null;
	if (watch.last_classification_hash !== null) {
		// Look up the prior audit_id for this watch — the most recent completed
		// brand_audits row whose owner+target match. Cap the search by created_at
		// to avoid scanning the whole table.
		const prior = (await args.db
			.prepare(
				"SELECT result_json FROM brand_audit_targets WHERE target = ? AND audit_id IN (SELECT id FROM brand_audits WHERE owner_id = ? AND id != ? AND status = 'completed' ORDER BY created_at DESC LIMIT 1) LIMIT 1",
			)
			.bind(args.target, watch.owner_id, args.auditId)
			.first()) as { result_json: string | null } | null;
		if (prior?.result_json) {
			try {
				previousResult = JSON.parse(prior.result_json) as CheckResult;
			} catch {
				previousResult = null;
			}
		}
	}

	// First-ever delivery: previousResult is null. We diff against an empty
	// baseline so `added` is populated with the full current candidate set —
	// otherwise customers receive a useless empty payload on watch registration
	// and have to call brand_audit_get_report to recover the actual state.
	const emptyBaseline: CheckResult = {
		category: 'brand_discovery',
		passed: true,
		score: 100,
		findings: [] as Finding[],
	};
	const diff = computeDiff(previousResult ?? emptyBaseline, args.current);

	const payload = {
		schemaVersion: 1 as const,
		watchId: args.watchId,
		auditId: args.auditId,
		target: args.target,
		interval: watch.interval,
		detectedAt: args.now,
		previousHash: watch.last_classification_hash,
		currentHash,
		changes: diff,
	};

	await args.deliverWebhook(watch.webhook_url, payload);
}

/**
 * Default webhook deliverer — uses safeFetch (SSRF-validated). Returns true
 * on 2xx, false on any non-2xx or thrown error. Never throws — caller relies
 * on the boolean.
 */
async function defaultDeliverWebhook(url: string, payload: unknown): Promise<boolean> {
	try {
		const { safeFetch } = await import('../lib/safe-fetch');
		const res = await safeFetch(url, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(payload),
			redirect: 'manual',
		});
		return res.ok;
	} catch {
		return false;
	}
}
