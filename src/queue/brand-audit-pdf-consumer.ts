// SPDX-License-Identifier: BUSL-1.1

/**
 * Cloudflare Queue consumer for the brand-audit PDF render path.
 *
 * Decoupled from the primary brand-audit-queue so that:
 *   - `audit.status='completed'` doesn't block on PDF rendering (a slow
 *     bv-browser-renderer call won't delay the JSON result a customer is
 *     polling for)
 *   - Browser Rendering's single-request constraint maps cleanly to
 *     `max_batch_size: 1` on the consumer config
 *
 * Each message: `{ auditId, target, format }` (produced by
 * `brand-audit-consumer` on per-target completion). The consumer:
 *
 *   1. Read `brand_audit_targets.result_json` + `pdf_r2_key` from D1.
 *   2. Idempotency: if `pdf_r2_key` is already set, ack and return —
 *      duplicate delivery shouldn't re-render or re-write R2.
 *   3. Skip-and-ack if `result_json` is null (upstream failure or race;
 *      no useful retry).
 *   4. Render PDF via `renderBrandAuditPdf` → `BV_BROWSER_RENDERER`.
 *   5. Write to R2 at `audits/{auditId}/{target}.pdf`.
 *   6. UPDATE `brand_audit_targets.pdf_r2_key` so `brand_audit_get_report`
 *      can mint signed URLs.
 *
 * Transient renderer / R2 failures → `retry`. Cloudflare redelivers up to
 * `max_retries`; idempotency check at step 2 short-circuits re-runs.
 */

import { z } from 'zod';
import type { CheckResult } from '../lib/scoring';
import { renderBrandAuditPdf as defaultRenderBrandAuditPdf } from '../lib/brand-audit-pdf-render';

export const BrandAuditPdfMessageSchema = z.object({
	auditId: z.string().min(1).max(64),
	target: z.string().min(1).max(253),
	format: z.enum(['json', 'markdown', 'both']),
});

export type BrandAuditPdfMessage = z.infer<typeof BrandAuditPdfMessageSchema>;

interface TargetRowSlim {
	result_json: string | null;
	pdf_r2_key: string | null;
}

export interface BrandAuditPdfConsumerDeps {
	db: D1Database;
	bucket: R2Bucket;
	serverVersion: string;
	now?: () => number;
	/**
	 * Injectable renderer fn for tests; defaults to the in-process pdf-lib
	 * renderer (`src/lib/brand-audit-pdf-render.ts`). No browser, no external
	 * service binding, no auth — pure code path. Replaces the prior
	 * bv-browser-renderer service binding that hit cascading timeout issues
	 * during 2026-05-19 brand-audit incident.
	 */
	renderPdf?: (
		result: CheckResult,
		target: string,
		opts: { serverVersion: string; now?: () => number },
	) => Promise<Uint8Array>;
}

export async function processBrandAuditPdfMessage(
	rawBody: unknown,
	deps: BrandAuditPdfConsumerDeps,
): Promise<'ack' | 'retry'> {
	const parsed = BrandAuditPdfMessageSchema.safeParse(rawBody);
	if (!parsed.success) {
		// Malformed payload — never recoverable by retry.
		return 'ack';
	}
	const message = parsed.data;

	let target: TargetRowSlim | null;
	try {
		target = (await deps.db
			.prepare(
				'SELECT result_json, pdf_r2_key FROM brand_audit_targets WHERE audit_id = ? AND target = ? LIMIT 1',
			)
			.bind(message.auditId, message.target)
			.first()) as TargetRowSlim | null;
	} catch {
		return 'retry';
	}

	if (!target) {
		// Row missing — upstream race or already cleaned up. No point retrying.
		return 'ack';
	}

	if (target.pdf_r2_key) {
		// Idempotency: PDF already rendered + persisted. Duplicate delivery.
		return 'ack';
	}

	if (!target.result_json) {
		// Upstream failed or hasn't flushed result_json yet. Dropping
		// (rather than retrying) — primary consumer either failed and
		// won't recover, or a redelivery will pick up the (eventually)
		// populated row from the queue's own retry stream.
		return 'ack';
	}

	let parsedResult: CheckResult;
	try {
		parsedResult = JSON.parse(target.result_json) as CheckResult;
	} catch {
		return 'ack';
	}

	const render = deps.renderPdf ?? defaultRenderBrandAuditPdf;
	let pdfBytes: Uint8Array;
	try {
		pdfBytes = await render(parsedResult, message.target, {
			serverVersion: deps.serverVersion,
			now: deps.now,
		});
	} catch {
		return 'retry';
	}

	const r2Key = `audits/${message.auditId}/${message.target}.pdf`;
	try {
		await deps.bucket.put(r2Key, pdfBytes);
	} catch {
		return 'retry';
	}

	try {
		const now = (deps.now ?? Date.now)();
		await deps.db
			.prepare('UPDATE brand_audit_targets SET pdf_r2_key = ?, completed_at = ? WHERE audit_id = ? AND target = ?')
			.bind(r2Key, now, message.auditId, message.target)
			.run();
	} catch {
		// PDF is in R2 already; failure to flag pdf_r2_key means a future
		// get-report can't surface it. Retry — idempotency check up top
		// keeps a redelivered render a no-op.
		return 'retry';
	}

	return 'ack';
}

export async function handleBrandAuditPdfQueue(
	batch: MessageBatch<unknown>,
	deps: BrandAuditPdfConsumerDeps,
): Promise<void> {
	for (const message of batch.messages) {
		const verdict = await processBrandAuditPdfMessage(message.body, deps);
		if (verdict === 'retry') {
			message.retry();
		} else {
			message.ack();
		}
	}
}
