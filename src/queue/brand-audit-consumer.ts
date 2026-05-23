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
import { brandAuditSingle as defaultBrandAuditSingle, type BrandAuditSingleOptions } from '../tools/brand-audit-single';
import type { BrandAuditSingleDeps } from '../tools/brand-audit-single';
import type { CheckResult, Finding } from '../lib/scoring';
import { BrandAuditStepStoreError, createD1BrandAuditStepStore } from '../lib/brand-audit-step-store';
import { decideRetryEnqueue } from '../lib/registrar-retry';
import type { Tier0Result } from '../lib/brand-tier0-enterprise';
import type { Tier1Result } from '../lib/brand-tier1-graph';
import type { Tier2Result } from '../lib/brand-tier2-evidence';

/**
 * Per-message budget for the orchestrator. The AbortController-driven catch
 * path commits a `failed` row only when the inner orchestrator is well-behaved
 * — the abort `setTimeout` macrotask competes with whatever microtasks the
 * orchestrator generates, and for fan-out-heavy brands (tier-1 portfolios)
 * the microtask queue stays saturated long enough that the worker is
 * killed before any catch UPDATE can flush. Those rows are recovered by the
 * cron reaper (`reapStuckBrandAudits`) ~15 min later — see the 2026-05-19
 * tier-1 investigation for the trace evidence. Until AbortSignal is plumbed
 * through `dns-transport`/`safe-fetch` (so in-flight fetches actually cancel),
 * the reaper is the durability boundary for oversized audits.
 *
 * 300s matches the report-generation runner's per-target poll contract and
 * gives large tier-1 brands enough room for registrar fallback enrichment.
 * Oversized audits still return a controlled failure before the 15-min reaper.
 */
export const BRAND_AUDIT_MESSAGE_TIMEOUT_MS = 300_000;

/** Wire format for a brand-audit queue message. Validated on the consumer side as defense in depth. */
export const BrandAuditQueueMessageSchema = z.object({
	auditId: z.string().min(1).max(64),
	target: z.string().min(1).max(253),
	format: z.enum(['json', 'markdown', 'both']),
	min_confidence: z.number().min(0).max(1).optional(),
	depth: z.enum(['standard', 'deep']).optional(),
	planner_mode: z.enum(['off', 'observe', 'enforce']).optional(),
	brand_aliases: z.array(z.string().min(2).max(64)).max(20).optional(),
	candidate_domains: z.array(z.string().min(1).max(253)).max(250).optional(),
	/**
	 * Per-target discovery mode forwarded by brand_audit_batch_start. Explicit
	 * caller-supplied value wins over deps.discoveryModeDefault in the
	 * pipeline's effective-mode resolution.
	 */
	discovery_mode: z.enum(['classic', 'tiered']).optional(),
	/**
	 * Output view mode forwarded by brand_audit_batch_start. Explicit
	 * caller-supplied value is threaded into runBrandAuditPipeline.
	 */
	view: z.enum(['standard', 'csc_complement']).optional(),
	/** Set when the message originated from the watch cron — drives post-completion diff/webhook. */
	watchId: z.string().min(1).max(64).optional(),
	/** Bound at enqueue time so the consumer doesn't need a D1 round-trip to look up the watch's owner. */
	ownerId: z.string().min(1).max(128).optional(),
	/**
	 * Set when the message is a Phase 2b retry pass — capped at 1 to bound the
	 * fan-out. retry_attempt=0 (or absent) is the initial enqueue; retry_attempt=1
	 * is the single retry pass after a transient registrar lookup failure.
	 * Consumer skips counter-tick + webhook on retry messages and force-refreshes
	 * the pipeline cache.
	 */
	retry_attempt: z.number().int().min(0).max(1).optional(),
});

export type BrandAuditQueueMessage = z.infer<typeof BrandAuditQueueMessageSchema>;

export interface BrandAuditConsumerDeps {
	db: D1Database;
	/** Injectable for tests. Production default accepts a third `deps` arg (tier closures + service bindings); tests typically omit it. */
	brandAuditSingle?: (target: string, options: BrandAuditSingleOptions, deps?: BrandAuditSingleDeps) => Promise<CheckResult>;
	/** Clock override for tests. */
	now?: () => number;
	/**
	 * Optional fanout to the PDF render queue. When present AND the message
	 * requested a PDF (`format ∈ {markdown, both}`), the consumer enqueues a
	 * follow-up `{ auditId, target, format }` after persisting the result.
	 * Absent in dev / unprovisioned environments — primary completion still
	 * succeeds; PDF rendering just doesn't happen.
	 */
	pdfQueue?: {
		send(
			message: { auditId: string; target: string; format: 'json' | 'markdown' | 'both' },
			options?: { contentType?: 'json' },
		): Promise<void>;
	};
	/**
	 * Optional binding for the brand-audit queue itself, used by Phase 2b to
	 * enqueue a single retry pass when a completed audit has transient
	 * registrar-lookup failures. When unset, retry detection still runs but
	 * the enqueue is a no-op (forward-compatible: the queue plumbing can land
	 * in a later deploy without breaking the consumer).
	 */
	brandAuditQueue?: { send(message: BrandAuditQueueMessage, options?: { contentType?: 'json' }): Promise<void> };
	/**
	 * Optional webhook delivery function. When set + the message carries a
	 * watchId + the new classification differs from the watch's previous
	 * `last_classification_hash`, the consumer POSTs the diff payload here.
	 * Returns true on 2xx delivery, false on failure (never throws).
	 * Defaults to a `safeFetch`-wrapped POST in production.
	 */
	deliverWebhook?: (url: string, payload: unknown) => Promise<boolean>;
	/**
	 * T13 — runtime-default for `discover_brand_domains` discovery_mode.
	 * Sourced from `env.BRAND_AUDIT_DISCOVERY_MODE_DEFAULT` at the queue
	 * dispatch site in `src/index.ts`. Threaded into the pipeline's
	 * `options.env`. `'tiered'` flips the default for queue-message audits
	 * that omit `discovery_mode` (which is all of them, since the queue
	 * message schema doesn't carry it); any other value (including
	 * undefined) leaves the public schema default (`'classic'`) in charge.
	 */
	discoveryModeDefault?: string;
	/**
	 * Tier 0/1/2 lookup closures wrapping the private brand-discovery service
	 * bindings. Constructed at the queue dispatch site in `src/index.ts` when
	 * the bindings (+ `BV_WEB_INTERNAL_KEY` for Tier 0/1) are provisioned.
	 * Undefined on BSL self-hosts — queued audits then run classic-equivalent.
	 *
	 * Required for the queue path because the request-path closures
	 * constructed in `executeMcpRequest` never reach queue consumers (different
	 * Worker invocation, different env access pattern).
	 */
	tier0Lookup?: (domain: string) => Promise<Tier0Result>;
	tier1Lookup?: (domain: string) => Promise<Tier1Result>;
	tier2Lookup?: (domain: string) => Promise<Tier2Result>;
	/** Optional service binding for registrar WHOIS fallback in queued audits. */
	whoisBinding?: { fetch: typeof fetch };
	/**
	 * Optional bv-certstream-worker service binding. Threaded into the
	 * SAN-signal path of `discoverBrandDomains` (via the pipeline) so queued
	 * audits use the dedicated CT-log binding instead of the public crt.sh
	 * fallback. The sync MCP path threads `ro.certstream` here; without this
	 * the queue path silently degraded to crt.sh for every batched audit.
	 */
	certstream?: { fetch: typeof fetch };
	/**
	 * Optional internal-call closure for the CSC deep-scan queue job.
	 * Wraps handleToolsCall so the deep-scan orchestrator can invoke scan_domain
	 * and discover_subdomains without going through HTTP framing. Constructed at
	 * the queue dispatch site in src/index.ts; undefined on BSL self-hosts where
	 * SCAN_CACHE or other required bindings are absent.
	 */
	internalCall?: (tool: string, args: { domain: string }) => Promise<unknown>;
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
export async function processBrandAuditMessage(rawBody: unknown, deps: BrandAuditConsumerDeps): Promise<'ack' | 'retry'> {
	const parsed = BrandAuditQueueMessageSchema.safeParse(rawBody);
	if (!parsed.success) {
		// Malformed payload — never recoverable by retry. Drop.
		return 'ack';
	}
	const message = parsed.data;
	// `clock` is the function (re-readable). `messageStartedAt` is a single
	// snapshot used only for the running-flip + audit-status running UPDATE.
	// All completed_at writes MUST re-read the clock at the actual time of
	// the write — otherwise an audit that takes 60s completes with a
	// completed_at recorded as 60s before the actual finish.
	// Surfaced by Linus-style review 2026-05-19; see audit cc177a62.
	const clock = deps.now ?? Date.now;
	const messageStartedAt = clock();
	const single = deps.brandAuditSingle ?? defaultBrandAuditSingle;
	const stepStore = createD1BrandAuditStepStore(deps.db, clock);
	const isRetry = (message.retry_attempt ?? 0) > 0;

	// 1. Idempotency check.
	let existing: TargetStatusRow | null;
	try {
		existing = (await deps.db
			.prepare('SELECT status, completed_at FROM brand_audit_targets WHERE audit_id = ? AND target = ? LIMIT 1')
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

	if (existing.status === 'failed') {
		// Terminal failure — ack without re-running, even on retry messages.
		return 'ack';
	}

	if (existing.status === 'completed' && !isRetry) {
		// Duplicate delivery of a completed (non-retry) row. Ack without re-running.
		return 'ack';
	}

	// 2. Atomic claim — flip queued → running. The conditional UPDATE is the
	// single point of mutual exclusion: only the consumer whose UPDATE matches
	// 1 row may proceed to run brandAuditSingle. Cloudflare Queues redelivers
	// every ~30s while our audit budget is 300s, so without this guard 4–10
	// concurrent consumers all enter the orchestrator on the same target,
	// contend for D1 / DNS / RDAP, and produce thrashing instead of progress.
	let claimed = false;
	try {
		// Phase 2b: retry messages claim from `completed` (since the original pass
		// already flipped the row); originals still claim from `queued`. The
		// conditional UPDATE is the per-message mutual exclusion — concurrent
		// duplicate deliveries of a retry both attempt to flip completed→running;
		// only the first one to commit wins. fromStatus is parameterized to match
		// the rest of the file's binding pattern.
		const fromStatus = isRetry ? 'completed' : 'queued';
		const claim = await deps.db
			.prepare("UPDATE brand_audit_targets SET status = 'running' WHERE audit_id = ? AND target = ? AND status = ?")
			.bind(message.auditId, message.target, fromStatus)
			.run();
		claimed = (claim.meta?.changes ?? 0) > 0;
		// Parent audit flip is best-effort; safe to no-op when already running.
		await deps.db
			.prepare("UPDATE brand_audits SET status = 'running', updated_at = ? WHERE id = ? AND status = 'queued'")
			.bind(messageStartedAt, message.auditId)
			.run();
	} catch {
		return 'retry';
	}

	if (!claimed) {
		// Another consumer already owns this target row. Ack without re-running
		// to avoid the parallel-execution stampede that wedges the audit.
		return 'ack';
	}

	// 3. Run the orchestrator under an AbortController-driven budget.
	//
	// Two layers of cancellation, chosen for what each CAN guarantee:
	//
	//   a. AbortSignal plumbed into runBrandAuditPipeline / discoverBrandDomains
	//      / registrar enrichment — each phase polls `signal.aborted` and throws
	//      at its next phase boundary. Best-effort: inner DNS/RDAP fetches don't
	//      yet accept a signal, so a probe stuck in flight won't unwind via this
	//      path. (Plumbing AbortSignal into dns-transport / safe-fetch is the
	//      next slice of work.)
	//   b. Promise.race against an abort-event rejecter — guarantees the
	//      consumer's await resolves at the deadline IF the macrotask queue
	//      can fire. For CPU-saturated audits (tier-1 brands), microtasks from
	//      pending fetch responses can starve the abort timer; in that case
	//      the consumer never reaches the catch path and the cron reaper
	//      (`reapStuckBrandAudits`) cleans the row up at the 15-min threshold.
	//
	// `deadlineMs` lets the inner per-candidate RDAP loop poll its own deadline
	// since it can't observe the AbortSignal across each await.
	const controller = new AbortController();
	const timeoutId = setTimeout(() => {
		controller.abort(new Error(`brand_audit_single budget exceeded after ${BRAND_AUDIT_MESSAGE_TIMEOUT_MS}ms`));
	}, BRAND_AUDIT_MESSAGE_TIMEOUT_MS);
	let result: CheckResult | null = null;
	let runtimeError: string | null = null;
	// Pipeline deps: built once, passed as the 3rd `deps` arg ONLY when at
	// least one binding-backed field is present (any tier closure, whoisBinding,
	// or certstream — see hasSingleDeps below). Skipping the arg keeps the
	// existing 2-arg `toHaveBeenCalledWith(...)` test assertions valid for the
	// many tests that mock no bindings — vitest matches arg count exactly. The
	// 3-arg path activates when ANY single binding is provided, including on a
	// BSL self-host with only BV_CERTSTREAM provisioned. Any new binding-backed
	// pipeline dep must be added to BOTH the singleDeps spread AND the
	// hasSingleDeps gate — they must enumerate the same set.
	const singleDeps: BrandAuditSingleDeps = {
		...(deps.tier0Lookup ? { tier0Lookup: deps.tier0Lookup } : {}),
		...(deps.tier1Lookup ? { tier1Lookup: deps.tier1Lookup } : {}),
		...(deps.tier2Lookup ? { tier2Lookup: deps.tier2Lookup } : {}),
		...(deps.whoisBinding ? { whoisBinding: deps.whoisBinding } : {}),
		...(deps.certstream ? { certstream: deps.certstream } : {}),
	};
	const hasSingleDeps = deps.tier0Lookup || deps.tier1Lookup || deps.tier2Lookup || deps.whoisBinding || deps.certstream;
	const singleOptions: BrandAuditSingleOptions = {
		auditId: message.auditId,
		stepStore,
		format: message.format,
		min_confidence: message.min_confidence,
		depth: message.depth,
		planner_mode: message.planner_mode,
		brand_aliases: message.brand_aliases,
		candidate_domains: message.candidate_domains,
		// Explicit per-target discovery mode from the batch_start payload
		// (the caller's `discovery_mode` arg). Wins over discoveryModeDefault
		// in the pipeline's effective-mode resolution.
		discovery_mode: message.discovery_mode,
		// Output view mode from the batch_start payload. Forwarded into the
		// pipeline so CSC enrichment runs when the caller requested csc_complement.
		view: message.view,
		signal: controller.signal,
		deadlineMs: messageStartedAt + BRAND_AUDIT_MESSAGE_TIMEOUT_MS,
		// Phase 2b: retry messages re-run the pipeline from scratch instead
		// of reading back the cached lookup_failed result from pass 1.
		force_refresh: isRetry,
		// T13 — propagate the BlackVeil-production runtime override.
		// Pipeline only honours it when the caller omits `discovery_mode`;
		// undefined on BSL self-hosts (schema default `'classic'` wins).
		...(deps.discoveryModeDefault ? { env: { BRAND_AUDIT_DISCOVERY_MODE_DEFAULT: deps.discoveryModeDefault } } : {}),
	};
	try {
		result = await Promise.race([
			hasSingleDeps ? single(message.target, singleOptions, singleDeps) : single(message.target, singleOptions),
			new Promise<never>((_, reject) => {
				const onAbort = () => {
					const reason = (controller.signal as AbortSignal & { reason?: unknown }).reason;
					reject(reason instanceof Error ? reason : new Error(typeof reason === 'string' ? reason : 'brand_audit_single budget exceeded'));
				};
				if (controller.signal.aborted) {
					onAbort();
				} else {
					controller.signal.addEventListener('abort', onAbort, { once: true });
				}
			}),
		]);
	} catch (err) {
		if (err instanceof BrandAuditStepStoreError) {
			clearTimeout(timeoutId);
			return 'retry';
		}
		runtimeError = err instanceof Error ? err.message : String(err);
	} finally {
		clearTimeout(timeoutId);
	}

	// 4. Status flip → 'completed' | 'failed'. Treat D1 write failure here as
	// retryable (Cloudflare redelivers; idempotency check up top short-circuits).
	let finalStatus: 'completed' | 'failed' = runtimeError ? 'failed' : 'completed';
	let resultJson: string | null = null;
	let errorString = runtimeError ? sanitizeErrorString(runtimeError) : null;
	if (finalStatus === 'completed' && result) {
		try {
			resultJson = JSON.stringify(result);
		} catch (err) {
			const message = err instanceof Error ? err.message : String(err);
			finalStatus = 'failed';
			errorString = sanitizeErrorString(`brand_audit_result_serialization_failed: ${message}`);
		}
	}

	try {
		if (isRetry && runtimeError) {
			// Phase 2b: a retry pass that throws MUST NOT destroy the original
			// pass's result_json. The first pass already produced a usable result;
			// the retry was only meant to enrich the lookup_failed rows. So we
			// preserve result_json, record the retry failure in `error`, AND flip
			// status back to 'completed' (the atomic claim earlier flipped it
			// completed→running; without restoring it the row sits stuck in
			// 'running' until the cron reaper sweeps at 15min). Surfaced by audit
			// synthetic-audit-brandepsilon.com on 2026-05-19.
			await deps.db
				.prepare("UPDATE brand_audit_targets SET status = 'completed', error = ?, completed_at = ? WHERE audit_id = ? AND target = ?")
				.bind(errorString, clock(), message.auditId, message.target)
				.run();
		} else {
			await deps.db
				.prepare(
					'UPDATE brand_audit_targets SET status = ?, result_json = ?, error = ?, completed_at = ? WHERE audit_id = ? AND target = ?',
				)
				.bind(finalStatus, resultJson, errorString, clock(), message.auditId, message.target)
				.run();
		}
	} catch {
		return 'retry';
	}

	// 4a. Phase 2b: retry enqueue decision. When the original pass produced
	// retryable candidates AND a retry hasn't already been scheduled AND we
	// have the brand-audit queue binding, schedule a single retry pass. The
	// `retry_scheduled` step-store row is the idempotency token — duplicate
	// delivery of the primary message produces only one retry enqueue.
	let retryEnqueued = false;
	if (finalStatus === 'completed' && result !== null && !isRetry && deps.brandAuditQueue) {
		const retryPayload = decideRetryEnqueue(result, message);
		if (retryPayload) {
			try {
				const existingRetry = await stepStore.get(message.auditId, message.target, 'retry_scheduled');
				if (!existingRetry) {
					await stepStore.put({
						auditId: message.auditId,
						target: message.target,
						step: 'retry_scheduled',
						status: 'completed',
						payload: { retry_attempt: 1, scheduledAt: clock() },
					});
					await deps.brandAuditQueue.send(retryPayload, { contentType: 'json' });
					retryEnqueued = true;
				}
			} catch {
				// Best-effort: an enqueue failure leaves the audit terminal at
				// the (possibly partial) original result. No retry, no webhook
				// suppression — fall through to deliver the webhook with what we have.
			}
		}
	}

	// 4b. Fanout: enqueue PDF render when one was requested AND the target
	// completed (don't bother on `failed`). Best-effort — if the PDF queue
	// binding is unavailable or send throws, we swallow and proceed; the
	// primary completion is the durability boundary, not PDF render.
	// Phase 2b: gate on `!retryEnqueued` so the partial first pass doesn't fire
	// a stale PDF that the terminal retry pass would immediately supersede.
	// Same policy as the watch-webhook gate in 4c.
	if (finalStatus === 'completed' && !retryEnqueued && deps.pdfQueue && (message.format === 'markdown' || message.format === 'both')) {
		try {
			await deps.pdfQueue.send({ auditId: message.auditId, target: message.target, format: message.format }, { contentType: 'json' });
		} catch {
			// swallow — PDF rendering is enrichment, not part of the
			// audit's durability contract
		}
	}

	// 4c. Watch webhook delivery (v2.21.1+). When this message originated from
	// the cron watch handler (carries watchId), compute the classification hash
	// vs the watch's `last_classification_hash` and POST a diff webhook if
	// shifted. Best-effort — webhook failure does NOT mark the audit failed;
	// just logged-and-skipped so customers can re-derive from get-report.
	//
	// Phase 2b webhook policy: fire on terminal result only. A retry-pending
	// result is suppressed because the about-to-arrive retry message will fire
	// the webhook with the corrected classification.
	if (finalStatus === 'completed' && result !== null && message.watchId && !retryEnqueued) {
		try {
			await deliverWatchWebhookIfShifted({
				db: deps.db,
				watchId: message.watchId,
				auditId: message.auditId,
				target: message.target,
				ownerId: message.ownerId ?? null,
				current: result,
				now: clock(),
				deliverWebhook: deps.deliverWebhook ?? defaultDeliverWebhook,
			});
		} catch {
			// Same fail-soft posture as PDF fanout.
		}
	}

	// 5. Counter tick — bump completed_targets and check finalization.
	// Phase 2b: retry messages skip the counter tick. The original pass already
	// incremented; bumping again would advance past total_targets and break the
	// audit-finalized check.
	if (isRetry) {
		return 'ack';
	}
	try {
		const tickAt = clock();
		await deps.db
			.prepare('UPDATE brand_audits SET completed_targets = completed_targets + 1, updated_at = ? WHERE id = ?')
			.bind(tickAt, message.auditId)
			.run();

		const counter = (await deps.db
			.prepare('SELECT completed_targets, total_targets FROM brand_audits WHERE id = ? LIMIT 1')
			.bind(message.auditId)
			.first()) as AuditCounterRow | null;

		if (counter && counter.completed_targets >= counter.total_targets) {
			const finalizedAt = clock();
			await deps.db
				.prepare("UPDATE brand_audits SET status = 'completed', completed_at = ?, updated_at = ? WHERE id = ?")
				.bind(finalizedAt, finalizedAt, message.auditId)
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
export async function handleBrandAuditQueue(batch: MessageBatch<unknown>, deps: BrandAuditConsumerDeps): Promise<void> {
	for (const message of batch.messages) {
		// Phase detection before Zod parse: deep_scan messages don't carry `format`
		// and would be silently acked as "malformed" by BrandAuditQueueMessageSchema.
		const rawBody = message.body as Record<string, unknown>;
		if (typeof rawBody === 'object' && rawBody !== null && rawBody.phase === 'deep_scan') {
			const { auditId, target } = rawBody as { auditId: string; target: string; phase: string };
			if (typeof auditId === 'string' && typeof target === 'string' && deps.internalCall) {
				try {
					const { runDeepScanFromStepStore } = await import('../lib/brand-audit-csc-deepscan-job');
					const stepStore = createD1BrandAuditStepStore(deps.db);
					await runDeepScanFromStepStore({ auditId, target, stepStore, internalCall: deps.internalCall });
				} catch (err) {
					// Deep-scan failures are not retryable: the step-store is the durability boundary.
					// The fast-stage payload is already persisted; brand_audit_get_report falls back to
					// csc_complement_fast when csc_complement_full is absent. Ack and let the cron reaper
					// re-enqueue if needed.
					console.warn('[csc-complement] deep_scan job failed:', err);
				}
			}
			// Ack unconditionally: malformed payload, missing internalCall, or deep-scan failure are not retryable.
			message.ack();
			continue;
		}

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
		.prepare('SELECT id, owner_id, domain, interval, webhook_url, last_classification_hash FROM brand_audit_watches WHERE id = ? LIMIT 1')
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
	await args.db.prepare('UPDATE brand_audit_watches SET last_classification_hash = ? WHERE id = ?').bind(currentHash, args.watchId).run();

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
