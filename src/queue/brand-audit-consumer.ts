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
import { logError } from '../lib/log';
import { disposeUnreadResponseBody } from '../lib/response-body';

import { z } from 'zod';
import { brandAuditSingle as defaultBrandAuditSingle, type BrandAuditSingleOptions } from '../tools/brand-audit-single';
import type { BrandAuditSingleDeps } from '../tools/brand-audit-single';
import {
	discoverBrandDomains as defaultDiscoverBrandDomains,
	type DiscoverBrandDomainsOptions,
	type DiscoverBrandDomainsDeps,
	type DiscoverSignal,
} from '../tools/discover-brand-domains';
import type { CheckResult, Finding } from '../lib/scoring';
import { BrandAuditStepStoreError, createD1BrandAuditStepStore } from '../lib/brand-audit-step-store';
import { decideRetryEnqueue } from '../lib/registrar-retry';
import type { Tier0Result } from '../lib/brand-tier0-enterprise';
import type { Tier1Result } from '../lib/brand-tier1-graph';
import type { Tier2Result } from '../lib/brand-tier2-evidence';
import { computeClassificationHash, computeDiff } from '../lib/brand-audit-classification-diff';
import {
	MCP_SECURITY_CRITICAL_SECRET_KEYS,
	securityCapabilityCollision,
	type McpSecurityCriticalSecretKey,
} from '../lib/security-capabilities';
import {
	BRAND_AUDIT_WATCH_WEBHOOK_MAX_BODY_BYTES,
	BrandAuditWatchWebhookPayloadSchema,
	type BrandAuditWatchWebhookPayload,
} from '../schemas/brand-audit-watch-webhook';

/**
 * The Cloudflare Workers CPU cap for this consumer, mirrored from `wrangler.jsonc`
 * `limits.cpu_ms`. The platform KILLS the isolate at this bound — anything past it
 * (including the AbortController catch that writes the terminal `failed` row) never
 * runs. **Keep in lockstep with wrangler.jsonc `limits.cpu_ms`.**
 */
export const PLATFORM_CONSUMER_CPU_CAP_MS = 300_000;

/**
 * Headroom reserved BELOW the platform cap for the abort to unwind + the terminal
 * D1 write to flush.
 *
 * History (the deep-discovery terminal-state bug, Bug #1): the abort budget used to
 * EQUAL the platform cap (both 300s), leaving zero headroom. A fan-out-heavy `deep`
 * discovery run consumed the whole budget, so the isolate was killed at the cap
 * before the AbortController catch could flush its `failed` UPDATE — stranding the
 * target in `running` until the 7-min read-path/reaper force-failed it (surfacing as
 * "consumer cap did not flip status"). Standard runs (~27s) never approach the cap,
 * so they always flip terminal — which is why only deep hung. With the abort now
 * threaded into `dnsContext` (new probes short-circuit on abort, so in-flight work
 * drains within a DoH timeout), the ONLY remaining gap was this missing headroom:
 * the abort must fire strictly before the cap. Since CPU time ≤ wall time, an abort
 * at `cap - headroom` wall leaves ≥ `headroom` of CPU budget under the cap for the
 * terminal write. The reaper stays as the last-resort durability boundary, no longer
 * the normal path for oversized audits.
 */
export const BRAND_AUDIT_TERMINAL_WRITE_HEADROOM_MS = 30_000;

/**
 * Per-message budget for the orchestrator — DERIVED from the platform cap minus the
 * terminal-write headroom so it can never silently drift back up to the cap. Shared
 * by the full-audit (`processBrandAuditMessage`) and discovery (`processDiscoverOnlyMessage`)
 * paths; both get the same terminal-state guarantee. Threaded into the orchestrator
 * as both the abort `setTimeout` delay and `deadlineMs`, so deadline-aware phases
 * (e.g. recursive SAN) also skip earlier. Comfortably covers large tier-1 brands +
 * registrar fallback enrichment; oversized audits return a controlled `failed`
 * before the cap, not via the cron reaper.
 */
export const BRAND_AUDIT_MESSAGE_TIMEOUT_MS = PLATFORM_CONSUMER_CPU_CAP_MS - BRAND_AUDIT_TERMINAL_WRITE_HEADROOM_MS;

/** Customer webhooks run after the scan budget; bound them independently. */
export const BRAND_AUDIT_WEBHOOK_TIMEOUT_MS = 5_000;

/** The sole customer webhook destination allowed to receive BlackVeil's internal capability. */
export const BLACKVEIL_BRAND_DRIFT_RECEIVER = 'https://www.blackveilsecurity.com/api/webhooks/brand-drift';

/** Internal service-binding host; only the path/query are meaningful to the bound Worker. */
const BLACKVEIL_BRAND_DRIFT_SERVICE_URL = 'https://bv-web-internal/api/webhooks/brand-drift';

/** Cross-worker capabilities must carry at least 256 bits when generated randomly. */
const MIN_BRAND_WEBHOOK_CAPABILITY_BYTES = 32;

/**
 * Every secret held by this Worker that must remain distinct from the outbound
 * Brand Drift capability. Reusing any one would hand the receiver (or a leaked
 * callback credential) authority over an unrelated MCP/internal surface.
 */
export const BRAND_WEBHOOK_PEER_SECRET_KEYS = MCP_SECURITY_CRITICAL_SECRET_KEYS.filter(
	(key): key is Exclude<McpSecurityCriticalSecretKey, 'BV_MCP_BRAND_WEBHOOK_KEY'> => key !== 'BV_MCP_BRAND_WEBHOOK_KEY',
);

export function brandWebhookPeerSecretsFromEnv(
	env: Partial<Record<(typeof BRAND_WEBHOOK_PEER_SECRET_KEYS)[number], unknown>>,
): Array<string | undefined> {
	return BRAND_WEBHOOK_PEER_SECRET_KEYS.map((key) => (typeof env[key] === 'string' ? env[key] : undefined));
}

/**
 * Return the colliding MCP capability name without ever exposing either value.
 * This is intentionally separate from the sender's strength check so public
 * request auth can fail closed before any route evaluates an aliased key.
 */
export function brandWebhookCapabilityCollision(
	env: Partial<Record<McpSecurityCriticalSecretKey, unknown>>,
): McpSecurityCriticalSecretKey | null {
	return securityCapabilityCollision(env, 'BV_MCP_BRAND_WEBHOOK_KEY');
}

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

/**
 * Wire format for a `discover_only` queue message produced by
 * `discover_brand_domains_start`. Distinct from BrandAuditQueueMessageSchema:
 * it carries the discovery args (no `format`) and a `phase` discriminator.
 * Validated on the consumer side as defense in depth.
 */
export const DiscoverOnlyQueueMessageSchema = z.object({
	auditId: z.string().min(1).max(64),
	target: z.string().min(1).max(253),
	phase: z.literal('discover_only'),
	signals: z.array(z.string().min(1).max(64)).max(12).optional(),
	depth: z.enum(['standard', 'deep']).optional(),
	planner_mode: z.enum(['off', 'observe', 'enforce']).optional(),
	brand_aliases: z.array(z.string().min(2).max(64)).max(20).optional(),
	candidate_domains: z.array(z.string().min(1).max(253)).max(250).optional(),
	dkim_selectors: z.array(z.string().min(1).max(63)).max(50).optional(),
	min_confidence: z.number().min(0).max(1).optional(),
	discovery_mode: z.enum(['classic', 'tiered']).optional(),
	ownership_verified: z.boolean().optional(),
});

export type DiscoverOnlyQueueMessage = z.infer<typeof DiscoverOnlyQueueMessageSchema>;

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
	/** Existing private bv-web service binding used only for the exact BlackVeil receiver URL. */
	brandWebhookBinding?: { fetch: typeof fetch };
	/** Dedicated bv-mcp -> bv-web webhook capability; never forwarded to customer URLs. */
	brandWebhookAuthToken?: string;
	/** All other MCP-held secrets; the webhook capability must not alias any of them. */
	brandWebhookPeerAuthTokens?: ReadonlyArray<string | undefined>;
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
	 * Bearer token for the bv-certstream-worker `/sans` endpoint. Paired with
	 * `certstream`; threaded through the pipeline into `discoverBrandDomains` so
	 * queued audits authenticate the CT-log binding instead of 401ing and
	 * degrading to the rate-limited public crt.sh fallback.
	 */
	certstreamAuthToken?: string;
	/**
	 * Optional internal-call closure for the CSC deep-scan queue job.
	 * Wraps handleToolsCall so the deep-scan orchestrator can invoke scan_domain
	 * and discover_subdomains without going through HTTP framing. Constructed at
	 * the queue dispatch site in src/index.ts; undefined on BSL self-hosts where
	 * SCAN_CACHE or other required bindings are absent.
	 */
	internalCall?: (tool: string, args: { domain: string }) => Promise<unknown>;
	/**
	 * Injectable override for the discovery orchestrator used by the
	 * `discover_only` phase (powers `discover_brand_domains_start`). Production
	 * default is the real `discoverBrandDomains`; tests pass a mock. The consumer
	 * threads the same certstream + tier closures + AbortSignal as the sync MCP
	 * path so queued discovery uses the dedicated CT-log binding and tier
	 * lookups instead of degrading to crt.sh / classic.
	 */
	discoverBrandDomains?: (
		seedDomain: string,
		options: DiscoverBrandDomainsOptions,
		deps?: DiscoverBrandDomainsDeps,
	) => Promise<CheckResult>;
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
		...(deps.certstreamAuthToken ? { certstreamAuthToken: deps.certstreamAuthToken } : {}),
		// The same brandAuditQueue binding that powers the Phase 2b retry-enqueue
		// at line 416 doubles as the CSC fast→full deep-scan trigger inside the
		// pipeline (brand-audit-pipeline.ts:1061). The send() signature there is
		// `{ send(unknown): Promise<void> }`, wider (more permissive in input
		// type) than the consumer's typed-message variant — the runtime shape
		// is identical. Gated on `!isRetry` because the primary pass already
		// enqueued deep_scan #1; allowing the retry pass to enqueue deep_scan #2
		// produces a race on csc_complement_full (last-write-wins UPSERT in the
		// step-store, no MVCC). Consumer's own retry-enqueue path is already
		// gated on `!isRetry` at line 411, so the consumer doesn't need
		// brandAuditQueue on retry messages either.
		...(deps.brandAuditQueue && !isRetry ? { brandAuditQueue: deps.brandAuditQueue } : {}),
	};
	const hasSingleDeps =
		deps.tier0Lookup ||
		deps.tier1Lookup ||
		deps.tier2Lookup ||
		deps.whoisBinding ||
		deps.certstream ||
		deps.certstreamAuthToken ||
		deps.brandAuditQueue;
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
	// shifted. Webhook failure does NOT mark the audit failed; its exact payload
	// remains in the watch-row outbox for replay by the next scheduled run.
	//
	// Phase 2b webhook policy: fire on terminal result only. A retry-pending
	// result is suppressed because the about-to-arrive retry message will fire
	// the webhook with the corrected classification.
	if (finalStatus === 'completed' && result !== null && message.watchId && !retryEnqueued) {
		try {
			const deliverWebhook =
				deps.deliverWebhook ??
				((url: string, payload: unknown) =>
					defaultDeliverWebhook(url, payload, BRAND_AUDIT_WEBHOOK_TIMEOUT_MS, {
						blackVeilBinding: deps.brandWebhookBinding,
						authToken: deps.brandWebhookAuthToken,
						peerAuthTokens: deps.brandWebhookPeerAuthTokens,
					}));
			await deliverWatchWebhookIfShifted({
				db: deps.db,
				watchId: message.watchId,
				auditId: message.auditId,
				target: message.target,
				ownerId: message.ownerId ?? null,
				current: result,
				now: clock(),
				deliverWebhook,
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

export interface DefaultWebhookDeliveryOptions {
	/** Private service binding selected only for {@link BLACKVEIL_BRAND_DRIFT_RECEIVER}. */
	blackVeilBinding?: { fetch: typeof fetch };
	/** Dedicated bearer attached only to the exact trusted service-binding request. */
	authToken?: string;
	/** Other MCP-held secrets that the dedicated bearer must not reuse. */
	peerAuthTokens?: ReadonlyArray<string | undefined>;
}

function isBlackVeilBrandDriftReceiver(rawUrl: string): URL | null {
	try {
		const url = new URL(rawUrl);
		const expected = new URL(BLACKVEIL_BRAND_DRIFT_RECEIVER);
		if (url.origin !== expected.origin || url.pathname !== expected.pathname || url.username || url.password) {
			return null;
		}
		return url;
	} catch {
		return null;
	}
}

function strongBrandWebhookCapability(value: string | undefined, peers: ReadonlyArray<string | undefined>): value is string {
	return (
		typeof value === 'string' &&
		new TextEncoder().encode(value).byteLength >= MIN_BRAND_WEBHOOK_CAPABILITY_BYTES &&
		!peers.some((peer) => typeof peer === 'string' && peer.length > 0 && peer === value)
	);
}

/**
 * Process a single `discover_only` message: run discoverBrandDomains directly
 * and persist the CheckResult to brand_audit_targets.result_json, flipping the
 * target + (single-target) audit rows to completed. Mirrors the claim →
 * idempotency → run → write structure of processBrandAuditMessage, but skips
 * brandAuditSingle's report/registrar machinery — discovery is the whole job.
 *
 * Returns 'ack' | 'retry' (same contract as processBrandAuditMessage).
 */
export async function processDiscoverOnlyMessage(rawBody: unknown, deps: BrandAuditConsumerDeps): Promise<'ack' | 'retry'> {
	const parsed = DiscoverOnlyQueueMessageSchema.safeParse(rawBody);
	if (!parsed.success) {
		// Malformed payload — never recoverable. Drop.
		return 'ack';
	}
	const message = parsed.data;
	const clock = deps.now ?? Date.now;
	const messageStartedAt = clock();
	const discover = deps.discoverBrandDomains ?? defaultDiscoverBrandDomains;

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
		// Producer should have inserted the row. Don't loop the queue.
		return 'ack';
	}
	if (existing.status === 'completed' || existing.status === 'failed') {
		return 'ack';
	}

	// 2. Atomic claim — flip queued → running.
	let claimed = false;
	try {
		const claim = await deps.db
			.prepare("UPDATE brand_audit_targets SET status = 'running' WHERE audit_id = ? AND target = ? AND status = 'queued'")
			.bind(message.auditId, message.target)
			.run();
		claimed = (claim.meta?.changes ?? 0) > 0;
		await deps.db
			.prepare("UPDATE brand_audits SET status = 'running', updated_at = ? WHERE id = ? AND status = 'queued'")
			.bind(messageStartedAt, message.auditId)
			.run();
	} catch {
		return 'retry';
	}
	if (!claimed) {
		// Another consumer owns this target. Ack without re-running.
		return 'ack';
	}

	// 3. Run discoverBrandDomains under an AbortController-driven budget.
	const controller = new AbortController();
	const timeoutId = setTimeout(() => {
		controller.abort(new Error(`discover_brand_domains budget exceeded after ${BRAND_AUDIT_MESSAGE_TIMEOUT_MS}ms`));
	}, BRAND_AUDIT_MESSAGE_TIMEOUT_MS);

	const discoverDeps: DiscoverBrandDomainsDeps = {
		...(deps.tier0Lookup ? { tier0Lookup: deps.tier0Lookup } : {}),
		...(deps.tier1Lookup ? { tier1Lookup: deps.tier1Lookup } : {}),
		...(deps.tier2Lookup ? { tier2Lookup: deps.tier2Lookup } : {}),
	} as DiscoverBrandDomainsDeps;
	const hasDiscoverDeps = Boolean(deps.tier0Lookup || deps.tier1Lookup || deps.tier2Lookup);

	const discoverOptions: DiscoverBrandDomainsOptions = {
		signals: message.signals as DiscoverSignal[] | undefined,
		depth: message.depth,
		planner_mode: message.planner_mode,
		brand_aliases: message.brand_aliases,
		candidate_domains: message.candidate_domains,
		dkim_selectors: message.dkim_selectors,
		min_confidence: message.min_confidence,
		discovery_mode: message.discovery_mode,
		certstream: deps.certstream,
		certstreamAuthToken: deps.certstreamAuthToken,
		signal: controller.signal,
		deadlineMs: messageStartedAt + BRAND_AUDIT_MESSAGE_TIMEOUT_MS,
	};

	let result: CheckResult | null = null;
	let runtimeError: string | null = null;
	try {
		result = await Promise.race([
			hasDiscoverDeps ? discover(message.target, discoverOptions, discoverDeps) : discover(message.target, discoverOptions),
			new Promise<never>((_, reject) => {
				const onAbort = () => {
					const reason = (controller.signal as AbortSignal & { reason?: unknown }).reason;
					reject(
						reason instanceof Error ? reason : new Error(typeof reason === 'string' ? reason : 'discover_brand_domains budget exceeded'),
					);
				};
				if (controller.signal.aborted) onAbort();
				else controller.signal.addEventListener('abort', onAbort, { once: true });
			}),
		]);
	} catch (err) {
		runtimeError = err instanceof Error ? err.message : String(err);
	} finally {
		clearTimeout(timeoutId);
	}

	// 4. Persist result / error. Treat D1 write failure as retryable.
	let finalStatus: 'completed' | 'failed' = runtimeError ? 'failed' : 'completed';
	let resultJson: string | null = null;
	let errorString = runtimeError ? sanitizeErrorString(runtimeError) : null;
	if (finalStatus === 'completed' && result) {
		try {
			resultJson = JSON.stringify(result);
		} catch (err) {
			finalStatus = 'failed';
			errorString = sanitizeErrorString(
				`discover_brand_domains_result_serialization_failed: ${err instanceof Error ? err.message : String(err)}`,
			);
		}
	}
	try {
		await deps.db
			.prepare('UPDATE brand_audit_targets SET status = ?, result_json = ?, error = ?, completed_at = ? WHERE audit_id = ? AND target = ?')
			.bind(finalStatus, resultJson, errorString, clock(), message.auditId, message.target)
			.run();
	} catch {
		return 'retry';
	}

	// 5. Single-target finalization — bump completed_targets + flip audit terminal.
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
		// Counter-tick failure leaves the audit row stale but the target is
		// terminal. Ack to avoid re-running discovery.
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
					logError(err instanceof Error ? err : String(err), { category: 'brand_audit', result: 'deep_scan_failed' });
				}
			}
			// Ack unconditionally: malformed payload, missing internalCall, or deep-scan failure are not retryable.
			message.ack();
			continue;
		}

		// Phase detection: discover_only messages (from discover_brand_domains_start)
		// don't carry `format` and would be acked as "malformed" by the brand-audit
		// schema. Route them to the discovery-only processor.
		if (typeof rawBody === 'object' && rawBody !== null && rawBody.phase === 'discover_only') {
			const verdict = await processDiscoverOnlyMessage(message.body, deps);
			if (verdict === 'retry') {
				message.retry();
			} else {
				message.ack();
			}
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
	last_classification_result_json: string | null;
	pending_webhook_json: string | null;
}

const PersistedClassificationResultSchema = z.object({ findings: z.array(z.unknown()) }).passthrough();
const PendingWatchWebhookSchema = z
	.object({
		payload: BrandAuditWatchWebhookPayloadSchema,
		currentResult: PersistedClassificationResultSchema,
	})
	.strict();

interface PendingWatchWebhook {
	payload: BrandAuditWatchWebhookPayload;
	currentResult: CheckResult;
}

function parsePersistedClassificationResult(raw: string | null | undefined): CheckResult | null {
	if (!raw) return null;
	try {
		const parsed = PersistedClassificationResultSchema.safeParse(JSON.parse(raw));
		return parsed.success ? (parsed.data as unknown as CheckResult) : null;
	} catch {
		return null;
	}
}

async function parsePendingWatchWebhook(raw: string, watch: WatchSlim): Promise<PendingWatchWebhook | null> {
	try {
		const parsed = PendingWatchWebhookSchema.safeParse(JSON.parse(raw));
		if (!parsed.success) return null;
		const pending = parsed.data as unknown as PendingWatchWebhook;
		if (
			pending.payload.watchId !== watch.id ||
			pending.payload.target !== watch.domain ||
			pending.payload.interval !== watch.interval ||
			pending.payload.previousHash !== watch.last_classification_hash ||
			(await computeClassificationHash(pending.currentResult)) !== pending.payload.currentHash
		) {
			return null;
		}
		return pending;
	} catch {
		return null;
	}
}

async function findClassificationResultByHash(db: D1Database, watch: WatchSlim, auditId: string): Promise<CheckResult | null> {
	const stored = parsePersistedClassificationResult(watch.last_classification_result_json);
	if (stored && (await computeClassificationHash(stored)) === watch.last_classification_hash) {
		return stored;
	}

	// Transitional recovery for watches created before the durable baseline
	// column existed. Do not assume the newest audit is the delivered baseline:
	// failed notifications can leave newer completed audits ahead of the hash.
	const history = await db
		.prepare(
			"SELECT t.result_json FROM brand_audit_targets t JOIN brand_audits a ON a.id = t.audit_id WHERE t.target = ? AND a.owner_id = ? AND a.id != ? AND t.status = 'completed' AND t.result_json IS NOT NULL ORDER BY a.created_at DESC",
		)
		.bind(watch.domain, watch.owner_id, auditId)
		.all<{ result_json: string | null }>();
	for (const row of history.results) {
		const candidate = parsePersistedClassificationResult(row.result_json);
		if (candidate && (await computeClassificationHash(candidate)) === watch.last_classification_hash) {
			return candidate;
		}
	}
	return null;
}

/**
 * Compute the new classification hash, compare to the watch row's previous
 * value, and (if shifted) durably stage an exact payload before POSTing it.
 *
 * Audit completion remains fail-soft: a D1/outbound error cannot turn the
 * completed audit into a failure. Notification state itself is durable in the
 * watch-row outbox, so non-2xx responses retain the exact payload for replay.
 */
async function deliverWatchWebhookIfShifted(args: DeliverWatchWebhookArgs): Promise<void> {
	const watch = (await args.db
		.prepare(
			'SELECT id, owner_id, domain, interval, webhook_url, last_classification_hash, last_classification_result_json, pending_webhook_json FROM brand_audit_watches WHERE id = ? LIMIT 1',
		)
		.bind(args.watchId)
		.first()) as WatchSlim | null;
	if (!watch) return;

	// Defense in depth: confirm the message's ownerId matches the watch row's
	// owner. If they diverge, drop — something is wrong upstream.
	if (args.ownerId !== null && watch.owner_id !== args.ownerId) return;

	const currentHash = await computeClassificationHash(args.current);
	const currentResultJson = JSON.stringify(args.current);
	let effectiveWatch = watch;
	let recoveredPreviousResult: CheckResult | undefined;

	// A previous attempt owns the delivery order. Replay its exact persisted
	// payload before considering the newest audit, so H0→H1 cannot collapse into
	// an empty H1→H1 diff after a transient POST failure.
	if (watch.pending_webhook_json) {
		if (!watch.webhook_url) return;
		const pending = await parsePendingWatchWebhook(watch.pending_webhook_json, watch);
		if (!pending) {
			logError('Invalid pending Brand Drift webhook state', {
				category: 'brand_audit',
				result: 'pending_webhook_invalid',
			});
			return;
		}
		if (!(await args.deliverWebhook(watch.webhook_url, pending.payload))) return;
		const finalized = await finalizePendingWebhookCas(args.db, watch, watch.pending_webhook_json, pending);
		if (!finalized) return;
		if (currentHash === pending.payload.currentHash) return;

		// The recovery tick may already contain H2. Continue in the same invocation
		// from the just-acknowledged H1 baseline so a monthly watch does not wait a
		// month to stage and deliver H1→H2.
		effectiveWatch = {
			...watch,
			last_classification_hash: pending.payload.currentHash,
			last_classification_result_json: JSON.stringify(pending.currentResult),
			pending_webhook_json: null,
		};
		recoveredPreviousResult = pending.currentResult;
	}

	// No drift. Existing rows created before the outbox migration may not yet
	// have the full baseline result; backfill it only when its hash is proven.
	if (effectiveWatch.last_classification_hash === currentHash) {
		if (!effectiveWatch.last_classification_result_json) {
			await persistClassificationBaselineCas(args.db, effectiveWatch, currentResultJson);
		}
		return;
	}

	if (!effectiveWatch.webhook_url) {
		// Logging-only watch — drift detected but no delivery target.
		await persistClassificationStateCas(args.db, effectiveWatch, currentHash, currentResultJson);
		return;
	}

	// Fetch the previous CheckResult if we had a prior hash, so we can compute
	// the actual diff (added/removed/modified). On first-ever delivery
	// (previous_hash null), we can't compute a meaningful diff — send the
	// current state as a one-shot "initial classification" event.
	const previousResult =
		effectiveWatch.last_classification_hash === null
			? null
			: (recoveredPreviousResult ?? (await findClassificationResultByHash(args.db, effectiveWatch, args.auditId)));
	if (effectiveWatch.last_classification_hash !== null && previousResult === null) {
		// Never fabricate a diff from the wrong historical audit. Preserve the
		// old hash so a later run can retry after the baseline is repaired.
		logError('Brand Drift baseline result did not match persisted hash', {
			category: 'brand_audit',
			result: 'classification_baseline_missing',
		});
		return;
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

	const payload: BrandAuditWatchWebhookPayload = {
		schemaVersion: 1 as const,
		watchId: args.watchId,
		auditId: args.auditId,
		target: args.target,
		interval: effectiveWatch.interval,
		detectedAt: args.now,
		previousHash: effectiveWatch.last_classification_hash,
		currentHash,
		changes: diff,
	};
	const parsedPayload = BrandAuditWatchWebhookPayloadSchema.safeParse(payload);
	if (!parsedPayload.success) {
		logError('Brand Drift webhook payload exceeded the bounded wire contract', {
			category: 'brand_audit',
			result: 'webhook_payload_invalid',
		});
		return;
	}
	const encodedPayload = JSON.stringify(parsedPayload.data);
	if (new TextEncoder().encode(encodedPayload).byteLength > BRAND_AUDIT_WATCH_WEBHOOK_MAX_BODY_BYTES) {
		logError('Brand Drift webhook payload exceeded the bounded body contract', {
			category: 'brand_audit',
			result: 'webhook_payload_too_large',
		});
		return;
	}

	const boundedPayload = parsedPayload.data as BrandAuditWatchWebhookPayload;
	const pendingJson = JSON.stringify({ payload: boundedPayload, currentResult: args.current });
	if (!(await persistPendingWebhookCas(args.db, effectiveWatch, pendingJson))) {
		// A concurrent invocation staged the ordered payload first. It owns the
		// POST; this invocation must not deliver an uncommitted competing diff.
		return;
	}

	const delivered = await args.deliverWebhook(effectiveWatch.webhook_url, boundedPayload);
	if (!delivered) {
		// Leave both the prior hash and exact pending payload intact. A later
		// watch run replays this payload rather than recomputing against a newer
		// completed audit.
		return;
	}

	await finalizePendingWebhookCas(args.db, effectiveWatch, pendingJson, {
		payload: boundedPayload,
		currentResult: args.current,
	});
}

async function persistPendingWebhookCas(db: D1Database, watch: WatchSlim, pendingJson: string): Promise<boolean> {
	const result =
		watch.last_classification_hash === null
			? await db
					.prepare(
						'UPDATE brand_audit_watches SET pending_webhook_json = ? WHERE id = ? AND last_classification_hash IS NULL AND pending_webhook_json IS NULL',
					)
					.bind(pendingJson, watch.id)
					.run()
			: await db
					.prepare(
						'UPDATE brand_audit_watches SET pending_webhook_json = ? WHERE id = ? AND last_classification_hash = ? AND pending_webhook_json IS NULL',
					)
					.bind(pendingJson, watch.id, watch.last_classification_hash)
					.run();
	return (result.meta?.changes ?? 0) === 1;
}

async function finalizePendingWebhookCas(
	db: D1Database,
	watch: WatchSlim,
	pendingJson: string,
	pending: PendingWatchWebhook,
): Promise<boolean> {
	const result =
		watch.last_classification_hash === null
			? await db
					.prepare(
						'UPDATE brand_audit_watches SET last_classification_hash = ?, last_classification_result_json = ?, pending_webhook_json = NULL WHERE id = ? AND last_classification_hash IS NULL AND pending_webhook_json = ?',
					)
					.bind(pending.payload.currentHash, JSON.stringify(pending.currentResult), watch.id, pendingJson)
					.run()
			: await db
					.prepare(
						'UPDATE brand_audit_watches SET last_classification_hash = ?, last_classification_result_json = ?, pending_webhook_json = NULL WHERE id = ? AND last_classification_hash = ? AND pending_webhook_json = ?',
					)
					.bind(pending.payload.currentHash, JSON.stringify(pending.currentResult), watch.id, watch.last_classification_hash, pendingJson)
					.run();
	return (result.meta?.changes ?? 0) === 1;
}

async function persistClassificationStateCas(
	db: D1Database,
	watch: WatchSlim,
	currentHash: string,
	currentResultJson: string,
): Promise<boolean> {
	const result =
		watch.last_classification_hash === null
			? await db
					.prepare(
						'UPDATE brand_audit_watches SET last_classification_hash = ?, last_classification_result_json = ? WHERE id = ? AND last_classification_hash IS NULL AND pending_webhook_json IS NULL',
					)
					.bind(currentHash, currentResultJson, watch.id)
					.run()
			: await db
					.prepare(
						'UPDATE brand_audit_watches SET last_classification_hash = ?, last_classification_result_json = ? WHERE id = ? AND last_classification_hash = ? AND pending_webhook_json IS NULL',
					)
					.bind(currentHash, currentResultJson, watch.id, watch.last_classification_hash)
					.run();
	return (result.meta?.changes ?? 0) === 1;
}

async function persistClassificationBaselineCas(db: D1Database, watch: WatchSlim, currentResultJson: string): Promise<boolean> {
	if (watch.last_classification_hash === null) return false;
	const result = await db
		.prepare(
			'UPDATE brand_audit_watches SET last_classification_result_json = ? WHERE id = ? AND last_classification_hash = ? AND last_classification_result_json IS NULL AND pending_webhook_json IS NULL',
		)
		.bind(currentResultJson, watch.id, watch.last_classification_hash)
		.run();
	return (result.meta?.changes ?? 0) === 1;
}

/**
 * Default webhook deliverer — uses safeFetch (SSRF-validated). Returns true
 * on 2xx, false on any non-2xx or thrown error. Never throws — caller relies
 * on the boolean.
 */
/** @internal The optional timeout override exists only for deterministic focused tests. */
export async function defaultDeliverWebhook(
	url: string,
	payload: unknown,
	timeoutMs = BRAND_AUDIT_WEBHOOK_TIMEOUT_MS,
	options: DefaultWebhookDeliveryOptions = {},
): Promise<boolean> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(new DOMException('Brand audit webhook timed out', 'TimeoutError')), timeoutMs);
	let response: Response | undefined;
	try {
		const trustedReceiver = isBlackVeilBrandDriftReceiver(url);
		const body = JSON.stringify(payload);
		if (new TextEncoder().encode(body).byteLength > BRAND_AUDIT_WATCH_WEBHOOK_MAX_BODY_BYTES) return false;
		if (trustedReceiver) {
			// Fail closed: never fall back to public HTTP for BlackVeil's receiver,
			// because only the service-bound request may carry this capability.
			if (
				!options.blackVeilBinding ||
				!options.peerAuthTokens ||
				!strongBrandWebhookCapability(options.authToken, options.peerAuthTokens)
			) {
				return false;
			}
			const serviceUrl = new URL(BLACKVEIL_BRAND_DRIFT_SERVICE_URL);
			serviceUrl.search = trustedReceiver.search;
			response = await options.blackVeilBinding.fetch(serviceUrl.toString(), {
				method: 'POST',
				headers: {
					Authorization: `Bearer ${options.authToken}`,
					'Content-Type': 'application/json',
				},
				body,
				redirect: 'manual',
				signal: controller.signal,
			});
		} else {
			const { safeFetch } = await import('../lib/safe-fetch');
			response = await safeFetch(url, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body,
				redirect: 'manual',
				signal: controller.signal,
			});
		}
		return response.ok;
	} catch {
		return false;
	} finally {
		clearTimeout(timeoutId);
		if (response) await disposeUnreadResponseBody(response);
	}
}
