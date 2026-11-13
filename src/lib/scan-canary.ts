// SPDX-License-Identifier: BUSL-1.1

/**
 * Scan-path canary — a synthetic end-to-end `scanDomain` run against ONE fixed control domain on the
 * 15-minute cron.
 *
 * WHY: the traffic-driven alert lanes abstain below a minimum sample floor
 * (`DEFAULT_MIN_ERROR_SAMPLES` in scheduled.ts), the reader-blind self-check only logs, the SPF canary
 * covers a single check once a day, and `/health` is static. A regression that breaks `scan_domain`
 * end to end (resolver transport, the scoring import, a binding) therefore pages nobody until real
 * traffic reaches the floor. This canary is the low-traffic tripwire.
 *
 * It asserts that the scan PATH works, never what the control domain's posture is: a score or grade
 * change on the control must not page, so health is "returned, resolved, graded, and measured enough".
 *
 * This module holds the pure/policy pieces (config, the single scan, the health predicate, the failure
 * counter transition). The KV + webhook I/O lives in `handleScanCanary` (scheduled.ts), mirroring the
 * SPF canary.
 */

import { scanDomain } from '../tools/scan-domain';
import type { ScanDomainResult } from '../tools/scan-domain';
import { isEvidenceSufficient, isGraded } from './scoring';
import { sanitizeDomain, validateDomain } from './sanitize';

/**
 * Default control domain: public DNS-infrastructure operator, DNSSEC-signed, NOT hosted on Cloudflare
 * (a Cloudflare-hosted control would measure our own provider's behaviour, not the scan path).
 */
export const DEFAULT_SCAN_CANARY_DOMAIN = 'isc.org';

/**
 * Hard wall-clock ceiling for the canary's one scan. Sits below the cron invocation's limits and above
 * the scan's own budget, so a hung scan is reported as `timeout` instead of eating the tick.
 */
export const SCAN_CANARY_TIMEOUT_MS = 12_000;

/** The scan's own internal budget, kept under {@link SCAN_CANARY_TIMEOUT_MS} so the engine times out first and returns partial evidence. */
const SCAN_CANARY_SCAN_BUDGET_MS = 10_000;

/** Consecutive unhealthy runs required before a page — a single blip never pages. */
export const SCAN_CANARY_PAGE_AFTER = 2;

export type ScanCanaryReason = 'ok' | 'threw' | 'timeout' | 'unresolved' | 'ungraded' | 'insufficient_evidence';

export interface ScanCanaryAssessment {
	healthy: boolean;
	reason: ScanCanaryReason;
	/** Fraction of attempted scoring checks that completed, when a scan returned. */
	evidenceRatio?: number;
	/** Bounded error text for `threw`. */
	detail?: string;
}

/** What the single scan did. `returned` carries only the fields the predicate reads. */
export type ScanCanaryOutcome =
	| { status: 'returned'; result: Pick<ScanDomainResult, 'resolves' | 'score'> }
	| { status: 'threw'; error: unknown }
	| { status: 'timeout' };

/** Resolve the control domain: a valid `SCAN_CANARY_DOMAIN` override, else the default. */
export function resolveScanCanaryDomain(override: string | undefined): string {
	if (!override || !override.trim()) return DEFAULT_SCAN_CANARY_DOMAIN;
	const candidate = sanitizeDomain(override);
	return validateDomain(candidate).valid ? candidate : DEFAULT_SCAN_CANARY_DOMAIN;
}

/** Kill switch: only the literal string 'false' (any case, trimmed) disables the canary. */
export function isScanCanaryEnabled(flag: string | undefined): boolean {
	return flag?.trim().toLowerCase() !== 'false';
}

/** Flattened, bounded text of a thrown value — log/alert safe. */
function boundedErrorText(error: unknown): string {
	const text = error instanceof Error ? error.message : String(error);
	return text.replace(/\s+/g, ' ').trim().slice(0, 200);
}

function isUnresolved(resolves: ScanDomainResult['resolves']): boolean {
	return resolves === false || resolves === 'broken';
}

function isUngraded(score: ScanDomainResult['score']): boolean {
	return !isGraded(score) || !!score.evidenceInsufficient;
}

function hasSufficientEvidence(score: ScanDomainResult['score']): boolean {
	return !!score.evidence && isEvidenceSufficient(score.evidence);
}

/** First failing health condition of a returned scan, or 'ok'. */
function returnedReason(result: Pick<ScanDomainResult, 'resolves' | 'score'>): ScanCanaryReason {
	if (isUnresolved(result.resolves)) return 'unresolved';
	if (isUngraded(result.score)) return 'ungraded';
	if (!hasSufficientEvidence(result.score)) return 'insufficient_evidence';
	return 'ok';
}

/**
 * Health predicate (pure). Healthy only when the scan returned, the apex resolved (`measured`), the
 * result is graded, and the completed-check ratio meets the engine's sufficiency threshold. Never
 * compares a score or grade value.
 */
export function assessScanCanary(outcome: ScanCanaryOutcome): ScanCanaryAssessment {
	if (outcome.status === 'timeout') return { healthy: false, reason: 'timeout' };
	if (outcome.status === 'threw') return { healthy: false, reason: 'threw', detail: boundedErrorText(outcome.error) };
	const reason = returnedReason(outcome.result);
	return { healthy: reason === 'ok', reason, evidenceRatio: outcome.result.score.evidence?.ratio };
}

type ScanFn = (
	domain: string,
	kv?: KVNamespace,
	options?: { forceRefresh?: boolean; scanTimeoutMs?: number; signal?: AbortSignal },
) => Promise<ScanDomainResult>;

/** One scan raced against a hard deadline; the signal is aborted when the deadline wins. Never throws. */
async function scanWithDeadline(domain: string, scan: ScanFn, timeoutMs: number): Promise<ScanCanaryOutcome> {
	const controller = new AbortController();
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timedOut = new Promise<'timeout'>((resolve) => {
		timer = setTimeout(() => {
			controller.abort();
			resolve('timeout');
		}, timeoutMs);
	});
	try {
		const run = scan(domain, undefined, {
			forceRefresh: true,
			scanTimeoutMs: Math.min(SCAN_CANARY_SCAN_BUDGET_MS, timeoutMs),
			signal: controller.signal,
		});
		// A scan rejecting AFTER the timeout already won must not become an unhandled rejection.
		run.catch(() => undefined);
		const winner = await Promise.race([run, timedOut]);
		return winner === 'timeout' ? { status: 'timeout' } : { status: 'returned', result: winner };
	} catch (error) {
		return controller.signal.aborted ? { status: 'timeout' } : { status: 'threw', error };
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Run ONE full scan of `domain`, bypassing the scan cache, under a hard timeout. Never throws.
 *
 * Deliberately passes no KV, `profileAccumulator` or `waitUntil`: `scanDomain` itself writes no
 * request analytics, and omitting these keeps the canary's result out of the shared scan cache and the
 * profile statistics, so it cannot be mistaken for (or replayed as) a customer's scan.
 */
export async function runScanCanary(
	domain: string,
	options: { timeoutMs?: number; scan?: ScanFn } = {},
): Promise<{ outcome: ScanCanaryOutcome; durationMs: number }> {
	const startedAt = Date.now();
	const outcome = await scanWithDeadline(domain, options.scan ?? scanDomain, options.timeoutMs ?? SCAN_CANARY_TIMEOUT_MS);
	return { outcome, durationMs: Date.now() - startedAt };
}

/** Parse the persisted consecutive-failure counter; anything unreadable is 0 (fail open to "no history"). */
export function parseFailureCount(raw: string | null | undefined): number {
	const n = Number.parseInt(raw ?? '', 10);
	return Number.isFinite(n) && n > 0 ? n : 0;
}

export interface ScanCanaryTransition {
	/** Counter value to persist (0 = clear). */
	failures: number;
	/** Page-worthy: the run is the {@link SCAN_CANARY_PAGE_AFTER}th or later consecutive unhealthy one. Repeat suppression still applies. */
	page: boolean;
	/** First healthy run after a page-worthy streak: send the recovery notice. */
	recover: boolean;
}

/** Counter transition (pure): unhealthy increments, healthy clears and recovers iff a page was due. */
export function nextScanCanaryState(previousFailures: number, healthy: boolean): ScanCanaryTransition {
	if (healthy) return { failures: 0, page: false, recover: previousFailures >= SCAN_CANARY_PAGE_AFTER };
	const failures = previousFailures + 1;
	return { failures, page: failures >= SCAN_CANARY_PAGE_AFTER, recover: false };
}
