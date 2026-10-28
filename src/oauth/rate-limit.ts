// SPDX-License-Identifier: BUSL-1.1

import { OAUTH_KV_PREFIX } from '../lib/config';
import {
	reserveBudgetWithCoordinator,
	type BudgetReservationResult,
	type QuotaCoordinator,
} from '../lib/quota-coordinator';

/** CIMD metadata fetches (cache misses only) allowed per client IP per window; each one is an outbound request to a caller-named host. */
export const CIMD_FETCH_RATE_LIMIT = 10;
export const CIMD_FETCH_RATE_WINDOW_SECONDS = 60;

export interface OAuthRateLimitResult {
	exceeded: boolean;
	retryAfterSeconds: number;
	unavailable?: true;
}

interface OAuthRateLimitOptions {
	kv: KVNamespace;
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>;
	/** Stable endpoint label, e.g. `register:min`; the principal/window are appended. */
	coordinationScope: string;
	/** Existing KV key retained as an unbound fallback and strong-path mirror. */
	kvKey: string;
	principal: string;
	limit: number;
	windowSeconds: number;
	nowMs?: number;
}

interface StoredWindow {
	count: number;
	expiresAt: number;
}

function parseStoredWindow(raw: string | null, nowMs: number): StoredWindow | null {
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw) as { count?: unknown; expiresAt?: unknown };
		if (
			typeof parsed.expiresAt !== 'number' ||
			!Number.isSafeInteger(parsed.expiresAt) ||
			parsed.expiresAt <= nowMs ||
			typeof parsed.count !== 'number' ||
			!Number.isSafeInteger(parsed.count) ||
			parsed.count < 0
		) {
			return null;
		}
		return { count: parsed.count, expiresAt: parsed.expiresAt };
	} catch {
		return null;
	}
}

function retryAfterSeconds(expiresAt: number, nowMs: number): number {
	return Math.max(1, Math.ceil((expiresAt - nowMs) / 1000));
}

function isBudgetReservation(value: unknown, expectedLimit: number): value is BudgetReservationResult {
	if (!value || typeof value !== 'object') return false;
	const candidate = value as Partial<BudgetReservationResult>;
	return (
		typeof candidate.allowed === 'boolean' &&
		candidate.limit === expectedLimit &&
		Number.isSafeInteger(candidate.used) &&
		(candidate.used as number) >= 0 &&
		(candidate.used as number) <= expectedLimit &&
		Number.isSafeInteger(candidate.remaining) &&
		(candidate.remaining as number) >= 0 &&
		(candidate.remaining as number) <= expectedLimit &&
		(!candidate.allowed || (candidate.used as number) >= 1)
	);
}

/**
 * True for the coordinator's "this window is already over" refusal (#985).
 *
 * `handleReserveBudget` answers an expired `expiresAt` with
 * `{allowed: false, used: 0, remaining: 0}`. That shape is unambiguous: a genuine denial
 * happens only when `amount > limit - used`, and with `amount === 1` and `limit >= 1` that
 * requires `used >= limit >= 1`. So `used === 0` alongside `allowed === false` can mean
 * nothing else — and it must NOT be reported as budget exhaustion, because no budget was
 * consulted.
 */
function isExpiredWindowRefusal(reservation: BudgetReservationResult): boolean {
	return !reservation.allowed && reservation.used === 0;
}

/** A coordinator or mirror fault is a denial, never a pass: exceeded + unavailable (the endpoint answers 503). */
function unavailableResult(expiresAt: number, nowMs: number): OAuthRateLimitResult {
	return { exceeded: true, retryAfterSeconds: retryAfterSeconds(expiresAt, nowMs), unavailable: true };
}

/** Configuration is validated before any I/O; an invalid limit or window is a programming error. */
function assertValidRateLimitConfig(limit: number, windowMs: number): void {
	if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(windowMs) || windowMs < 1) {
		throw new RangeError('Invalid OAuth rate-limit configuration');
	}
}

/**
 * Consume one request from an OAuth endpoint window.
 *
 * Production uses a deterministic window key in the quota coordinator, making
 * concurrent requests linearizable. KV remains a best-effort mirror and the
 * bounded self-host fallback when no coordinator is provisioned. Once a
 * coordinator is configured, its failure never falls through to racy KV.
 */
export async function consumeOAuthRateLimit(options: OAuthRateLimitOptions): Promise<OAuthRateLimitResult> {
	const nowMs = options.nowMs ?? Date.now();
	const windowMs = options.windowSeconds * 1000;
	assertValidRateLimitConfig(options.limit, windowMs);

	if (options.quotaCoordinator) {
		return consumeViaCoordinator(options, options.quotaCoordinator, nowMs, windowMs);
	}
	return consumeViaKvWindow(options, nowMs, windowMs);
}

/** Consume one CIMD cache-miss fetch from the client IP's window (bucket `cimd-fetch`, KV mirror `oauth:cimd-rl:<ip>`). */
export function consumeCimdFetchRateLimit(
	kv: KVNamespace,
	ip: string,
	quotaCoordinator?: DurableObjectNamespace<QuotaCoordinator>,
): Promise<OAuthRateLimitResult> {
	return consumeOAuthRateLimit({
		kv,
		quotaCoordinator,
		coordinationScope: 'cimd-fetch',
		kvKey: `${OAUTH_KV_PREFIX}cimd-rl:${ip}`,
		principal: ip,
		limit: CIMD_FETCH_RATE_LIMIT,
		windowSeconds: CIMD_FETCH_RATE_WINDOW_SECONDS,
	});
}

/**
 * Coordinator path, with ONE bounded retry for the window-boundary race only (#985).
 *
 * The window is aligned on the CALLER's clock, but it is the coordinator that
 * judges it: `handleReserveBudget` refuses outright when `expiresAt <= now`. A
 * request that computes its window a few milliseconds before a boundary therefore
 * arrives with a window that has already ended, and the refusal is indistinguishable
 * at the endpoint from a real denial — `exceeded: true` with no `unavailable`, i.e.
 * a 429 telling a caller who has spent NOTHING that it has made too many requests.
 * On a 60s window that is a small but permanent share of live traffic, and it was
 * reproduced against a principal whose first request this was.
 *
 * The retry recomputes the window from the clock as it is NOW, so the second attempt
 * belongs to the window the request actually landed in. It is a genuinely different
 * coordination key, not a re-ask of the same question, which is why a single pass is
 * enough: the new window has nearly its full length left, so it cannot expire in
 * flight the way the first one did. `attempt` is hard-bounded at 2 — an expired
 * window must never become a retry loop against a Durable Object.
 */
async function consumeViaCoordinator(
	options: OAuthRateLimitOptions,
	coordinator: DurableObjectNamespace<QuotaCoordinator>,
	nowMs: number,
	windowMs: number,
): Promise<OAuthRateLimitResult> {
	for (let attempt = 0; attempt < 2; attempt++) {
		const result = await attemptCoordinatedConsume(options, coordinator, attempt, nowMs, windowMs);
		if (result) return result;
	}

	// Unreachable: attempt 0 either returns or continues, and attempt 1 always returns.
	// Written as a denial rather than a throw so a future edit that breaks the invariant
	// fails closed on the endpoint instead of 500-ing.
	return { exceeded: true, retryAfterSeconds: options.windowSeconds, unavailable: true };
}

/** The aligned window one attempt is judged in. */
function attemptWindow(attempt: number, nowMs: number, windowMs: number): { attemptNowMs: number; windowStart: number; expiresAt: number } {
	// Aligned windows ensure every colo derives the same coordinator key. Using
	// `now + window` would create different keys during a concurrent first burst.
	//
	// The retry deliberately ignores an explicitly-supplied `options.nowMs`: that
	// option exists to pin a window for testing, and the whole point of this pass is
	// that the pinned window is over. The request is happening now.
	const attemptNowMs = attempt === 0 ? nowMs : Date.now();
	const windowStart = Math.floor(attemptNowMs / windowMs) * windowMs;
	return { attemptNowMs, windowStart, expiresAt: windowStart + windowMs };
}

/**
 * One coordinator attempt. Resolves to the verdict, or `null` when the first attempt hit the
 * expired-window refusal and the caller should retry on a freshly computed window.
 */
async function attemptCoordinatedConsume(
	options: OAuthRateLimitOptions,
	coordinator: DurableObjectNamespace<QuotaCoordinator>,
	attempt: number,
	nowMs: number,
	windowMs: number,
): Promise<OAuthRateLimitResult | null> {
	const aligned = attemptWindow(attempt, nowMs, windowMs);
	const initialUsed = await readMirroredCount(options, aligned.attemptNowMs);
	try {
		const reservation = await reserveBudgetWithCoordinator(
			`oauth-rate:${options.coordinationScope}:${options.principal}:${aligned.windowStart}`,
			1,
			options.limit,
			aligned.expiresAt,
			coordinator,
			Math.min(initialUsed, options.limit),
		);
		return await settleReservation(options, reservation, attempt, aligned);
	} catch {
		return unavailableResult(aligned.expiresAt, aligned.attemptNowMs);
	}
}

/** The KV mirror's count seeds the coordinator; an unavailable mirror reads as zero and is not an outage. */
async function readMirroredCount(options: OAuthRateLimitOptions, attemptNowMs: number): Promise<number> {
	try {
		return parseStoredWindow(await options.kv.get(options.kvKey), attemptNowMs)?.count ?? 0;
	} catch {
		// The coordinator is authoritative; an unavailable mirror cannot relax it
		// after the first reservation and must not turn into a request outage.
		return 0;
	}
}

/** Turn the coordinator's answer into a verdict (or `null` = retry). A malformed answer is a denial. */
async function settleReservation(
	options: OAuthRateLimitOptions,
	reservation: unknown,
	attempt: number,
	aligned: { attemptNowMs: number; expiresAt: number },
): Promise<OAuthRateLimitResult | null> {
	if (!isBudgetReservation(reservation, options.limit)) return unavailableResult(aligned.expiresAt, aligned.attemptNowMs);
	if (isExpiredWindowRefusal(reservation)) {
		if (attempt === 0) return null;
		// The retry recomputed the window from `Date.now()`, so a SECOND expired-window
		// refusal is not the same race again — it means window judgement is unreliable
		// right now (e.g. a coordinator clock far enough from the caller's). Reporting
		// `exceeded: true` here would 429 a principal whose `used` is still 0, which is
		// exactly the defect #985/#1011 fixed for attempt 0. Fail as unavailable (503)
		// instead, unconditionally preserving "never 429 a principal with used === 0".
		return unavailableResult(aligned.expiresAt, aligned.attemptNowMs);
	}
	await mirrorWindow(options, reservation.used, aligned.expiresAt, aligned.attemptNowMs);
	return {
		exceeded: !reservation.allowed,
		retryAfterSeconds: reservation.allowed ? 0 : retryAfterSeconds(aligned.expiresAt, aligned.attemptNowMs),
	};
}

/** Non-authoritative migration/visibility mirror only; a write failure never changes the verdict. */
async function mirrorWindow(options: OAuthRateLimitOptions, count: number, expiresAt: number, nowMs: number): Promise<void> {
	try {
		await options.kv.put(options.kvKey, JSON.stringify({ count, expiresAt }), {
			expirationTtl: Math.max(60, retryAfterSeconds(expiresAt, nowMs)),
		});
	} catch {
		// Non-authoritative migration/visibility mirror only.
	}
}

/**
 * Self-host compatibility path: preserve the existing first-request-pinned
 * fixed window without requiring a Durable Object namespace.
 */
async function consumeViaKvWindow(options: OAuthRateLimitOptions, nowMs: number, windowMs: number): Promise<OAuthRateLimitResult> {
	const stored = parseStoredWindow(await options.kv.get(options.kvKey), nowMs);
	const count = stored?.count ?? 0;
	const expiresAt = stored?.expiresAt ?? nowMs + windowMs;
	if (count >= options.limit) {
		return { exceeded: true, retryAfterSeconds: retryAfterSeconds(expiresAt, nowMs) };
	}
	await options.kv.put(options.kvKey, JSON.stringify({ count: count + 1, expiresAt }), {
		expirationTtl: Math.max(60, retryAfterSeconds(expiresAt, nowMs)),
	});
	return { exceeded: false, retryAfterSeconds: 0 };
}
