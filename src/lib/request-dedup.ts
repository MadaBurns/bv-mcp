// SPDX-License-Identifier: BUSL-1.1

/**
 * Request deduplication and durable idempotency for mutating tools.
 *
 * The mutating `*_start` / `register_*` tools force a cache-miss by design (a
 * random-UUID cache key), so a client network-retry re-sends identical args and
 * creates a DUPLICATE watch / scan / investigation. This helper fingerprints
 * (principal + tool + canonical args) into KV with a short TTL and replays the
 * prior SUCCESSFUL result on a duplicate within the window, so the retry gets
 * the same operation ID instead of enqueuing fresh work.
 *
 * The legacy argument fingerprint below remains a best-effort compatibility
 * window for public MCP clients that do not send an explicit idempotency key.
 * Internal callers can supply a stable Idempotency-Key; those requests use the
 * strong Durable Object coordinator further down this file and fail closed when
 * strong state is unavailable.
 *
 * Legacy design notes / boundaries:
 *  - **Best-effort, not a lock.** KV is eventually consistent, so two truly
 *    simultaneous retries can both miss the window and both execute. That's
 *    acceptable here — it collapses the common SEQUENTIAL network-retry, and
 *    D1 UUID uniqueness limits the blast radius of the rare concurrent race.
 *  - **Store-on-success only.** A failed/transient result is never stored, so a
 *    retry after a transient failure still re-attempts. The flip side: a
 *    `*_start` that already enqueued work in the backend and THEN timed out
 *    returns `isError` (not stored), so its retry can still duplicate. Inherent
 *    to a store-on-success window.
 *  - **Requires a real principal.** Without an authenticated principal we skip
 *    dedup entirely. Keying two different unauthenticated callers to the same
 *    fingerprint would replay caller A's operation ID to caller B — a
 *    cross-principal disclosure, since IDs are pollable via `*_status`/`*_report`.
 *  - **Fail-soft.** Any KV/crypto error degrades to a normal (un-deduped) call;
 *    dedup never breaks the tool.
 */

import {
	beginIdempotentRequestWithCoordinator,
	completeIdempotentRequestWithCoordinator,
	releaseIdempotentRequestWithCoordinator,
	type QuotaCoordinator,
} from './quota-coordinator';

/** TTL of the dedup window. ≥60s to satisfy Cloudflare KV's minimum expirationTtl. */
export const DEDUP_TTL_SECONDS = 90;

/** Replay horizon for explicit internal Idempotency-Key requests. */
export const STRONG_IDEMPOTENCY_TTL_SECONDS = 7 * 24 * 60 * 60;

/**
 * Deterministic JSON: object keys sorted recursively so arg order doesn't change
 * the fingerprint. Array order is PRESERVED — it is semantic (`[a,b]` ≠ `[b,a]`).
 */
export function canonicalJson(value: unknown): string {
	return JSON.stringify(sortValue(value));
}

async function sha256Hex(payload: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

function sortValue(v: unknown): unknown {
	if (Array.isArray(v)) return v.map(sortValue);
	if (v && typeof v === 'object') {
		const out: Record<string, unknown> = {};
		for (const k of Object.keys(v as Record<string, unknown>).sort()) {
			out[k] = sortValue((v as Record<string, unknown>)[k]);
		}
		return out;
	}
	return v;
}

/** `idem:<tool>:<sha256hex(principal · tool · canonicalArgs)>` — tool name kept in the key for observability. */
export async function computeDedupKey(toolName: string, principal: string, args: Record<string, unknown>): Promise<string> {
	const payload = `${principal}\0${toolName}\0${canonicalJson(args)}`;
	const hex = await sha256Hex(payload);
	return `idem:${toolName}:${hex}`;
}

/**
 * Bind a caller-supplied idempotency key to both the authenticated principal and
 * normalized tool name. The separate request hash detects accidental or hostile
 * reuse of the same key for different arguments.
 */
export async function computeStrongIdempotencyKeys(
	toolName: string,
	principal: string,
	idempotencyKey: string,
	args: Record<string, unknown>,
): Promise<{ coordinationKey: string; requestHash: string }> {
	const [keyHash, requestHash] = await Promise.all([
		sha256Hex(`${principal}\0${toolName}\0${idempotencyKey}`),
		sha256Hex(`${toolName}\0${canonicalJson(args)}`),
	]);
	return { coordinationKey: `request-idempotency:${keyHash}`, requestHash };
}

/** Structural result shape the window operates on — only `isError` is read. */
export interface DedupableResult {
	isError?: boolean;
}

export interface RequestDedupParams {
	toolName: string;
	/** Authenticated principal (keyHash / principalId). Falsy → dedup is skipped. */
	principal: string | undefined;
	args: Record<string, unknown>;
	kv: KVNamespace;
	/** When provided, the KV write is deferred (kept off the tool-timeout budget). */
	waitUntil?: (promise: Promise<unknown>) => void;
}

export interface StrongRequestIdempotencyParams {
	toolName: string;
	principal: string;
	idempotencyKey: string;
	args: Record<string, unknown>;
	coordinator?: DurableObjectNamespace<QuotaCoordinator>;
	waitUntil?: (promise: Promise<unknown>) => void;
}

function idempotencyError<T extends DedupableResult>(message: string): T {
	return {
		content: [{ type: 'text', text: message }],
		isError: true,
	} as unknown as T;
}

/**
 * Execute one explicitly keyed mutation at most once during the replay horizon.
 * The claim and terminal response live in strong Durable Object state. A retry
 * while the first request is still running is rejected without executing; a
 * completed retry receives the exact stored response. The execution promise is
 * attached to waitUntil so an HTTP timeout does not abandon result persistence.
 */
export async function withStrongRequestIdempotency<T extends DedupableResult>(
	params: StrongRequestIdempotencyParams,
	fn: () => Promise<T>,
): Promise<T> {
	const { toolName, principal, idempotencyKey, args, coordinator, waitUntil } = params;
	if (!coordinator) {
		return idempotencyError('Idempotency state is unavailable; the mutating request was not executed. Retry with the same Idempotency-Key.');
	}

	let keys: { coordinationKey: string; requestHash: string };
	try {
		keys = await computeStrongIdempotencyKeys(toolName, principal, idempotencyKey, args);
		const begin = await beginIdempotentRequestWithCoordinator(
			keys.coordinationKey,
			keys.requestHash,
			Date.now() + STRONG_IDEMPOTENCY_TTL_SECONDS * 1000,
			coordinator,
		);
		if (!begin) {
			return idempotencyError('Idempotency state is unavailable; the mutating request was not executed. Retry with the same Idempotency-Key.');
		}
		if (begin.state === 'conflict') {
			return idempotencyError('Idempotency-Key was already used with a different request. Use a new key for different arguments.');
		}
		if (begin.state === 'in_progress') {
			return idempotencyError('The request for this Idempotency-Key is still in progress. Retry with the same key.');
		}
		if (begin.state === 'complete') {
			try {
				return JSON.parse(begin.result) as T;
			} catch {
				return idempotencyError('The stored idempotent response is unavailable; the mutating request was not re-executed.');
			}
		}
	} catch {
		return idempotencyError('Idempotency state is unavailable; the mutating request was not executed. Retry with the same Idempotency-Key.');
	}

	const execution = (async (): Promise<T> => {
		let result: T;
		try {
			result = await fn();
		} catch (error) {
			// The executor threw before producing a response: drop the in_progress claim so a
			// same-key retry can run instead of being refused for the 7-day replay horizon.
			try {
				await releaseIdempotentRequestWithCoordinator(keys.coordinationKey, keys.requestHash, coordinator);
			} catch {
				// Best-effort: an unreleased claim stays fail-closed (retry refused), never a duplicate effect.
			}
			throw error;
		}
		try {
			const serialized = JSON.stringify(result);
			await completeIdempotentRequestWithCoordinator(keys.coordinationKey, keys.requestHash, serialized, coordinator);
		} catch {
			// The strong claim remains in-progress, which is fail-closed: a retry
			// cannot duplicate an effect whose response could not be persisted.
		}
		return result;
	})();

	if (waitUntil) waitUntil(execution.then(() => undefined, () => undefined));
	return execution;
}

/**
 * Run `fn`, deduplicating identical mutating requests within the TTL window.
 * Returns the prior successful result on a duplicate; otherwise executes `fn`
 * and (on success) stores it. Degrades to a plain `fn()` call on any failure.
 */
export async function withRequestDedup<T extends DedupableResult>(params: RequestDedupParams, fn: () => Promise<T>): Promise<T> {
	const { toolName, principal, args, kv, waitUntil } = params;

	// Never dedup without a real principal — see module header (cross-principal ID leak).
	if (!principal) return fn();

	let key: string;
	try {
		key = await computeDedupKey(toolName, principal, args);
	} catch {
		return fn(); // hashing unavailable → no dedup
	}

	try {
		const stored = await kv.get(key);
		if (stored) return JSON.parse(stored) as T;
	} catch {
		// KV read failed → fall through and execute normally.
	}

	const result = await fn();

	// Store only successful results so a transient failure stays retryable.
	if (!result.isError) {
		const put = kv.put(key, JSON.stringify(result), { expirationTtl: DEDUP_TTL_SECONDS }).catch(() => {});
		if (waitUntil) waitUntil(put);
		else await put;
	}
	return result;
}
