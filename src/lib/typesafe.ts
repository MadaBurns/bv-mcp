// SPDX-License-Identifier: BUSL-1.1

/**
 * TypeSafe (System One / Jev) client wrapper.
 *
 * WHY A WRAPPER RATHER THAN THE SDK DIRECTLY — three repo invariants the bare
 * client would violate:
 *
 *  1. **SSRF chokepoint.** The SDK defaults to `globalThis.fetch`. We inject
 *     {@link safeFetch} as its transport so every TypeSafe request passes the same
 *     `validateOutboundUrl` gate as any other outbound call.
 *  2. **Fail-soft, never throw.** Absent key, 401, 422, 429, 529, timeout, malformed
 *     body — all collapse to `null`. Callers fall back to their deterministic path.
 *     Same doctrine as `resolveCertspotterToken`, whose docblock states it "must
 *     never become a hard dependency". A security scanner must not start returning
 *     errors because a third-party inference API had a bad afternoon.
 *  3. **Budget awareness.** Where a caller already owns a deadline (`FetchBudget`),
 *     the request inherits it rather than inventing a second, longer one.
 *
 * ⚠️ NOT FOR THE SCORE. Nothing here may reach `computeScanScore`. TypeSafe returns
 * calibrated probabilities, but the scan score is deterministic by design and a
 * weight/grade change re-grades every customer. Judgments belong to STANDALONE
 * intelligence tools (`scanIncluded: false`, no `tier`) only.
 */

import { TypeSafeClient } from '@typesafe-ai/sdk';
import type { FetchBudget } from './fetch-budget';
import { safeFetch } from './safe-fetch';

/** Pinned model. Bump deliberately — a model change re-calibrates every threshold. */
export const TYPESAFE_MODEL = 'jev-latest';

/**
 * Default per-request deadline. Deliberately well under the ~24s standalone-handler
 * budgets so a slow inference call leaves room for the deterministic work that
 * follows it. Their published batched-call figure is ~0.27s for 13 questions, so
 * this is ~20x headroom, not a tight race.
 */
export const TYPESAFE_DEFAULT_TIMEOUT_MS = 6_000;

export type TypesafeAskOptions = {
	/** Inherit a caller's existing deadline instead of starting a fresh one. */
	budget?: FetchBudget;
	/** Override the per-request deadline (ms). Ignored when `budget` is tighter. */
	timeoutMs?: number;
};

/**
 * Build a client, or `null` when unprovisioned.
 *
 * `null` is the NORMAL state on a BUSL self-host and in the Vitest pool — it is not
 * an error and must not be logged as one.
 */
export function createTypesafeClient(apiKey: string | undefined): TypeSafeClient | null {
	if (!apiKey) return null;
	try {
		return new TypeSafeClient({
			apiKey,
			// The SSRF chokepoint. Do not remove: without it the SDK reaches
			// `globalThis.fetch` and bypasses `validateOutboundUrl` entirely.
			fetch: safeFetch,
			timeout: TYPESAFE_DEFAULT_TIMEOUT_MS,
			// ⚠️ RETRIES OFF — do not restore the SDK default (`maxRetries: 2`).
			//
			// The SDK applies `timeout` PER ATTEMPT, inside its retry loop, and adds
			// ~500ms/~1000ms of backoff between attempts. With the default policy a
			// retryable 408/429/5xx therefore costs up to ~3x the timeout this
			// wrapper just clamped to the caller's `FetchBudget`, plus ~1.5s — so the
			// budget it promises to honour would be silently overrun. That is the
			// #641 failure class (`lib/fetch-budget.ts`): sequential legs summing past
			// a deadline and killing the check mid-flight.
			//
			// A retry also buys nothing here. Every failure path in `askTypesafe`
			// collapses to `null` and the caller keeps its deterministic result, so a
			// retry can only add latency risk to an enrichment that is allowed to be
			// absent. Set at CLIENT level, not per request, so it holds for any future
			// call site that does not route through `askTypesafe`.
			retry: { maxRetries: 0 },
		});
	} catch {
		// Constructor validates apiKey/baseURL/timeout. A bad value is a
		// provisioning fault, not a request fault — degrade, don't crash boot.
		return null;
	}
}

/**
 * Ask a batch of questions about one state. Returns the `answers` map, or `null`
 * if anything at all went wrong.
 *
 * ALWAYS batch: the state dominates the payload, so N separate calls cost N times
 * the input tokens. Their measured figure is 12.2x cheaper and 10x faster for 13
 * questions batched versus sent individually.
 */
export async function askTypesafe<Q extends Record<string, unknown>>(
	client: TypeSafeClient | null,
	state: unknown,
	questions: Q,
	options: TypesafeAskOptions = {},
): Promise<Record<keyof Q, unknown> | null> {
	if (!client) return null;
	if (Object.keys(questions).length === 0) return null;

	// A budget that is already spent must not burn a subrequest.
	const budget = options.budget;
	if (budget && !budget.canIssueRequest()) return null;

	const timeout = Math.min(options.timeoutMs ?? TYPESAFE_DEFAULT_TIMEOUT_MS, budget?.remainingMs() ?? Number.POSITIVE_INFINITY);
	if (!Number.isFinite(timeout) || timeout <= 0) return null;

	try {
		const result = await client.systemOne({ state, model: TYPESAFE_MODEL, questions } as never, { timeout });
		const answers = (result as { answers?: unknown })?.answers;
		if (!answers || typeof answers !== 'object') return null;
		return answers as Record<keyof Q, unknown>;
	} catch {
		// Every SDK error class (Authentication, RateLimit, APITimeout, APIConnection,
		// UnprocessableEntity, ...) lands here by design. The caller's deterministic
		// path is the fallback; a judgment is an enrichment, never a prerequisite.
		return null;
	}
}
