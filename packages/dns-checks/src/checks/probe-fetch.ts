// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { FetchFunction } from '../types';
import { SCANNER_USER_AGENT } from '../robots-gate';

/**
 * Below this much remaining budget (ms), a GET fallback cannot return a genuine answer —
 * it would be aborted almost immediately. Skip it rather than spend a fetch on a race it
 * cannot win (#1088).
 */
export const GET_FALLBACK_MIN_BUDGET_MS = 250;

/**
 * Attempt a GET request as fallback when a HEAD probe was refused (403/405) or
 * failed server-side (5xx).
 *
 * Shared by check-http-security and check-ssl deliberately: both probe the SAME
 * origin in the SAME scan, so a second, separately-maintained copy would let the
 * two checks drift into disagreeing about whether an origin is assessable. That
 * failure mode is not hypothetical here — the SPF trust-surface analyzer shipped
 * in two copies that disagreed on the scored number until 1.17.0.
 *
 * `remainingMs` is what's LEFT of the check's total per-origin `timeoutMs` budget after the
 * HEAD probe already spent part of it — NOT a fresh timeout (#1088). Callers must compute
 * `Math.max(0, timeoutMs - elapsedSinceHead)` and pass it here, so the HEAD+GET pair together
 * never exceeds the check's one `timeoutMs`; before this fix each caller re-armed the GET with
 * the full original `timeoutMs`, so a slow-but-still-answering HEAD could push the pair to
 * roughly 2x the intended budget. Below `GET_FALLBACK_MIN_BUDGET_MS`, there isn't enough budget
 * left for a GET to return a genuine answer, so this returns null immediately without issuing
 * the request — the same "no fallback available" signal a network failure produces, routing the
 * caller to its existing HEAD-status abstention path.
 *
 * Returns null on any fetch error (including SSRF rejection from a safeFetch
 * wrapper), so callers keep their existing "not assessable" lane for that case.
 */
export async function tryGetFallback(url: string, fetchFn: FetchFunction, remainingMs: number): Promise<Response | null> {
	if (remainingMs < GET_FALLBACK_MIN_BUDGET_MS) return null;
	try {
		return await fetchFn(url, {
			method: 'GET',
			redirect: 'manual',
			headers: { 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(remainingMs),
		});
	} catch {
		return null;
	}
}
