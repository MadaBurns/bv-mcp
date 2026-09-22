// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { FetchFunction } from '../types';
import { SCANNER_USER_AGENT } from '../robots-gate';

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
 * Returns null on any fetch error (including SSRF rejection from a safeFetch
 * wrapper), so callers keep their existing "not assessable" lane for that case.
 */
export async function tryGetFallback(url: string, fetchFn: FetchFunction, timeoutMs: number): Promise<Response | null> {
	try {
		return await fetchFn(url, {
			method: 'GET',
			redirect: 'manual',
			headers: { 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(timeoutMs),
		});
	} catch {
		return null;
	}
}
