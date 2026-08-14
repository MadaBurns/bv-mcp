// SPDX-License-Identifier: BUSL-1.1

import type { DNSQueryFunction } from '@blackveil/dns-checks';
import { DNS_TIMEOUT_MS } from './config';
import { queryDnsRecords, queryTxtRecords } from './dns';
import type { QueryDnsOptions } from './dns-types';

/**
 * Build a DNSQueryFunction adapter that routes TXT queries through queryTxtRecords
 * (which strips surrounding quotes from DoH TXT data) and all other record types
 * through queryDnsRecords.
 *
 * ## The caller's `timeout` is an UPPER BOUND, never a floor
 *
 * `DNSQueryFunction` declares a third `options?: { timeout?: number }` parameter and
 * the package checks pass one (`{ timeout: 4000 }` / `{ timeout: 5000 }` at ~15 call
 * sites). This adapter previously took only TWO parameters: with no return-type
 * annotation TypeScript inferred the 2-arg shape, structural typing accepted it
 * everywhere a `DNSQueryFunction` was expected, and the third argument was silently
 * DISCARDED (issue #674).
 *
 * Simply honouring it would be a regression, not a fix. One LOGICAL query costs
 * `DNS_RETRIES + 1 = 2` attempts plus a 75–125ms backoff, so the worst case is
 * `2 * timeout + 125ms`: 6125ms at the Worker's 3000ms, but 8125ms at 4000 and
 * 10125ms at 5000 — both OVER the 8s `PER_CHECK_TIMEOUT_MS`. Obeying the caller
 * would turn an inert parameter into a category-losing one on a single slow lookup,
 * reintroducing exactly the #641 failure mode (`safeCheck` kills the check and
 * `scan_domain` loses the whole category, discarding legs that already succeeded).
 *
 * The parameter is NOT dropped from the package type either — it is published API,
 * and bv-web-prod's own resolver honours it correctly with no per-check killer over
 * it. The Worker is deliberately the odd one out, so it makes its refusal explicit:
 * the caller's value may only LOWER the effective timeout (`Math.min`), never raise
 * it above the Worker's own resolved value. Today no caller passes below the 3000ms
 * global, so the clamp is a zero-behaviour-change guardrail.
 *
 * ⚠️ The `: DNSQueryFunction` annotation does NOT by itself prevent a repeat of #674.
 * TypeScript accepts a function with FEWER parameters wherever more are declared, so
 * deleting the third parameter again compiles clean under the annotation (measured,
 * not assumed). What the annotation does catch is a wrong option shape
 * (`{ timeoutMs }` for `{ timeout }`), a wrong return type, and an extra REQUIRED
 * parameter. The dropped-parameter direction — the one that actually shipped — is
 * guarded at runtime by the `fn.length === 3` assertion in
 * `test/dns-query-adapter.spec.ts`. Do not delete that assertion as redundant with
 * the type: it is the only thing standing where the type system is silent.
 */
export function makeQueryDNS(dnsOptions?: QueryDnsOptions): DNSQueryFunction {
	const workerTimeoutMs = dnsOptions?.timeoutMs ?? DNS_TIMEOUT_MS;

	return async (domain: string, type: string, options?: { timeout?: number }): Promise<string[]> => {
		const requested = options?.timeout;
		// Clamp DOWN only. A non-positive/non-finite request is treated as absent.
		const effective =
			typeof requested === 'number' && Number.isFinite(requested) && requested > 0 ? Math.min(requested, workerTimeoutMs) : workerTimeoutMs;

		// Pass the caller's options object through UNTOUCHED unless the request
		// actually lowers the timeout — the no-options path (every current caller of
		// the underlying check helpers) must stay byte-for-byte identical, including
		// the `queryCache` / `dnsSemaphore` / `signal` identities carried on it.
		const opts = effective === workerTimeoutMs ? dnsOptions : { ...dnsOptions, timeoutMs: effective };

		if (type === 'TXT') {
			return queryTxtRecords(domain, opts);
		}
		return queryDnsRecords(domain, type as Parameters<typeof queryDnsRecords>[1], opts);
	};
}
