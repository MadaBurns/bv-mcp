// SPDX-License-Identifier: BUSL-1.1

/**
 * DoH TRANSPORT failures for the per-check abstention specs (SQ-201): the resolver never
 * answered, as opposed to an answered NXDOMAIN / empty NOERROR, which is a measurement. Each
 * mode makes EVERY DoH fetch fail the same way, at the `fetch` boundary, so the Worker's real
 * DNS transport (retries, DnsQueryError wrapping) runs unmocked.
 *
 * `fail` is the single failing fetch, exposed so a spec can cut ONLY some lookups (SQ-207: the
 * DNSSEC/AD lookup fails while the TLSA lookup answers) by calling it from its own `fetch`
 * mock for the targeted URLs.
 */

import { expect, vi } from 'vitest';
import type { CheckResult } from '../../src/lib/scoring';

export interface DohTransportFailure {
	label: string;
	/** One failing DoH fetch: resolves to an HTTP error response or rejects at the fetch boundary. */
	fail: () => Promise<Response>;
	/** Make EVERY DoH fetch fail this way. */
	install: () => void;
}

function mode(label: string, fail: () => Promise<Response>): DohTransportFailure {
	return {
		label,
		fail,
		install: () => {
			globalThis.fetch = vi.fn(fail) as unknown as typeof fetch;
		},
	};
}

export const DOH_TRANSPORT_FAILURES: ReadonlyArray<DohTransportFailure> = [
	mode('the DoH resolver returns HTTP 503', async () => new Response('upstream unavailable', { status: 503 })),
	mode('the DoH fetch rejects with a network error', async () => {
		throw new TypeError('Network connection lost');
	}),
	// The DOMException `AbortSignal.timeout` produces in the runtime.
	mode('the DoH fetch times out', async () => {
		throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
	}),
];

/**
 * The not-assessed shape: excluded from scoring (`checkStatus`), retried (`score` 0), uncached
 * (`partial`), not a pass, no publication claim, and only the `dns_error`-marked info finding —
 * never a scored finding or a declared missing control.
 */
export function expectDnsAbstention(result: CheckResult, category: string): void {
	expect(result.category).toBe(category);
	expect(result.checkStatus).toBe('error');
	expect(result.score).toBe(0);
	expect(result.passed).toBe(false);
	expect(result.partial).toBe(true);
	expect(result.recordPresent).toBeUndefined();
	expect(result.findings.length).toBeGreaterThan(0);
	for (const finding of result.findings) {
		expect(finding.severity, finding.title).toBe('info');
		expect(finding.metadata?.errorKind, finding.title).toBe('dns_error');
		expect(finding.metadata?.missingControl, finding.title).not.toBe(true);
	}
}
