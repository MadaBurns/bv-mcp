// SPDX-License-Identifier: BUSL-1.1

/**
 * DoH TRANSPORT failures for the per-check abstention specs (SQ-201): the resolver never
 * answered, as opposed to an answered NXDOMAIN / empty NOERROR, which is a measurement. Each
 * mode makes EVERY DoH fetch fail the same way, at the `fetch` boundary, so the Worker's real
 * DNS transport (retries, DnsQueryError wrapping) runs unmocked.
 */

import { expect, vi } from 'vitest';
import type { CheckResult } from '../../src/lib/scoring';

export const DOH_TRANSPORT_FAILURES: ReadonlyArray<{ label: string; install: () => void }> = [
	{
		label: 'the DoH resolver returns HTTP 503',
		install: () => {
			globalThis.fetch = vi.fn(async () => new Response('upstream unavailable', { status: 503 })) as unknown as typeof fetch;
		},
	},
	{
		label: 'the DoH fetch rejects with a network error',
		install: () => {
			globalThis.fetch = vi.fn(async () => {
				throw new TypeError('Network connection lost');
			}) as unknown as typeof fetch;
		},
	},
	{
		label: 'the DoH fetch times out',
		install: () => {
			// The DOMException `AbortSignal.timeout` produces in the runtime.
			globalThis.fetch = vi.fn(async () => {
				throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
			}) as unknown as typeof fetch;
		},
	},
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
