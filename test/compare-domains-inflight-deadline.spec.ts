// SPDX-License-Identifier: BUSL-1.1

// SQ-291 item 4 — the deadline must bound a scan that is ALREADY running, not only gate the
// start of the next one; otherwise a scan begun near the budget outlives the handler's 28s
// tool timeout and every finished comparison is discarded.

import { describe, it, expect, vi } from 'vitest';
import { compareDomains } from '../src/tools/compare-domains';

type ScanFn = typeof import('../src/tools/scan-domain').scanDomain;

/** Minimal scan result accepted by buildStructuredScanResult-compatible stubs. */
async function fastScanResult(domain: string) {
	const { scanDomain } = await import('../src/tools/scan-domain');
	// Reuse a real shape by scanning nothing: the stub below only needs fields buildStructuredScanResult reads.
	void scanDomain;
	return {
		domain,
		score: { overall: 90, grade: 'A', categoryScores: { spf: 100 }, findings: [], summary: '' },
		checks: [{ category: 'spf', passed: true, score: 100, findings: [] }],
		maturity: { stage: 3, label: 'x', description: 'x', nextStep: null },
		context: { profile: 'mail_enabled', signals: [] },
		cached: false,
		timestamp: '2026-10-03T00:00:00.000Z',
	};
}

describe('SQ-291 compareDomains — in-flight scans are bounded by the deadline', () => {
	it('a scan that hangs past the deadline is cut off, the finished comparison is kept, result is partial', async () => {
		const fast = await fastScanResult('fast.com');
		const scanFn = vi
			.fn()
			.mockResolvedValueOnce(fast)
			.mockImplementation(
				() =>
					new Promise(() => {
						/* never settles, ignores any signal */
					}),
			);

		const start = Date.now();
		const result = await compareDomains(['fast.com', 'hang.com'], {
			scanFn: scanFn as unknown as ScanFn,
			deadlineMs: Date.now() + 300,
		});
		const elapsed = Date.now() - start;

		expect(scanFn).toHaveBeenCalledTimes(2); // the hang started inside the budget...
		expect(elapsed).toBeLessThan(3_000); // ...and was cut off by it, not left to the 28s race
		expect(result.partial).toBe(true);
		expect(result.errors?.['hang.com']).toBe('budget_exceeded');
		expect(result.errors?.['fast.com']).toBeUndefined();
		expect(result.domains).toContain('fast.com');
	});

	it('forwards an abort signal into each scan via runtimeOptions.signal', async () => {
		const fast = await fastScanResult('a.com');
		const seen: Array<AbortSignal | undefined> = [];
		const scanFn = vi.fn().mockImplementation((_d: string, _kv: unknown, rt?: { signal?: AbortSignal }) => {
			seen.push(rt?.signal);
			return Promise.resolve(fast);
		});
		await compareDomains(['a.com', 'b.com'], {
			scanFn: scanFn as unknown as ScanFn,
			deadlineMs: Date.now() + 5_000,
		});
		expect(seen).toHaveLength(2);
		for (const s of seen) {
			expect(s).toBeInstanceOf(AbortSignal);
			expect(s?.aborted).toBe(false);
		}
	});

	it('an already-aborted caller signal stops the loop before any scan starts', async () => {
		const scanFn = vi.fn();
		const result = await compareDomains(['a.com', 'b.com'], {
			scanFn: scanFn as unknown as ScanFn,
			signal: AbortSignal.abort(),
		});
		expect(scanFn).not.toHaveBeenCalled();
		expect(result.partial).toBe(true);
		expect(result.errors?.['a.com']).toBe('budget_exceeded');
	});

	it('control: a scan that finishes inside the budget is not marked partial', async () => {
		const fast = await fastScanResult('ok.com');
		const scanFn = vi.fn().mockResolvedValue(fast);
		const result = await compareDomains(['ok.com', 'ok2.com'], {
			scanFn: scanFn as unknown as ScanFn,
			deadlineMs: Date.now() + 5_000,
		});
		expect(result.partial).toBeUndefined();
		expect(result.errors).toEqual({});
	});
});
