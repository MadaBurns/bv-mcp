// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect } from 'vitest';
import {
	DEFAULT_SCAN_CANARY_DOMAIN,
	SCAN_CANARY_PAGE_AFTER,
	assessScanCanary,
	isScanCanaryEnabled,
	nextScanCanaryState,
	parseFailureCount,
	resolveScanCanaryDomain,
	runScanCanary,
} from '../../src/lib/scan-canary';
import type { ScanCanaryOutcome } from '../../src/lib/scan-canary';
import { EVIDENCE_SUFFICIENCY_THRESHOLD } from '../../src/lib/scoring';

type Returned = Extract<ScanCanaryOutcome, { status: 'returned' }>['result'];

/** A scan result shaped like a healthy graded one; override only what a case varies. */
function scanResult(overrides: { resolves?: boolean | 'broken'; score?: Record<string, unknown> } = {}): Returned {
	return {
		resolves: overrides.resolves,
		score: {
			overall: 81,
			grade: 'B',
			categoryScores: {},
			findings: [],
			summary: '',
			evidence: { attempted: 19, completed: 19, ratio: 1 },
			...overrides.score,
		},
	} as unknown as Returned;
}

describe('assessScanCanary — health predicate', () => {
	it.each<[string, ScanCanaryOutcome, boolean, string]>([
		['healthy scan', { status: 'returned', result: scanResult() }, true, 'ok'],
		[
			'a low score is still healthy (posture is not asserted)',
			{ status: 'returned', result: scanResult({ score: { overall: 12, grade: 'F' } }) },
			true,
			'ok',
		],
		['throw', { status: 'threw', error: new Error('resolver transport down') }, false, 'threw'],
		['timeout', { status: 'timeout' }, false, 'timeout'],
		[
			'ungraded (null overall/grade, evidenceInsufficient)',
			{ status: 'returned', result: scanResult({ score: { overall: null, grade: null, evidenceInsufficient: true } }) },
			false,
			'ungraded',
		],
		['apex did not resolve', { status: 'returned', result: scanResult({ resolves: false }) }, false, 'unresolved'],
		['apex SERVFAIL', { status: 'returned', result: scanResult({ resolves: 'broken' }) }, false, 'unresolved'],
		[
			'graded but evidence below the engine threshold',
			{ status: 'returned', result: scanResult({ score: { evidence: { attempted: 19, completed: 10, ratio: 10 / 19 } } }) },
			false,
			'insufficient_evidence',
		],
		[
			'missing evidence block',
			{ status: 'returned', result: scanResult({ score: { evidence: undefined } }) },
			false,
			'insufficient_evidence',
		],
	])('%s', (_name, outcome, healthy, reason) => {
		const a = assessScanCanary(outcome);
		expect(a.healthy).toBe(healthy);
		expect(a.reason).toBe(reason);
	});

	it('accepts a ratio exactly at the engine threshold (imported, not copied)', () => {
		const ratio = EVIDENCE_SUFFICIENCY_THRESHOLD;
		const a = assessScanCanary({ status: 'returned', result: scanResult({ score: { evidence: { attempted: 10, completed: 6, ratio } } }) });
		expect(a.healthy).toBe(true);
	});

	it('bounds and flattens thrown error text', () => {
		const a = assessScanCanary({ status: 'threw', error: new Error(`line1\n${'x'.repeat(500)}`) });
		expect(a.detail).not.toContain('\n');
		expect(a.detail!.length).toBeLessThanOrEqual(200);
	});
});

describe('nextScanCanaryState — consecutive-failure counter', () => {
	it('first unhealthy run counts but does not page', () => {
		expect(nextScanCanaryState(0, false)).toEqual({ failures: 1, page: false, recover: false });
	});
	it(`the ${SCAN_CANARY_PAGE_AFTER}nd consecutive unhealthy run pages`, () => {
		expect(nextScanCanaryState(1, false)).toEqual({ failures: 2, page: true, recover: false });
	});
	it('later unhealthy runs stay page-worthy (suppression is the repeat-alert helper job)', () => {
		expect(nextScanCanaryState(2, false)).toMatchObject({ failures: 3, page: true });
	});
	it('healthy after a page recovers and clears the counter', () => {
		expect(nextScanCanaryState(2, true)).toEqual({ failures: 0, page: false, recover: true });
	});
	it('healthy after a single blip clears the counter silently', () => {
		expect(nextScanCanaryState(1, true)).toEqual({ failures: 0, page: false, recover: false });
	});
	it('parseFailureCount treats junk as no history', () => {
		expect(parseFailureCount(null)).toBe(0);
		expect(parseFailureCount('abc')).toBe(0);
		expect(parseFailureCount('-3')).toBe(0);
		expect(parseFailureCount('2')).toBe(2);
	});
});

describe('config resolution', () => {
	it('defaults to a non-Cloudflare control domain', () => {
		expect(resolveScanCanaryDomain(undefined)).toBe(DEFAULT_SCAN_CANARY_DOMAIN);
		expect(resolveScanCanaryDomain('  ')).toBe(DEFAULT_SCAN_CANARY_DOMAIN);
	});
	it('honours a valid override, normalised', () => {
		expect(resolveScanCanaryDomain(' NIC.CZ ')).toBe('nic.cz');
	});
	it('falls back to the default for an invalid override', () => {
		expect(resolveScanCanaryDomain('localhost')).toBe(DEFAULT_SCAN_CANARY_DOMAIN);
		expect(resolveScanCanaryDomain('not a domain')).toBe(DEFAULT_SCAN_CANARY_DOMAIN);
	});
	it('only the literal string false disables the canary', () => {
		expect(isScanCanaryEnabled('false')).toBe(false);
		expect(isScanCanaryEnabled(' FALSE ')).toBe(false);
		expect(isScanCanaryEnabled(undefined)).toBe(true);
		expect(isScanCanaryEnabled('true')).toBe(true);
		expect(isScanCanaryEnabled('0')).toBe(true);
	});
});

describe('runScanCanary', () => {
	it('runs ONE cache-bypassing scan with no KV and returns its result', async () => {
		const calls: unknown[][] = [];
		const { outcome } = await runScanCanary('isc.org', {
			scan: async (...args) => {
				calls.push(args);
				return scanResult() as never;
			},
		});
		expect(outcome.status).toBe('returned');
		expect(calls).toHaveLength(1);
		const [domain, kv, opts] = calls[0] as [string, unknown, { forceRefresh?: boolean; profileAccumulator?: unknown }];
		expect(domain).toBe('isc.org');
		expect(kv).toBeUndefined();
		expect(opts.forceRefresh).toBe(true);
		expect(opts.profileAccumulator).toBeUndefined();
	});

	it('reports a rejected scan as threw', async () => {
		const { outcome } = await runScanCanary('isc.org', {
			scan: async () => {
				throw new Error('boom');
			},
		});
		expect(outcome.status).toBe('threw');
	});

	it('reports a synchronous throw as threw', async () => {
		const { outcome } = await runScanCanary('isc.org', {
			scan: () => {
				throw new Error('sync boom');
			},
		});
		expect(outcome.status).toBe('threw');
	});

	it('reports a hung scan as timeout and aborts its signal', async () => {
		let signal: AbortSignal | undefined;
		const { outcome, durationMs } = await runScanCanary('isc.org', {
			timeoutMs: 30,
			scan: (_d, _kv, opts) => {
				signal = opts?.signal;
				return new Promise(() => undefined);
			},
		});
		expect(outcome.status).toBe('timeout');
		expect(signal?.aborted).toBe(true);
		expect(durationMs).toBeLessThan(2000);
	});

	it('does not leak an unhandled rejection when the scan rejects after the timeout', async () => {
		const { outcome } = await runScanCanary('isc.org', {
			timeoutMs: 10,
			scan: () => new Promise((_resolve, reject) => setTimeout(() => reject(new Error('late')), 40)),
		});
		expect(outcome.status).toBe('timeout');
		await new Promise((r) => setTimeout(r, 80)); // an unhandled rejection would fail the run
	});
});
