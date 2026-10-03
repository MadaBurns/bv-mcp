// SPDX-License-Identifier: BUSL-1.1

// SQ-291 item 1 — unmeasured vectors are never "all blocked" / low risk.

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

const CHECK_MODULES: Array<[string, string]> = [
	['../src/tools/check-spf', 'checkSpf'],
	['../src/tools/check-dmarc', 'checkDmarc'],
	['../src/tools/check-dkim', 'checkDkim'],
	['../src/tools/check-dnssec', 'checkDnssec'],
	['../src/tools/check-ssl', 'checkSsl'],
	['../src/tools/check-mta-sts', 'checkMtaSts'],
	['../src/tools/check-caa', 'checkCaa'],
	['../src/tools/check-http-security', 'checkHttpSecurity'],
	['../src/tools/check-dane', 'checkDane'],
	['../src/tools/check-subdomain-takeover', 'checkSubdomainTakeover'],
];

afterEach(() => {
	for (const [path] of CHECK_MODULES) vi.doUnmock(path);
	vi.resetModules();
	restore();
});

function resultWith(checkStatus?: 'timeout' | 'error') {
	return {
		category: 'spf',
		passed: !checkStatus,
		score: checkStatus ? 0 : 100,
		findings: [],
		...(checkStatus ? { checkStatus, partial: true } : {}),
	};
}

function mockChecks(impl: (fn: string) => () => Promise<unknown>) {
	globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(createDohResponse([], [])));
	for (const [path, fn] of CHECK_MODULES) vi.doMock(path, () => ({ [fn]: impl(fn) }));
}

describe('SQ-291 simulateAttackPaths — unmeasured inputs never read as low risk', () => {
	it('every check rejecting → not assessed (no low risk, no "all vectors blocked")', async () => {
		mockChecks(() => () => Promise.reject(new Error('boom')));
		const { simulateAttackPaths, formatAttackPaths } = await import('../src/tools/simulate-attack-paths');
		const result = await simulateAttackPaths('reject-sim-291.example');
		expect(result.overallRisk).toBeNull();
		expect(result.notAssessed?.reason).toBe('checks_unmeasured');
		expect(result.unmeasuredChecks).toHaveLength(10);
		for (const format of ['full', 'compact'] as const) {
			const text = formatAttackPaths(result, format);
			expect(text).toContain('Not assessed');
			expect(text).not.toMatch(/Overall Risk: LOW/);
			expect(text).not.toContain('blocked');
		}
	});

	it('every check timing out (checkStatus) → not assessed', async () => {
		mockChecks(() => () => Promise.resolve(resultWith('timeout')));
		const { simulateAttackPaths } = await import('../src/tools/simulate-attack-paths');
		const result = await simulateAttackPaths('timeout-sim-291.example');
		expect(result.overallRisk).toBeNull();
		expect(result.notAssessed?.reason).toBe('checks_unmeasured');
		expect(result.unmeasuredChecks?.every((c) => c.reason === 'timeout')).toBe(true);
	});

	it('some checks unmeasured and no feasible path → not low; unmeasured vectors are listed', async () => {
		mockChecks((fn) =>
			fn === 'checkSpf' || fn === 'checkDmarc' ? () => Promise.reject(new Error('boom')) : () => Promise.resolve(resultWith()),
		);
		const { simulateAttackPaths, formatAttackPaths } = await import('../src/tools/simulate-attack-paths');
		const result = await simulateAttackPaths('partial-sim-291.example');
		expect(result.totalPaths).toBe(0);
		expect(result.overallRisk).toBeNull();
		expect(result.unmeasuredChecks?.map((c) => c.check).sort()).toEqual(['dmarc', 'spf']);
		expect(formatAttackPaths(result, 'full')).not.toContain('All evaluated attack vectors are blocked');
	});

	it('control: every check measured clean → still low with all vectors blocked', async () => {
		mockChecks(() => () => Promise.resolve(resultWith()));
		const { simulateAttackPaths, formatAttackPaths } = await import('../src/tools/simulate-attack-paths');
		const result = await simulateAttackPaths('clean-sim-291.example');
		expect(result.overallRisk).toBe('low');
		expect(result.unmeasuredChecks).toBeUndefined();
		expect(formatAttackPaths(result, 'full')).toContain('All evaluated attack vectors are blocked');
	});
});
