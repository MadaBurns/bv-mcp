// SPDX-License-Identifier: BUSL-1.1

import fixture from '../fixtures/characterization-scan-results.json';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { IN_MEMORY_CACHE } from '../../src/lib/cache';
import { parseTenantScanSnapshot, toTenantScanSnapshot } from '../../src/tenants/scan-snapshot';
import type { ScanDomainResult } from '../../src/tools/scan-domain';
import { txtResponse } from '../helpers/dns-mock';

function mockDns(domain: string): void {
	globalThis.fetch = vi.fn().mockResolvedValue(txtResponse(domain, ['v=spf1 -all']));
}

async function captureScan(domain: string): Promise<ScanDomainResult> {
	let captured: ScanDomainResult | undefined;
	const { handleToolsCall } = await import('../../src/handlers/tools');
	await handleToolsCall(
		{ name: 'scan_domain', arguments: { domain } },
		undefined,
		{ scanResultCapture: (result) => (captured = result) },
	);
	expect(captured).toBeDefined();
	return captured!;
}

afterEach(() => {
	IN_MEMORY_CACHE.clear();
	vi.restoreAllMocks();
});

describe('scan-domain public result characterization', () => {
	it('keeps the successful public result shape used by callers and tenant persistence', async () => {
		const expected = fixture.success;
		mockDns(expected.domain);

		const result = await captureScan(expected.domain);
		expect(result).toMatchObject({ domain: expected.domain, cached: expected.cached });
		expect(typeof result.score.overall).toBe(expected.score.overall);
		expect(typeof result.score.grade).toBe(expected.score.grade);
		expect(Array.isArray(result.score.findings)).toBe(true);
		expect(Array.isArray(result.checks)).toBe(true);

		const snapshot = toTenantScanSnapshot(result);
		expect(parseTenantScanSnapshot(JSON.stringify(snapshot))).toEqual(snapshot);
	});

	it('preserves null score and grade for inconclusive scans rather than manufacturing a failure', () => {
		const expected = fixture.inconclusive;
		const result = {
			domain: expected.domain,
			score: { overall: expected.score.overall, grade: expected.score.grade, categoryScores: {}, findings: expected.findings, summary: 'not measured' },
			checks: [],
			maturity: expected.maturity,
		} as unknown as ScanDomainResult;

		expect(toTenantScanSnapshot(result)).toMatchObject({ score: null, grade: null, maturityStage: null, findings: [] });
	});

	it('marks a repeated public scan as a cache hit without changing its result contract', async () => {
		const expected = fixture.cacheHit;
		mockDns(expected.domain);

		await captureScan(expected.domain);
		const cached = await captureScan(expected.domain);
		expect(cached).toMatchObject({ domain: expected.domain, cached: expected.cached });
		expect(typeof cached.score.overall).toBe('number');
		expect(typeof cached.score.grade).toBe('string');
	});
});
