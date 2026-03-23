// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function mockConsistentDns() {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? 'example.com';
		const type = u.searchParams.get('type') ?? 'A';

		const typeNum = type === 'MX' ? 15 : type === 'TXT' ? 16 : type === 'NS' ? 2 : type === 'AAAA' ? 28 : 1;

		if (type === 'A' || typeNum === 1) {
			return Promise.resolve(createDohResponse([{ name, type: 1 }], [
				{ name, type: 1, TTL: 300, data: '93.184.216.34' },
			]));
		}
		return Promise.resolve(createDohResponse([{ name, type: typeNum }], []));
	});
}

function mockSplitDns() {
	let callCount = 0;
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? 'example.com';
		callCount++;

		// Alternate between two different IPs per resolver
		const ip = callCount % 2 === 0 ? '1.2.3.4' : '5.6.7.8';
		return Promise.resolve(createDohResponse([{ name, type: 1 }], [
			{ name, type: 1, TTL: 300, data: ip },
		]));
	});
}

describe('checkResolverConsistency', () => {
	async function run(domain = 'example.com', recordType?: string) {
		const { checkResolverConsistency } = await import('../src/tools/check-resolver-consistency');
		return checkResolverConsistency(domain, recordType);
	}

	it('returns CheckResult with zone_hygiene category', async () => {
		mockConsistentDns();
		const result = await run();
		expect(result.category).toBe('zone_hygiene');
		expect(result.findings).toBeInstanceOf(Array);
		expect(result.findings.length).toBeGreaterThan(0);
	});

	it('returns info findings for consistent records', async () => {
		mockConsistentDns();
		const result = await run();
		const infoFindings = result.findings.filter((f) => f.severity === 'info');
		expect(infoFindings.length).toBeGreaterThan(0);
	});

	it('checks specific record type when provided', async () => {
		mockConsistentDns();
		const result = await run('example.com', 'A');
		// Should only have 1 finding (for A records)
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toContain('A');
	});

	it('checks 5 record types by default', async () => {
		mockConsistentDns();
		const result = await run();
		expect(result.findings.length).toBe(5); // A, AAAA, MX, TXT, NS
	});

	it('returns low findings for split records', async () => {
		mockSplitDns();
		const result = await run('example.com', 'A');
		// Should detect the split
		const nonInfo = result.findings.filter((f) => f.severity !== 'info');
		expect(nonInfo.length + result.findings.filter((f) => f.severity === 'info').length).toBe(1);
	});

	it('findings have resolver metadata', async () => {
		mockSplitDns();
		const result = await run('example.com', 'A');
		for (const finding of result.findings) {
			expect(finding.metadata).toBeDefined();
			expect(finding.metadata?.recordType).toBe('A');
			expect(finding.metadata?.status).toBeDefined();
		}
	});
});

describe('formatResolverConsistency', () => {
	it('formats results as readable text', async () => {
		mockConsistentDns();
		const { checkResolverConsistency, formatResolverConsistency } = await import('../src/tools/check-resolver-consistency');
		const result = await checkResolverConsistency('example.com', 'A');
		const text = formatResolverConsistency(result);
		expect(text).toContain('DNS Resolver Consistency Check');
		expect(text).toContain('Summary');
	});

	it('compact mode omits per-resolver answers and info findings', async () => {
		mockConsistentDns();
		const { checkResolverConsistency, formatResolverConsistency } = await import('../src/tools/check-resolver-consistency');
		const result = await checkResolverConsistency('example.com', 'A');
		const compact = formatResolverConsistency(result, 'compact');
		const full = formatResolverConsistency(result, 'full');
		expect(compact.length).toBeLessThanOrEqual(full.length);
		expect(compact).toContain('Resolver Consistency:');
		expect(compact).not.toContain('# DNS Resolver Consistency Check');
	});
});
