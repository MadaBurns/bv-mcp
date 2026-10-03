// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse, servfailResponse } from './helpers/dns-mock';

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
		const ip = callCount % 2 === 0 ? '192.0.2.1' : '5.6.7.8';
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

	it('returns CheckResult with resolver_consistency category', async () => {
		mockConsistentDns();
		const result = await run();
		expect(result.category).toBe('resolver_consistency');
		expect(result.findings).toBeInstanceOf(Array);
		expect(result.findings.length).toBeGreaterThan(0);
	});

	it('labels every finding with the resolver_consistency category', async () => {
		mockConsistentDns();
		const result = await run();
		expect(result.findings.length).toBeGreaterThan(0);
		for (const finding of result.findings) {
			expect(finding.category).toBe('resolver_consistency');
		}
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

describe('checkResolverConsistency — resolvers that never answered (T6 item 6)', () => {
	async function run(domain = 'example.com', recordType?: string) {
		const { checkResolverConsistency } = await import('../src/tools/check-resolver-consistency');
		return checkResolverConsistency(domain, recordType);
	}

	it('abstains when every resolver SERVFAILs instead of reporting consistent records', async () => {
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			return Promise.resolve(servfailResponse(u.searchParams.get('name') ?? 'example.com', 1));
		});

		const result = await run('example.com', 'A');

		expect(result.findings.some((f) => f.title === 'A records consistent')).toBe(false);
		expect(result.findings.some((f) => f.detail.includes('agree'))).toBe(false);
		expect(result.checkStatus).toBe('error');
		expect(result.passed).toBe(false);
		expect(result.score).toBe(0);
		expect(result.partial).toBe(true);
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
	});

	it('does not abstain the whole check when only some record types lack a resolver quorum', async () => {
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			const name = u.searchParams.get('name') ?? 'example.com';
			if (u.searchParams.get('type') === 'MX') return Promise.resolve(servfailResponse(name, 15));
			return Promise.resolve(createDohResponse([{ name, type: 1 }], []));
		});

		const result = await run('example.com');

		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.title === 'MX records consistent')).toBe(false);
		expect(result.findings.some((f) => f.title === 'MX records incomplete across resolvers')).toBe(true);
		// A degraded type means a degraded fan-out: not cacheable.
		expect(result.partial).toBe(true);
	});
});

describe('checkResolverConsistency — fan-out coverage and quorum (#1199)', () => {
	async function load() {
		return import('../src/tools/check-resolver-consistency');
	}

	/** Cloudflare + Google answer `answers`; Quad9 + OpenDNS are unreachable. */
	function mockTwoOfFour(cloudflare: string, google: string) {
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const urlStr = typeof url === 'string' ? url : url.toString();
			const isCloudflare = urlStr.includes('cloudflare');
			if (!isCloudflare && !urlStr.includes('dns.google')) return Promise.reject(new Error('unreachable'));
			const name = new URL(urlStr).searchParams.get('name') ?? 'example.com';
			const data = isCloudflare ? cloudflare : google;
			return Promise.resolve(createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data }]));
		});
	}

	it('below-quorum unanimous answers: INCOMPLETE low finding, coverage metadata, partial: true', async () => {
		mockTwoOfFour('192.0.2.1', '192.0.2.1');
		const { checkResolverConsistency } = await load();

		const result = await checkResolverConsistency('example.com', 'A');

		expect(result.findings).toHaveLength(1);
		const finding = result.findings[0];
		expect(finding.title).toBe('A records incomplete across resolvers');
		expect(finding.severity).toBe('low');
		expect(finding.metadata).toMatchObject({
			status: 'INCOMPLETE',
			resolversQueried: 4,
			respondedCount: 2,
			unreachableResolvers: ['Quad9', 'OpenDNS'],
			quorum: 3,
			quorumMet: false,
		});
		expect(result.partial).toBe(true);
		// Not the all-abstain path: 2 answered, so the check is still a measurement.
		expect(result.checkStatus).toBeUndefined();
	});

	it('full fan-out: coverage on the CONSISTENT finding, resolverCount kept, not partial', async () => {
		mockConsistentDns();
		const { checkResolverConsistency } = await load();

		const result = await checkResolverConsistency('example.com', 'A');

		expect(result.findings[0].metadata).toMatchObject({
			status: 'CONSISTENT',
			resolverCount: 4,
			resolversQueried: 4,
			respondedCount: 4,
			unreachableResolvers: [],
			quorum: 3,
			quorumMet: true,
		});
		expect(result.partial).toBeUndefined();
	});

	it('divergent answers carry coverage on the SPLIT_HORIZON finding', async () => {
		mockTwoOfFour('192.0.2.1', '198.51.100.7');
		const { checkResolverConsistency } = await load();

		const result = await checkResolverConsistency('example.com', 'A');

		expect(result.findings[0].metadata).toMatchObject({ status: 'SPLIT_HORIZON', respondedCount: 2, quorumMet: false });
		expect(result.partial).toBe(true);
	});

	it('full format prints answered N/M per type', async () => {
		mockTwoOfFour('192.0.2.1', '192.0.2.1');
		const { checkResolverConsistency, formatResolverConsistency } = await load();

		const text = formatResolverConsistency(await checkResolverConsistency('example.com', 'A'));

		expect(text).toContain('answered 2/4');
	});
});
