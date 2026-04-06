// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Mock fetch to return different responses based on the queried domain name.
 * Covers the parallel checks that scan_domain runs.
 */
function mockScanResponses(options: { hasSpf?: boolean; hasDmarc?: boolean; hasDkim?: boolean } = {}) {
	const { hasSpf = true, hasDmarc = true, hasDkim = true } = options;

	globalThis.fetch = vi.fn().mockImplementation((url: string | URL | Request) => {
		const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
		const u = new URL(urlStr);

		// DoH requests
		if (u.hostname.includes('cloudflare-dns') || u.hostname.includes('dns.google')) {
			const name = u.searchParams.get('name') ?? '';
			const type = Number(u.searchParams.get('type') ?? '0');

			// TXT records
			if (type === 16) {
				if (name === 'example.com') {
					const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
					if (hasSpf) records.push({ name, type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com -all"' });
					return Promise.resolve(createDohResponse([{ name, type }], records));
				}
				if (name === '_dmarc.example.com') {
					const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
					if (hasDmarc) records.push({ name, type: 16, TTL: 300, data: '"v=DMARC1; p=none; rua=mailto:dmarc@example.com"' });
					return Promise.resolve(createDohResponse([{ name, type }], records));
				}
				if (name.includes('_domainkey')) {
					const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
					if (hasDkim) records.push({ name, type: 16, TTL: 300, data: '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"' });
					return Promise.resolve(createDohResponse([{ name, type }], records));
				}
				if (name === '_mta-sts.example.com') {
					return Promise.resolve(createDohResponse([{ name, type }], []));
				}
				if (name === '_smtp._tls.example.com') {
					return Promise.resolve(createDohResponse([{ name, type }], []));
				}
				// Default: empty TXT
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// MX records
			if (type === 15) {
				return Promise.resolve(createDohResponse([{ name, type }], [
					{ name, type: 15, TTL: 300, data: '10 mail.example.com.' },
				]));
			}
			// NS records
			if (type === 2) {
				return Promise.resolve(createDohResponse([{ name, type }], [
					{ name, type: 2, TTL: 300, data: 'ns1.example.com.' },
					{ name, type: 2, TTL: 300, data: 'ns2.example.com.' },
				]));
			}
			// A records
			if (type === 1) {
				return Promise.resolve(createDohResponse([{ name, type }], [
					{ name, type: 1, TTL: 300, data: '93.184.216.34' },
				]));
			}
			// AAAA
			if (type === 28) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// CNAME
			if (type === 5) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// DNSKEY
			if (type === 48) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// DS
			if (type === 43) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// CAA
			if (type === 257) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// TLSA
			if (type === 52) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// SOA
			if (type === 6) {
				return Promise.resolve(createDohResponse([{ name, type }], [
					{ name, type: 6, TTL: 300, data: 'ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400' },
				]));
			}
			// SRV
			if (type === 33) {
				return Promise.resolve(createDohResponse([{ name, type }], []));
			}
			// Default: empty
			return Promise.resolve(createDohResponse([{ name, type }], []));
		}

		// HTTPS fetch (SSL check, MTA-STS policy, HTTP security headers)
		if (urlStr.startsWith('https://')) {
			return Promise.resolve({
				ok: true,
				status: 200,
				headers: new Headers({
					'content-type': 'text/plain',
				}),
				text: () => Promise.resolve(''),
				json: () => Promise.resolve({}),
			} as unknown as Response);
		}

		return Promise.resolve(createDohResponse([], []));
	});
}

describe('generateFixPlan', () => {
	async function run(domain = 'example.com', options?: { hasSpf?: boolean; hasDmarc?: boolean; hasDkim?: boolean }) {
		mockScanResponses(options);
		const { generateFixPlan } = await import('../src/tools/generate-fix-plan');
		return generateFixPlan(domain);
	}

	it('returns a fix plan with domain and score', async () => {
		const plan = await run();
		expect(plan.domain).toBe('example.com');
		expect(plan.score).toBeGreaterThanOrEqual(0);
		expect(plan.score).toBeLessThanOrEqual(100);
		expect(plan.grade).toBeDefined();
		expect(plan.maturityStage).toBeGreaterThanOrEqual(0);
		expect(plan.maturityStage).toBeLessThanOrEqual(4);
		expect(plan.totalActions).toBe(plan.actions.length);
	});

	it('produces more actions when email auth is missing', async () => {
		const planWithAuth = await run('example.com', { hasSpf: true, hasDmarc: true, hasDkim: true });
		const planWithoutAuth = await run('example.com', { hasSpf: false, hasDmarc: false, hasDkim: false });
		expect(planWithoutAuth.totalActions).toBeGreaterThanOrEqual(planWithAuth.totalActions);
	});

	it('sorts actions by priority descending', async () => {
		const plan = await run('example.com', { hasSpf: false, hasDmarc: false });
		if (plan.actions.length > 1) {
			for (let i = 1; i < plan.actions.length; i++) {
				expect(plan.actions[i - 1].priority).toBeGreaterThanOrEqual(plan.actions[i].priority);
			}
		}
	});

	it('actions have required fields', async () => {
		const plan = await run('example.com', { hasSpf: false });
		for (const action of plan.actions) {
			expect(action.category).toBeDefined();
			expect(action.action).toBeDefined();
			expect(action.severity).toBeDefined();
			expect(['low', 'medium', 'high']).toContain(action.effort);
			expect(['critical', 'high', 'medium', 'low']).toContain(action.impact);
			expect(action.dependencies).toBeInstanceOf(Array);
			expect(action.findingTitle).toBeDefined();
		}
	});
});

describe('formatFixPlan', () => {
	it('formats a plan as readable text', async () => {
		mockScanResponses({ hasSpf: false, hasDmarc: false });
		const { generateFixPlan, formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const plan = await generateFixPlan('example.com');
		const text = formatFixPlan(plan);
		expect(text).toContain('Fix Plan: example.com');
		expect(text).toContain('Score:');
		expect(text).toContain('action');
	});

	it('shows "no actionable findings" for clean domain', async () => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const text = formatFixPlan({
			domain: 'clean.com',
			score: 95,
			grade: 'A+',
			maturityStage: 4,
			totalActions: 0,
			actions: [],
		});
		expect(text).toContain('No actionable findings');
	});

	it('compact mode uses one-liners and caps at 5 actions', async () => {
		const { formatFixPlan } = await import('../src/tools/generate-fix-plan');
		const actions = Array.from({ length: 7 }, (_, i) => ({
			category: 'spf' as const,
			severity: 'high' as const,
			action: `Action ${i + 1}`,
			effort: 'low' as const,
			impact: 'high' as const,
			dependencies: ['dep'],
		}));
		const compact = formatFixPlan({ domain: 'test.com', score: 30, grade: 'F', maturityStage: 0, totalActions: 7, actions }, 'compact');
		const full = formatFixPlan({ domain: 'test.com', score: 30, grade: 'F', maturityStage: 0, totalActions: 7, actions }, 'full');
		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('Fix Plan: test.com');
		expect(compact).toContain('7 actions');
		expect(compact).toContain('Action 5');
		expect(compact).not.toContain('Action 6');
		expect(compact).toContain('... and 2 more');
		expect(compact).not.toContain('##');
		expect(compact).not.toContain('Dependencies');
	});
});
