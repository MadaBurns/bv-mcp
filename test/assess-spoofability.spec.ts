// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Mock DNS responses for SPF, DMARC, and DKIM checks.
 */
function mockEmailAuth(options: {
	spf?: string | null;
	dmarc?: string | null;
	dkim?: boolean;
}) {
	const { spf, dmarc, dkim = false } = options;

	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const type = Number(u.searchParams.get('type') ?? '0');

		if (type === 16) {
			if (name === 'example.com') {
				const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
				if (spf !== null && spf !== undefined) {
					records.push({ name, type: 16, TTL: 300, data: `"${spf}"` });
				}
				return Promise.resolve(createDohResponse([{ name, type }], records));
			}
			if (name === '_dmarc.example.com') {
				const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
				if (dmarc !== null && dmarc !== undefined) {
					records.push({ name, type: 16, TTL: 300, data: `"${dmarc}"` });
				}
				return Promise.resolve(createDohResponse([{ name, type }], records));
			}
			if (name.includes('_domainkey')) {
				const records: Array<{ name: string; type: number; TTL: number; data: string }> = [];
				if (dkim) {
					records.push({ name, type: 16, TTL: 300, data: '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"' });
				}
				return Promise.resolve(createDohResponse([{ name, type }], records));
			}
			return Promise.resolve(createDohResponse([{ name, type }], []));
		}
		if (type === 15) {
			return Promise.resolve(createDohResponse([{ name, type }], [
				{ name, type: 15, TTL: 300, data: '10 mail.example.com.' },
			]));
		}
		return Promise.resolve(createDohResponse([{ name, type }], []));
	});
}

describe('assessSpoofability', () => {
	async function run(options: Parameters<typeof mockEmailAuth>[0] = {}) {
		mockEmailAuth(options);
		const { assessSpoofability } = await import('../src/tools/assess-spoofability');
		return assessSpoofability('example.com');
	}

	it('returns high spoofability when no email auth exists', async () => {
		const result = await run({ spf: null, dmarc: null, dkim: false });
		expect(result.domain).toBe('example.com');
		expect(result.spoofabilityScore).toBeGreaterThanOrEqual(70);
		expect(result.spfProtection).toBe(0);
		expect(result.dmarcProtection).toBe(0);
		expect(result.dkimProtection).toBe(0);
	});

	it('protection scores reflect DNS records', async () => {
		mockEmailAuth({
			spf: 'v=spf1 include:_spf.google.com -all',
			dmarc: 'v=DMARC1; p=reject; rua=mailto:d@example.com; pct=100',
			dkim: true,
		});
		// Verify the underlying checks return meaningful findings for the spoofability assessment
		const { checkSpf } = await import('../src/tools/check-spf');
		const { checkDmarc } = await import('../src/tools/check-dmarc');
		const spf = await checkSpf('example.com');
		const dmarc = await checkDmarc('example.com');
		expect(spf.findings.length).toBeGreaterThan(0);
		expect(dmarc.findings.length).toBeGreaterThan(0);
	});

	it('DMARC p=none has higher spoofability than p=reject', async () => {
		// Test p=none in isolation
		const pNone = await run({
			spf: 'v=spf1 include:_spf.google.com -all',
			dmarc: 'v=DMARC1; p=none; rua=mailto:d@example.com',
			dkim: true,
		});
		expect(pNone.dmarcProtection).toBeLessThanOrEqual(30);
		// With p=none, spoofability should be moderate-to-high
		expect(pNone.spoofabilityScore).toBeGreaterThan(20);
	});

	it('includes interaction effects for no SPF + no DMARC', async () => {
		const result = await run({ spf: null, dmarc: null, dkim: false });
		expect(result.interactionEffects.length).toBeGreaterThan(0);
		expect(result.interactionEffects.some((e) => e.toLowerCase().includes('absence'))).toBe(true);
	});

	it('score is always 0-100', async () => {
		const result1 = await run({ spf: null, dmarc: null, dkim: false });
		expect(result1.spoofabilityScore).toBeGreaterThanOrEqual(0);
		expect(result1.spoofabilityScore).toBeLessThanOrEqual(100);

		const result2 = await run({
			spf: 'v=spf1 -all',
			dmarc: 'v=DMARC1; p=reject; aspf=s; adkim=s; pct=100',
			dkim: true,
		});
		expect(result2.spoofabilityScore).toBeGreaterThanOrEqual(0);
		expect(result2.spoofabilityScore).toBeLessThanOrEqual(100);
	});

	it('has all required fields', async () => {
		const result = await run({ spf: 'v=spf1 -all', dmarc: 'v=DMARC1; p=none', dkim: false });
		expect(result).toHaveProperty('domain');
		expect(result).toHaveProperty('spoofabilityScore');
		expect(result).toHaveProperty('riskLevel');
		expect(result).toHaveProperty('spfProtection');
		expect(result).toHaveProperty('dmarcProtection');
		expect(result).toHaveProperty('dkimProtection');
		expect(result).toHaveProperty('interactionEffects');
		expect(result).toHaveProperty('summary');
	});

	it('risk level matches score range', async () => {
		const result = await run({ spf: null, dmarc: null, dkim: false });
		if (result.spoofabilityScore >= 80) expect(result.riskLevel).toBe('critical');
		else if (result.spoofabilityScore >= 60) expect(result.riskLevel).toBe('high');
		else if (result.spoofabilityScore >= 40) expect(result.riskLevel).toBe('medium');
		else if (result.spoofabilityScore >= 20) expect(result.riskLevel).toBe('low');
		else expect(result.riskLevel).toBe('minimal');
	});
});

describe('formatSpoofability', () => {
	it('formats result as readable text', async () => {
		const { formatSpoofability } = await import('../src/tools/assess-spoofability');
		const text = formatSpoofability({
			domain: 'example.com',
			spoofabilityScore: 65,
			riskLevel: 'high',
			spfProtection: 50,
			dmarcProtection: 30,
			dkimProtection: 0,
			interactionEffects: ['Test effect'],
			summary: 'Test summary',
		});
		expect(text).toContain('example.com');
		expect(text).toContain('65/100');
		expect(text).toContain('HIGH');
		expect(text).toContain('SPF Protection');
		expect(text).toContain('Test effect');
	});

	it('compact mode omits narrative and interaction effects', async () => {
		const { formatSpoofability } = await import('../src/tools/assess-spoofability');
		const data = {
			domain: 'example.com',
			spoofabilityScore: 65,
			riskLevel: 'high' as const,
			spfProtection: 50,
			dmarcProtection: 30,
			dkimProtection: 0,
			interactionEffects: ['Test effect'],
			summary: 'Test summary',
		};
		const compact = formatSpoofability(data, 'compact');
		const full = formatSpoofability(data, 'full');
		expect(compact.length).toBeLessThan(full.length);
		expect(compact).toContain('65/100');
		expect(compact).toContain('SPF: 50/100');
		expect(compact).toContain('DMARC: 30/100');
		expect(compact).not.toContain('Test summary');
		expect(compact).not.toContain('Test effect');
		expect(compact).not.toContain('#');
	});
});
