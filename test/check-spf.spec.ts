import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/**
 * Helper: set up fetch mock that responds to TXT queries based on domain.
 * Accepts a map of domain -> SPF/TXT records.
 * Falls back to empty answers for unmapped domains.
 */
function mockMultiDomainTxt(domainRecords: Record<string, string[]>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const records = domainRecords[name] ?? [];
		const answers = records.map((data) => ({
			name,
			type: 16,
			TTL: 300,
			data: `"${data}"`,
		}));
		return Promise.resolve(
			createDohResponse([{ name, type: 16 }], answers),
		);
	});
}

/** Simple single-domain TXT mock (matches original mockTxtRecords behavior) */
function mockTxtRecords(records: string[], domain = 'example.com') {
	mockMultiDomainTxt({ [domain]: records });
}

describe('checkSpf', () => {
	async function run(domain = 'example.com') {
		const { checkSpf } = await import('../src/tools/check-spf');
		return checkSpf(domain);
	}

	it('should return critical finding when no SPF record exists', async () => {
		mockTxtRecords([]);
		const result = await run();
		expect(result.category).toBe('spf');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('critical');
		expect(result.findings[0].title).toMatch(/No SPF/i);
	});

	it('should return high finding for multiple SPF records', async () => {
		mockTxtRecords(['v=spf1 -all', 'v=spf1 ~all']);
		const result = await run();
		const finding = result.findings.find((f) => /Multiple SPF/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
	});

	it('should return critical finding for +all', async () => {
		mockTxtRecords(['v=spf1 +all']);
		const result = await run();
		const finding = result.findings.find((f) => /Permissive/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return critical finding for ?all', async () => {
		mockTxtRecords(['v=spf1 ?all']);
		const result = await run();
		const finding = result.findings.find((f) => /Permissive/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	it('should return low finding for ~all (soft fail)', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com ~all']);
		const result = await run();
		const finding = result.findings.find((f) => /soft fail/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return info finding for -all (hard fail, best practice)', async () => {
		mockTxtRecords(['v=spf1 include:_spf.google.com -all']);
		const result = await run();
		// Trust surface analysis adds a medium finding for Google Workspace
		const trustFinding = result.findings.find((f) => /SPF delegates to shared platform/i.test(f.title));
		expect(trustFinding).toBeDefined();
		expect(trustFinding!.severity).toBe('medium');
		// SPF record configured info finding is still present (trust surface findings are not counted as issues)
		const infoFinding = result.findings.find((f) => /SPF record configured/i.test(f.title));
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.severity).toBe('info');
		expect(infoFinding!.metadata?.includeDomains).toContain('_spf.google.com');
	});

	it('handles case-insensitive SPF prefix', async () => {
		mockTxtRecords(['V=spf1 -all']);
		const r = await run();
		expect(r.findings).toHaveLength(1);
		expect(r.findings[0].severity).toBe('info');
	});

	it('detects exactly 10 DNS lookups as acceptable', async () => {
		const mechs = Array.from({ length: 10 }, (_, i) => `include:spf${i}.example.com`).join(' ');
		// Each included domain has no further lookups
		const domainMap: Record<string, string[]> = {
			'example.com': [`v=spf1 ${mechs} -all`],
		};
		for (let i = 0; i < 10; i++) {
			domainMap[`spf${i}.example.com`] = ['v=spf1 -all'];
		}
		mockMultiDomainTxt(domainMap);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Too many DNS'));
		expect(f).toBeUndefined();
	});

	it('flags 9 DNS lookups as near-limit high risk', async () => {
		const mechs = Array.from({ length: 9 }, (_, i) => `include:spf${i}.example.com`).join(' ');
		const domainMap: Record<string, string[]> = {
			'example.com': [`v=spf1 ${mechs} -all`],
		};
		for (let i = 0; i < 9; i++) {
			domainMap[`spf${i}.example.com`] = ['v=spf1 -all'];
		}
		mockMultiDomainTxt(domainMap);
		const r = await run();
		const f = r.findings.find((f) => /lookup budget near limit/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('counts mixed lookup mechanisms (include, a, mx, redirect)', async () => {
		const mechs =
			'include:a.com include:b.com include:c.com include:d.com include:e.com a:f.com mx:g.com redirect=h.com include:i.com include:j.com include:k.com';
		const domainMap: Record<string, string[]> = {
			'example.com': [`v=spf1 ${mechs} -all`],
		};
		// Each included domain resolves to a simple SPF
		for (const d of ['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'h.com', 'i.com', 'j.com', 'k.com']) {
			domainMap[d] = ['v=spf1 -all'];
		}
		mockMultiDomainTxt(domainMap);
		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Too many DNS'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
	});

	// ---- New tests for recursive include expansion ----

	it('counts recursive include lookups across nested SPF records', async () => {
		// example.com -> 3 includes, each with 3 more includes = 3 + 9 = 12 (top-level 3 + nested 3*3)
		mockMultiDomainTxt({
			'example.com': ['v=spf1 include:a.com include:b.com include:c.com -all'],
			'a.com': ['v=spf1 include:a1.com include:a2.com include:a3.com -all'],
			'b.com': ['v=spf1 include:b1.com include:b2.com include:b3.com -all'],
			'c.com': ['v=spf1 include:c1.com include:c2.com include:c3.com -all'],
			'a1.com': ['v=spf1 -all'],
			'a2.com': ['v=spf1 -all'],
			'a3.com': ['v=spf1 -all'],
			'b1.com': ['v=spf1 -all'],
			'b2.com': ['v=spf1 -all'],
			'b3.com': ['v=spf1 -all'],
			'c1.com': ['v=spf1 -all'],
			'c2.com': ['v=spf1 -all'],
			'c3.com': ['v=spf1 -all'],
		});

		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Too many DNS'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
		// Total: 3 (top-level includes) + 3*3 (nested includes) = 12
		expect(f!.metadata?.lookupCount).toBe(12);
	});

	it('detects circular SPF includes', async () => {
		mockMultiDomainTxt({
			'example.com': ['v=spf1 include:loop.com -all'],
			'loop.com': ['v=spf1 include:example.com -all'],
		});

		const r = await run();
		const f = r.findings.find((f) => /circular/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('does not flag missing all when redirect= is present (RFC 7208 §6.1)', async () => {
		mockMultiDomainTxt({
			'example.com': ['v=spf1 redirect=_spf.other.com'],
			'_spf.other.com': ['v=spf1 -all'],
		});

		const r = await run();
		const noAllFinding = r.findings.find((f) => /No 'all' mechanism/i.test(f.title));
		expect(noAllFinding).toBeUndefined();
	});

	it('detects overly broad IPv4 range (ip4:0.0.0.0/0)', async () => {
		mockTxtRecords(['v=spf1 ip4:0.0.0.0/0 -all']);
		const r = await run();
		const f = r.findings.find((f) => /Overly broad IP range/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('detects overly broad IPv4 range with small prefix', async () => {
		mockTxtRecords(['v=spf1 ip4:10.0.0.0/8 -all']);
		const r = await run();
		const f = r.findings.find((f) => /Overly broad IP range/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('does not flag ip4 with reasonable prefix length', async () => {
		mockTxtRecords(['v=spf1 ip4:192.168.1.0/24 -all']);
		const r = await run();
		const f = r.findings.find((f) => /Overly broad IP range/i.test(f.title));
		expect(f).toBeUndefined();
	});

	it('detects overly broad IPv6 range (ip6:::/0)', async () => {
		mockTxtRecords(['v=spf1 ip6:::/0 -all']);
		const r = await run();
		const f = r.findings.find((f) => /Overly broad IPv6 range/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('detects overly broad IPv6 range with small prefix', async () => {
		mockTxtRecords(['v=spf1 ip6:2001::/16 -all']);
		const r = await run();
		const f = r.findings.find((f) => /Overly broad IPv6 range/i.test(f.title));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('high');
	});

	it('does not flag ip6 with reasonable prefix length', async () => {
		mockTxtRecords(['v=spf1 ip6:2001:db8::/32 -all']);
		const r = await run();
		const f = r.findings.find((f) => /Overly broad IPv6 range/i.test(f.title));
		expect(f).toBeUndefined();
	});

	it('handles deep nesting that exceeds DNS lookup budget', async () => {
		// Chain: example.com -> a.com -> b.com -> c.com, each with additional mechanisms
		mockMultiDomainTxt({
			'example.com': ['v=spf1 include:a.com a mx exists:verify.com -all'],
			'a.com': ['v=spf1 include:b.com a mx -all'],
			'b.com': ['v=spf1 include:c.com a mx ptr -all'],
			'c.com': ['v=spf1 a mx exists:test.com -all'],
		});

		const r = await run();
		const f = r.findings.find((f) => f.title.includes('Too many DNS'));
		expect(f).toBeDefined();
		expect(f!.severity).toBe('critical');
		// example.com: include + a + mx + exists = 4
		// a.com: include + a + mx = 3
		// b.com: include + a + mx + ptr = 4
		// c.com: a + mx + exists = 3
		// Total: 4 + 3 + 4 + 3 = 14
		expect(f!.metadata?.lookupCount).toBe(14);
	});

	it('handles failed nested DNS queries gracefully', async () => {
		let callCount = 0;
		globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
			const u = new URL(typeof url === 'string' ? url : url.toString());
			const name = u.searchParams.get('name') ?? '';

			if (name === 'example.com') {
				callCount++;
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 16 }],
						[{ name, type: 16, TTL: 300, data: '"v=spf1 include:failing.com include:ok.com -all"' }],
					),
				);
			}
			if (name === 'failing.com') {
				callCount++;
				return Promise.reject(new Error('DNS timeout'));
			}
			if (name === 'ok.com') {
				callCount++;
				return Promise.resolve(
					createDohResponse(
						[{ name, type: 16 }],
						[{ name, type: 16, TTL: 300, data: '"v=spf1 -all"' }],
					),
				);
			}
			return Promise.resolve(createDohResponse([{ name, type: 16 }], []));
		});

		const r = await run();
		// Should not crash — should still complete the check
		expect(r.category).toBe('spf');
		// The include count should still be present (2 top-level includes counted)
		expect(r.findings.length).toBeGreaterThan(0);
	});
});
