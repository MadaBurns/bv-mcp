import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from '../helpers/dns-mock';
import { runSpfCanary, shouldAlertOnCanary, SPF_CANARY_DOMAINS } from '../../src/lib/spf-canary';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** Per-domain TXT mock: returns whatever SPF (or no SPF) the test wants for each name. */
function mockPerDomainSpf(domainSpf: Record<string, string | null>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const type = u.searchParams.get('type') ?? '';
		// only care about TXT here; non-TXT (e.g. DMARC at _dmarc.<name>) returns empty
		if (type !== 'TXT') return Promise.resolve(createDohResponse([{ name, type: Number(type) }], []));
		// _dmarc lookups: return empty so the SPF check skips DMARC-side branches deterministically
		if (name.startsWith('_dmarc.')) return Promise.resolve(createDohResponse([{ name, type: 16 }], []));
		const spf = domainSpf[name];
		if (spf == null) return Promise.resolve(createDohResponse([{ name, type: 16 }], []));
		return Promise.resolve(
			createDohResponse(
				[{ name, type: 16 }],
				[{ name, type: 16, TTL: 300, data: `"${spf}"` }],
			),
		);
	});
}

describe('runSpfCanary', () => {
	it('reports zero nulls when every domain has SPF', async () => {
		const spf: Record<string, string | null> = {};
		for (const d of SPF_CANARY_DOMAINS) spf[d] = 'v=spf1 -all';
		mockPerDomainSpf(spf);

		const r = await runSpfCanary();
		expect(r.totalProbed).toBe(SPF_CANARY_DOMAINS.length);
		expect(r.nullCount).toBe(0);
		expect(r.nullRate).toBe(0);
		expect(r.nullDomains).toEqual([]);
	});

	it('reports a null when a canary domain has no SPF', async () => {
		const spf: Record<string, string | null> = {};
		for (const d of SPF_CANARY_DOMAINS) spf[d] = 'v=spf1 -all';
		spf['google.com'] = null; // genuine absence

		mockPerDomainSpf(spf);

		const r = await runSpfCanary();
		expect(r.nullCount).toBe(1);
		expect(r.nullDomains).toContain('google.com');
		expect(r.nullRate).toBeCloseTo(1 / SPF_CANARY_DOMAINS.length, 6);
	});

	it('counts every canary domain as null when none publish SPF', async () => {
		const spf: Record<string, string | null> = {};
		for (const d of SPF_CANARY_DOMAINS) spf[d] = null;
		mockPerDomainSpf(spf);

		const r = await runSpfCanary();
		expect(r.nullCount).toBe(SPF_CANARY_DOMAINS.length);
		expect(r.nullRate).toBe(1);
	});

	it('classifies transport failure as error, not null', async () => {
		const subset = ['only.example'];
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('network down'));

		const r = await runSpfCanary(subset);
		// checkSpf wraps DNS errors into a finding (errorKind=dns_error, NOT "No SPF record found"),
		// so the canary should classify this as error, not null.
		expect(r.nullCount).toBe(0);
		expect(r.errorCount).toBe(1);
		expect(r.errorDomains).toContain('only.example');
	});
});

describe('shouldAlertOnCanary', () => {
	const base = { totalProbed: 20, errorCount: 0, errorDomains: [] as string[], nullDomains: [] as string[] };

	it('does not alert below threshold', () => {
		expect(shouldAlertOnCanary({ ...base, nullCount: 2, nullRate: 0.1 }, 0.15)).toBe(false);
	});

	it('alerts at threshold', () => {
		expect(shouldAlertOnCanary({ ...base, nullCount: 3, nullRate: 0.15 }, 0.15)).toBe(true);
	});

	it('alerts above threshold', () => {
		expect(shouldAlertOnCanary({ ...base, nullCount: 10, nullRate: 0.5 }, 0.15)).toBe(true);
	});
});

describe('SPF_CANARY_DOMAINS sanity', () => {
	it('has a minimum representative sample size', () => {
		// Below ~15 domains, a single false negative is >6%, making thresholds noisy.
		expect(SPF_CANARY_DOMAINS.length).toBeGreaterThanOrEqual(15);
	});

	it('contains only lowercase ascii domains (no IPs, no spaces, no uppercase)', () => {
		for (const d of SPF_CANARY_DOMAINS) {
			expect(d).toMatch(/^[a-z0-9.-]+\.[a-z]{2,}$/);
		}
	});

	it('contains no duplicates', () => {
		expect(new Set(SPF_CANARY_DOMAINS).size).toBe(SPF_CANARY_DOMAINS.length);
	});
});
