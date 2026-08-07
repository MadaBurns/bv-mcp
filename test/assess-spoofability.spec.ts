// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach } from 'vitest';
import { vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

/** DoH record-type NAMES (what `buildDohUrl` actually sends) → numeric codes. */
const TYPE_CODES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, CAA: 257 };

/**
 * The requested record type as a numeric code.
 *
 * `buildDohUrl` sends `type=TXT`, not `type=16`. This mock previously did
 * `Number(searchParams.get('type'))`, which is `NaN` for every real query — so it
 * served an empty answer for EVERYTHING and every assertion in this file that
 * depended on a record being present passed vacuously (a `p=reject` fixture was
 * scored as "no DMARC record"). Accept both spellings.
 */
function requestedType(u: URL): number {
	const raw = u.searchParams.get('type') ?? '';
	const numeric = Number(raw);
	if (raw !== '' && Number.isFinite(numeric)) return numeric;
	return TYPE_CODES[raw.toUpperCase()] ?? -1;
}

/**
 * Mock DNS responses for SPF, DMARC, and DKIM checks.
 */
function mockEmailAuth(options: {
	spf?: string | null;
	dmarc?: string | null;
	dkim?: boolean;
	/** Publish REVOKED DKIM keys (empty p=) on every probed selector — the non-sending posture. */
	dkimRevoked?: boolean;
	/** Emit no MX records (a domain that receives no mail). */
	noMx?: boolean;
}) {
	const { spf, dmarc, dkim = false, dkimRevoked = false, noMx = false } = options;

	globalThis.fetch = vi.fn().mockImplementation((url: string | URL) => {
		const u = new URL(typeof url === 'string' ? url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const type = requestedType(u);

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
				if (dkimRevoked) {
					records.push({ name, type: 16, TTL: 300, data: '"v=DKIM1; k=rsa; p="' });
				} else if (dkim) {
					records.push({ name, type: 16, TTL: 300, data: '"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"' });
				}
				return Promise.resolve(createDohResponse([{ name, type }], records));
			}
			return Promise.resolve(createDohResponse([{ name, type }], []));
		}
		if (type === 15 && !noMx) {
			return Promise.resolve(createDohResponse([{ name, type }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]));
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
		// DKIM abstains: selector probing that found nothing has not established
		// absence (the same confidence rule the scan model applies), so it is
		// excluded from the composite rather than scored as a measured zero.
		expect(result.dkimProtection).toBeNull();
		expect(result.controls.dkim.status).toBe('unmeasured');
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
		expect(result.spoofabilityScore).not.toBeNull();
		const score = result.spoofabilityScore!;
		if (score >= 80) expect(result.riskLevel).toBe('critical');
		else if (score >= 60) expect(result.riskLevel).toBe('high');
		else if (score >= 40) expect(result.riskLevel).toBe('medium');
		else if (score >= 20) expect(result.riskLevel).toBe('low');
		else expect(result.riskLevel).toBe('minimal');
	});

	/**
	 * Banked defect (measured live, same day): `example.com` — all probed DKIM
	 * selectors revoked, null MX, `v=spf1 -all` — reported `dkimProtection: 100`
	 * and "Domain has strong email authentication", while `scan_domain` put the
	 * same domain's DKIM in `notApplicableCategories` with a NULL score.
	 *
	 * A domain with zero usable signing keys is not "100 protected"; a domain that
	 * cannot send mail does not have "strong email authentication".
	 */
	describe('no-send domain (revoked DKIM keys, -all, no MX)', () => {
		async function runNoSend() {
			mockEmailAuth({
				spf: 'v=spf1 -all',
				dmarc: 'v=DMARC1; p=reject; rua=mailto:d@example.com',
				dkimRevoked: true,
				noMx: true,
			});
			const { assessSpoofability } = await import('../src/tools/assess-spoofability');
			return assessSpoofability('example.com');
		}

		it('abstains on DKIM instead of awarding full marks', async () => {
			const result = await runNoSend();
			expect(result.dkimProtection).toBeNull();
			expect(result.controls.dkim.status).toBe('not_applicable');
			expect(result.controls.dkim.reason).toBeTruthy();
			expect(result.noSendPolicy).toBe(true);
		});

		it('never describes a domain that cannot send mail as having strong email authentication', async () => {
			const result = await runNoSend();
			expect(result.summary.toLowerCase()).not.toContain('strong email authentication');
			expect(result.summary).toContain('no-send');
			expect(result.summary).toContain('sends no email');
		});

		it('does not claim missing DKIM weakens DMARC alignment for a domain with no mail flow', async () => {
			const result = await runNoSend();
			expect(result.interactionEffects.some((e) => e.includes('Missing DKIM'))).toBe(false);
		});

		it('renders the abstention in the prose, not `null/100`', async () => {
			const { formatSpoofability } = await import('../src/tools/assess-spoofability');
			const result = await runNoSend();
			for (const format of ['full', 'compact'] as const) {
				const text = formatSpoofability(result, format);
				expect(text).not.toContain('null');
				expect(text).toContain('not applicable');
			}
		});
	});

	/**
	 * Banked defect: `check_dkim` scored github.com 45 (`passed: false`) on the same
	 * day `assess_spoofability` reported `dkimProtection: 80` — two tools
	 * disagreeing about one control on one domain. The bucketing that produced the
	 * 80 (`score >= 80 ? 100 : 80`) is gone.
	 */
	it("reports the DKIM check's own score rather than a bucketed one", async () => {
		mockEmailAuth({
			spf: 'v=spf1 include:_spf.google.com -all',
			dmarc: 'v=DMARC1; p=reject; rua=mailto:d@example.com',
			dkim: true,
		});
		const { assessSpoofability } = await import('../src/tools/assess-spoofability');
		const { checkDkim } = await import('../src/tools/check-dkim');
		const result = await assessSpoofability('example.com');
		const dkim = await checkDkim('example.com');

		expect(result.controls.dkim.status).toBe('measured');
		expect(result.dkimProtection).toBe(dkim.score);
	});

	/**
	 * The structural invariant behind the divergence: a spoofability sub-score may
	 * never claim MORE protection than the underlying check measured. Stated over
	 * several postures so it cannot be satisfied by one lucky fixture.
	 */
	it('never reports more protection than the underlying check measured', async () => {
		const fixtures = [
			{ spf: 'v=spf1 include:_spf.google.com -all', dmarc: 'v=DMARC1; p=reject; rua=mailto:d@example.com', dkim: true },
			{ spf: 'v=spf1 include:_spf.google.com ~all', dmarc: 'v=DMARC1; p=none; rua=mailto:d@example.com', dkim: true },
			{ spf: 'v=spf1 +all', dmarc: 'v=DMARC1; p=quarantine; rua=mailto:d@example.com', dkim: true },
			{ spf: 'v=spf1 -all', dmarc: null, dkim: true },
		];

		const { assessSpoofability } = await import('../src/tools/assess-spoofability');
		const { checkSpf } = await import('../src/tools/check-spf');
		const { checkDmarc } = await import('../src/tools/check-dmarc');
		const { checkDkim } = await import('../src/tools/check-dkim');

		for (const fixture of fixtures) {
			mockEmailAuth(fixture);
			const result = await assessSpoofability('example.com');
			const [spf, dmarc, dkim] = await Promise.all([checkSpf('example.com'), checkDmarc('example.com'), checkDkim('example.com')]);

			for (const [label, protection, check] of [
				['spf', result.spfProtection, spf],
				['dmarc', result.dmarcProtection, dmarc],
				['dkim', result.dkimProtection, dkim],
			] as const) {
				if (protection === null) continue;
				expect(protection, `${label} for ${fixture.spf} / ${fixture.dmarc}`).toBeLessThanOrEqual(check.score);
			}
		}
	});

	/**
	 * `v=spf1 +all` authorizes every sender on the internet. It scored
	 * `spfProtection: 100` because the classifier matched the substring `-all`
	 * inside the `+all` finding's own REMEDIATION prose ("Use \"-all\" (hard fail)").
	 */
	it('does not read a permissive +all record as hard fail', async () => {
		mockEmailAuth({ spf: 'v=spf1 +all', dmarc: 'v=DMARC1; p=none', dkim: true });
		const { assessSpoofability } = await import('../src/tools/assess-spoofability');
		const result = await assessSpoofability('example.com');
		expect(result.spfProtection).toBe(0);
	});

	/**
	 * `p=quarantine` is ENFORCING everywhere else in the product — it is the BIMI
	 * eligibility bar, and scan_domain emits a "DMARC enforcing" signal for it.
	 */
	it('does not label p=quarantine as weak or non-enforcing DMARC', async () => {
		mockEmailAuth({
			spf: 'v=spf1 include:sendgrid.net ~all',
			dmarc: 'v=DMARC1; p=quarantine; rua=mailto:d@example.com',
			dkim: true,
		});
		const { assessSpoofability } = await import('../src/tools/assess-spoofability');
		const result = await assessSpoofability('example.com');

		const effects = result.interactionEffects.join(' ').toLowerCase();
		expect(effects).not.toContain('weak dmarc');
		expect(effects).not.toContain('non-enforcing dmarc');
	});
});

/** A fully-measured fixture, so the format specs stay about formatting. */
function measuredFixture() {
	return {
		domain: 'example.com',
		spoofabilityScore: 65,
		riskLevel: 'high' as const,
		spfProtection: 50,
		dmarcProtection: 30,
		dkimProtection: 0,
		controls: {
			spf: { score: 50, status: 'measured' as const },
			dmarc: { score: 30, status: 'measured' as const },
			dkim: { score: 0, status: 'measured' as const },
		},
		noSendPolicy: false,
		evidenceInsufficient: false,
		interactionEffects: ['Test effect'],
		summary: 'Test summary',
	};
}

describe('formatSpoofability', () => {
	it('formats result as readable text', async () => {
		const { formatSpoofability } = await import('../src/tools/assess-spoofability');
		const text = formatSpoofability(measuredFixture());
		expect(text).toContain('example.com');
		expect(text).toContain('65/100');
		expect(text).toContain('HIGH');
		expect(text).toContain('SPF Protection');
		expect(text).toContain('Test effect');
	});

	it('renders `not measured` rather than a verdict when nothing could be measured', async () => {
		const { formatSpoofability } = await import('../src/tools/assess-spoofability');
		const data = {
			...measuredFixture(),
			spoofabilityScore: null,
			riskLevel: null,
			spfProtection: null,
			dmarcProtection: null,
			dkimProtection: null,
			controls: {
				spf: { score: null, status: 'unmeasured' as const, reason: 'The SPF lookup did not complete.' },
				dmarc: { score: null, status: 'unmeasured' as const, reason: 'The DMARC lookup did not complete.' },
				dkim: { score: null, status: 'unmeasured' as const, reason: 'The DKIM lookup did not complete.' },
			},
			evidenceInsufficient: true,
			interactionEffects: [],
			summary: 'Email spoofability for example.com is not measured.',
		};

		for (const format of ['full', 'compact'] as const) {
			const text = formatSpoofability(data, format);
			expect(text).not.toContain('null');
			expect(text).not.toContain('RISK');
			expect(text).toContain('not measured');
		}
	});

	it('compact mode omits narrative and interaction effects', async () => {
		const { formatSpoofability } = await import('../src/tools/assess-spoofability');
		const data = measuredFixture();
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
