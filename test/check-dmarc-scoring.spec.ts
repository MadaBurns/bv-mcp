// SPDX-License-Identifier: BUSL-1.1
//
// Cluster 3 — Defect J — DMARC scoring credits DMARCbis + strict alignment
//
// Cross-domain evidence (fact-check 2026-05-28):
//   - gov.uk DMARC = "v=DMARC1;p=reject;sp=none;np=reject;adkim=s;aspf=s;fo=1;rua=..."
//     → score 70 (WRONG — DMARCbis non-existent-subdomain protection is strict)
//   - stripe.com DMARC = "v=DMARC1;p=reject;pct=100;fo=1;rua=...;ruf=..." → score 85
//
// Required ordering: gov.uk DMARC > stripe.com DMARC. gov.uk floor ≥ 85.
//
// Approach (single-mechanism, penalty-based): when DMARCbis `np=reject` or
// `np=quarantine` is present, downgrade the "Subdomain policy weaker than
// parent policy" finding from HIGH to LOW. `np` covers non-existent
// subdomains explicitly, which is the practical risk `sp=none` leaves open.
//
// Per plan §10 (testing anti-patterns): use ">=" / "<" ranges and
// cross-domain ordering — do NOT assert exact scores.

import { describe, it, expect, vi } from 'vitest';
import { checkDMARC } from '../packages/dns-checks/src/checks/check-dmarc';
import type { DNSQueryFunction } from '../packages/dns-checks/src/types';

function mockDmarc(domain: string, record: string): DNSQueryFunction {
	return vi.fn(async (q: string, _type: string) => {
		if (q === `_dmarc.${domain}`) return [record];
		// All other lookups (RUA authorization, parent DMARC) return empty.
		return [];
	});
}

describe('Defect J — DMARC scoring credits modern best practices', () => {
	it('gov.uk-style strict DMARCbis policy scores ≥ 85 (regression — 2026-05-28 baseline was 70)', async () => {
		const queryDNS = mockDmarc(
			'gov.uk',
			'v=DMARC1; p=reject; sp=none; np=reject; adkim=s; aspf=s; fo=1; rua=mailto:dmarc-rua@dmarc.service.gov.uk',
		);
		const result = await checkDMARC('gov.uk', queryDNS);
		expect(result.score).toBeGreaterThanOrEqual(85);
	});

	it('credits strict alignment (adkim=s, aspf=s) over relaxed', async () => {
		const baseline = await checkDMARC(
			'baseline.example',
			mockDmarc('baseline.example', 'v=DMARC1; p=reject; rua=mailto:r@baseline.example'),
		);
		const strict = await checkDMARC(
			'strict.example',
			mockDmarc('strict.example', 'v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:r@strict.example'),
		);
		expect(strict.score).toBeGreaterThan(baseline.score);
	});

	it('does NOT credit pct=100 (which is the default since DMARC introduction)', async () => {
		const withPct = await checkDMARC(
			'with-pct.example',
			mockDmarc('with-pct.example', 'v=DMARC1; p=reject; pct=100; rua=mailto:r@with-pct.example'),
		);
		const withoutPct = await checkDMARC(
			'without-pct.example',
			mockDmarc('without-pct.example', 'v=DMARC1; p=reject; rua=mailto:r@without-pct.example'),
		);
		expect(withPct.score).toBe(withoutPct.score);
	});

	it('cross-domain ordering: gov.uk (DMARCbis + strict) > stripe.com (basic + pct=100)', async () => {
		const govuk = await checkDMARC(
			'gov.uk',
			mockDmarc(
				'gov.uk',
				'v=DMARC1; p=reject; sp=none; np=reject; adkim=s; aspf=s; fo=1; rua=mailto:dmarc-rua@dmarc.service.gov.uk',
			),
		);
		const stripe = await checkDMARC(
			'stripe.com',
			mockDmarc(
				'stripe.com',
				'v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc@stripe.com; ruf=mailto:ruf@stripe.com',
			),
		);
		expect(govuk.score).toBeGreaterThan(stripe.score);
	});

	it('np=reject downgrades "Subdomain policy weaker than parent" from HIGH to LOW (DMARCbis covers non-existent subdomains)', async () => {
		// Without np= — sp=none is a HIGH finding (parent reject, subdomain none — full gap).
		const withoutNp = await checkDMARC(
			'a.example',
			mockDmarc('a.example', 'v=DMARC1; p=reject; sp=none; rua=mailto:r@a.example'),
		);
		const sevWithoutNp = withoutNp.findings
			.filter((f) => f.title === 'Subdomain policy weaker than parent policy')
			.map((f) => f.severity);
		expect(sevWithoutNp).toEqual(['high']);

		// With np=reject — DMARCbis explicitly protects non-existent subdomains; sp=none
		// is now only a concern for existing subdomains, downgraded to low.
		const withNp = await checkDMARC(
			'b.example',
			mockDmarc('b.example', 'v=DMARC1; p=reject; sp=none; np=reject; rua=mailto:r@b.example'),
		);
		const subdomainFinding = withNp.findings.find((f) => f.title === 'Subdomain policy weaker than parent policy');
		// Either downgraded to low OR omitted in favour of an "np present" finding — both acceptable as long as severity is not high.
		if (subdomainFinding) {
			expect(subdomainFinding.severity).toBe('low');
		}
	});

	it('np=quarantine also triggers the subdomain-finding downgrade (DMARCbis non-existent-subdomain protection)', async () => {
		const withNpQuarantine = await checkDMARC(
			'c.example',
			mockDmarc('c.example', 'v=DMARC1; p=reject; sp=none; np=quarantine; rua=mailto:r@c.example'),
		);
		const subdomainFinding = withNpQuarantine.findings.find((f) => f.title === 'Subdomain policy weaker than parent policy');
		if (subdomainFinding) {
			expect(subdomainFinding.severity).not.toBe('high');
		}
	});

	it('np=none does NOT downgrade the subdomain-weaker finding (no DMARCbis protection)', async () => {
		const withNpNone = await checkDMARC(
			'd.example',
			mockDmarc('d.example', 'v=DMARC1; p=reject; sp=none; np=none; rua=mailto:r@d.example'),
		);
		const subdomainFinding = withNpNone.findings.find((f) => f.title === 'Subdomain policy weaker than parent policy');
		expect(subdomainFinding?.severity).toBe('high');
	});
});
