// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import { appendDmarcCleanInfo, classifyDmarc } from './dmarc';

const base = { recordCount: 1 } as const;

describe('classifyDmarc', () => {
	it('flags absent DMARC as high (NIST v3.5.0)', () => {
		const f = classifyDmarc({ recordCount: 0, policy: null });
		expect(f).toHaveLength(1);
		expect(f[0].title).toBe('No DMARC record found');
		expect(f[0].severity).toBe('high');
	});

	it('scores p=none as a medium finding (NIST v3.5.0)', () => {
		const f = classifyDmarc({ ...base, policy: 'none' });
		expect(f.find((x) => x.title === 'DMARC policy set to none')?.severity).toBe('medium');
	});

	it('flags p=quarantine as low', () => {
		const f = classifyDmarc({ ...base, policy: 'quarantine', rua: 'mailto:dmarc@example.com' });
		expect(f.find((x) => x.title === 'DMARC policy set to quarantine')?.severity).toBe('low');
	});

	it('emits no significant finding for a clean p=reject record', () => {
		const f = classifyDmarc({ ...base, policy: 'reject', sp: 'reject', rua: 'mailto:dmarc@example.com', adkim: 's', aspf: 's' });
		const significant = f.filter((x) => ['critical', 'high', 'medium'].includes(x.severity));
		expect(significant).toHaveLength(0);
	});

	it('flags multiple records as no valid policy (missingControl)', () => {
		// RFC 9989: more than one DMARC record = no policy at all → unprotected.
		const f = classifyDmarc({ ...base, recordCount: 2, policy: 'reject', rua: 'mailto:dmarc@example.com', adkim: 's', aspf: 's' });
		const finding = f.find((x) => x.title === 'Multiple DMARC records — no valid policy');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
		expect(finding!.metadata?.missingControl).toBe(true);
	});

	it('flags missing p= tag as critical', () => {
		const f = classifyDmarc({ ...base, policy: null });
		expect(f.some((x) => x.title === 'Missing DMARC policy' && x.severity === 'critical')).toBe(true);
	});

	it('downgrades weak subdomain policy when np protects (DMARCbis)', () => {
		const f = classifyDmarc({ ...base, policy: 'reject', sp: 'none', np: 'reject', rua: 'mailto:dmarc@example.com' });
		expect(f.find((x) => x.title === 'Subdomain policy weaker than parent policy')?.severity).toBe('low');
	});

	it('flags weak subdomain policy as high when np is absent (DMARCbis)', () => {
		const f = classifyDmarc({ recordCount: 1, policy: 'reject', sp: 'none', rua: 'mailto:dmarc@example.com' });
		expect(f.find((x) => x.title === 'Subdomain policy weaker than parent policy')?.severity).toBe('high');
	});

	it('flags invalid policy value as high', () => {
		const f = classifyDmarc({ recordCount: 1, policy: 'discard' });
		expect(f.find((x) => x.title === 'Invalid DMARC policy value')?.severity).toBe('high');
	});

	it('flags pct<100 as medium', () => {
		const f = classifyDmarc({ recordCount: 1, policy: 'reject', sp: 'reject', pct: '50', rua: 'mailto:dmarc@example.com', adkim: 's', aspf: 's' });
		expect(f.find((x) => x.title === 'DMARC not applied to all emails')?.severity).toBe('medium');
	});

	it('appendDmarcCleanInfo adds the info note only when no significant finding exists', () => {
		const clean = appendDmarcCleanInfo([], 'reject');
		expect(clean.some((x) => x.title === 'DMARC properly configured')).toBe(true);
		const dirty = appendDmarcCleanInfo([{ category: 'dmarc', title: 'x', severity: 'medium', detail: 'y' } as never], 'reject');
		expect(dirty.some((x) => x.title === 'DMARC properly configured')).toBe(false);
	});

	it('flags t=y test mode as medium regardless of p=reject', () => {
		const f = classifyDmarc({ recordCount: 1, policy: 'reject', sp: 'reject', t: 'y', rua: 'mailto:dmarc@example.com', adkim: 's', aspf: 's' });
		expect(f.find((x) => x.title === 'DMARC in test mode (t=y)')?.severity).toBe('medium');
	});
	it('flags np=none spoofability on an enforcing org domain', () => {
		const f = classifyDmarc({ recordCount: 1, policy: 'reject', sp: 'reject', np: 'none', rua: 'mailto:dmarc@example.com', adkim: 's', aspf: 's' });
		expect(f.find((x) => x.title === 'Non-existent subdomains spoofable (np=none)')?.severity).toBe('medium');
	});
	it('does NOT flag np spoofability when np=reject', () => {
		const f = classifyDmarc({ recordCount: 1, policy: 'reject', sp: 'none', np: 'reject', rua: 'mailto:dmarc@example.com' });
		expect(f.some((x) => x.title === 'Non-existent subdomains spoofable (np=none)')).toBe(false);
	});
	it('does NOT flag np spoofability for an inherited subdomain scan', () => {
		const f = classifyDmarc({ recordCount: 1, policy: 'reject', np: 'none', inheritedFromParent: true, rua: 'mailto:dmarc@example.com' });
		expect(f.some((x) => x.title === 'Non-existent subdomains spoofable (np=none)')).toBe(false);
	});

	describe('subdomain / org-domain enforcement asymmetry', () => {
		const asymmetric = {
			recordCount: 1,
			policy: 'none',
			domain: 'billing.example.com',
			sp: 'none',
			inheritedFromParent: true,
			orgPolicy: 'reject',
			orgDomain: 'example.com',
			rua: 'mailto:dmarc@example.com',
		} as const;

		it('names the parent-enforcing / subdomain-open asymmetry in the detail', () => {
			const f = classifyDmarc({ ...asymmetric });
			const none = f.find((x) => x.title === 'DMARC policy set to none');
			expect(none).toBeDefined();
			expect(none?.detail).toContain('sp=none');
			expect(none?.detail).toContain('example.com');
			expect(none?.detail).toContain('billing.example.com');
			expect(none?.detail).toMatch(/asymmetric/i);
		});

		it('keeps the title and severity unchanged (downstream matchers + no score change)', () => {
			const f = classifyDmarc({ ...asymmetric });
			const none = f.find((x) => x.title === 'DMARC policy set to none');
			expect(none?.severity).toBe('medium');
			expect(none?.title).toBe('DMARC policy set to none');
		});

		it('emits exactly one policy finding — no second finding that would double-count the penalty', () => {
			const f = classifyDmarc({ ...asymmetric });
			expect(f.filter((x) => x.title === 'DMARC policy set to none')).toHaveLength(1);
			expect(f.some((x) => x.title === 'Subdomain policy weaker than parent policy')).toBe(false);
		});

		it('keeps the generic wording when the org domain is NOT enforcing (p=none, sp=none)', () => {
			const f = classifyDmarc({ ...asymmetric, orgPolicy: 'none' });
			const none = f.find((x) => x.title === 'DMARC policy set to none');
			expect(none?.detail).toContain('only monitors');
			expect(none?.detail).not.toMatch(/asymmetric/i);
		});

		it('keeps the generic wording on an organizational-domain scan with p=none', () => {
			const f = classifyDmarc({ recordCount: 1, policy: 'none', domain: 'example.com' });
			const none = f.find((x) => x.title === 'DMARC policy set to none');
			expect(none?.detail).toContain('only monitors');
			expect(none?.detail).not.toMatch(/asymmetric/i);
		});

		it('recognises an enforcing parent at p=quarantine too', () => {
			const f = classifyDmarc({ ...asymmetric, orgPolicy: 'quarantine' });
			expect(f.find((x) => x.title === 'DMARC policy set to none')?.detail).toMatch(/asymmetric/i);
		});
	});
});
