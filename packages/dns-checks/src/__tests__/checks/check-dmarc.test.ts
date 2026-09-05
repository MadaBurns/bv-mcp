// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { checkDMARC } from '../../checks/check-dmarc';
import type { DNSQueryFunction } from '../../types';

function createMockDNS(records: Record<string, string[]>): DNSQueryFunction {
	return vi.fn(async (domain: string, _type: string) => {
		return records[domain] ?? [];
	});
}

describe('checkDMARC', () => {
	it('returns high when no DMARC record found (scan_domain escalates to critical under impersonation)', async () => {
		const queryDNS = createMockDNS({ '_dmarc.example.com': [] });
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.category).toBe('dmarc');
		expect(result.findings[0].severity).toBe('high');
		expect(result.findings[0].title).toBe('No DMARC record found');
	});

	it('flags p=none (monitoring-only)', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=none; rua=mailto:dmarc@example.com'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'DMARC policy set to none')).toBe(true);
	});

	it('flags p=quarantine as low', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'DMARC policy set to quarantine')).toBe(true);
	});

	it('reports properly configured for p=reject with strict alignment', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com; ruf=mailto:ruf@example.com; adkim=s; aspf=s'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'DMARC properly configured')).toBe(true);
		expect(result.passed).toBe(true);
	});

	it('flags missing rua', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'No aggregate reporting')).toBe(true);
	});

	it('flags subdomain policy weaker than parent', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'Subdomain policy weaker than parent policy' && f.severity === 'high')).toBe(true);
	});

	it('flags invalid pct value', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; pct=abc'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'Invalid DMARC percentage value')).toBe(true);
	});

	it('does not flag subdomain RUA as unauthorized (e.g. dmarc.example.com for example.com)', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:dmarc@dmarc.example.com'],
		});
		const result = await checkDMARC('example.com', queryDNS);
		// Should NOT have "Third-party aggregate reporting not authorized"
		expect(result.findings.some((f) => f.title === 'Third-party aggregate reporting not authorized')).toBe(false);
	});

	it('flags true third-party RUA as unauthorized if TXT record missing', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:dmarc@otherbrand.com'],
			'example.com._report._dmarc.otherbrand.com': [], // missing auth
		});
		const result = await checkDMARC('example.com', queryDNS);
		expect(result.findings.some((f) => f.title === 'Third-party aggregate reporting not authorized')).toBe(true);
	});

	// Authorization lookup establishes a DNS fact, not a report-delivery outcome.
	// Keep the public consequence conditional, cite RFC 9990 §4, and retain the
	// exact record the destination needs to publish. All evidence here is synthetic.
	it('states the RUA-authorization consequence as evidence-bounded, citing the current RFC', async () => {
		const queryDNS = createMockDNS({
			'_dmarc.example.com': ['v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.net'],
			'example.com._report._dmarc.reports.example.net': [], // missing auth
		});
		const result = await checkDMARC('example.com', queryDNS);
		const finding = result.findings.find((f) => f.title === 'Third-party aggregate reporting not authorized');
		expect(finding).toBeDefined();

		// No unfalsifiable claim of a definite delivery outcome.
		expect(finding!.detail).not.toMatch(/will be silently discarded/i);
		expect(finding!.detail).toMatch(/may be discarded by receivers that enforce/i);

		// Cite the standard that is actually in force.
		expect(finding!.detail).toMatch(/RFC 9990/);

		// The actionable part must survive the rewording: name the exact record to publish.
		expect(finding!.detail).toContain('example.com._report._dmarc.reports.example.net');
		expect(finding!.detail).toContain('v=DMARC1');
	});

	describe('subdomain scanned directly against an enforcing parent (sp=none asymmetry)', () => {
		// The org domain is locked down (p=reject) but hands this child sp=none, so the
		// effective policy for the subdomain is "none". The tree walk resolves the record at
		// the parent, and the parent's own p= must reach the classifier for it to say so.
		const enforcingParent = { '_dmarc.example.com': ['v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@example.com'] };

		it('reports the asymmetry in the detail while keeping the title (severity high since 1.19.0)', async () => {
			const queryDNS = createMockDNS(enforcingParent);
			const result = await checkDMARC('billing.example.com', queryDNS);
			const none = result.findings.find((f) => f.title === 'DMARC policy set to none');
			expect(none?.severity).toBe('high');
			expect(none?.detail).toContain('sp=none');
			expect(none?.detail).toContain('p=reject');
			expect(none?.detail).toContain('example.com');
			expect(none?.detail).toContain('billing.example.com');
		});

		it('still reports the subdomain as not enforcing (controlPresent unchanged)', async () => {
			const queryDNS = createMockDNS(enforcingParent);
			const result = await checkDMARC('billing.example.com', queryDNS);
			expect(result.controlPresent).toBe(false);
		});

		it('leaves the parent scan itself untouched — sp= is still the org-domain finding', async () => {
			const queryDNS = createMockDNS(enforcingParent);
			const result = await checkDMARC('example.com', queryDNS);
			expect(result.findings.some((f) => f.title === 'DMARC policy set to none')).toBe(false);
			expect(result.findings.find((f) => f.title === 'Subdomain policy weaker than parent policy')?.severity).toBe('high');
		});

		it('keeps the generic wording when the parent is itself p=none', async () => {
			const queryDNS = createMockDNS({ '_dmarc.example.com': ['v=DMARC1; p=none; sp=none; rua=mailto:dmarc@example.com'] });
			const result = await checkDMARC('billing.example.com', queryDNS);
			expect(result.findings.find((f) => f.title === 'DMARC policy set to none')?.detail).toContain('take no action');
		});
	});
});
