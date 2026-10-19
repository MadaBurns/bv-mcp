// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for `renderBrandAuditHtml` — pure HTML template.
 *
 * Focus: empty-bucket transparency. Reviewers reading a brand-audit PDF
 * must be able to distinguish "classifier ran and found nothing" from
 * "this code path didn't fire" — surfaced via `data-state` on each
 * bucket's <table>.
 */

import { describe, it, expect } from 'vitest';
import { renderBrandAuditHtml, type BrandCandidateRow } from '../src/lib/brand-audit-html-template';

const baseInput = {
	target: 'example.com',
	dateIso: '2026-05-15T00:00:00Z',
	serverVersion: '2.21.1',
};

const consolidatedRow: BrandCandidateRow = {
	domain: 'a.example.com',
	bucket: 'consolidated',
	relationshipType: 'owned_primary',
	registrar: 'X',
	registrarSource: 'rdap',
	reasons: ['NS overlap'],
	signals: ['ns_overlap'],
	combinedConfidence: 0.9,
};

describe('empty-bucket transparency', () => {
	it('marks an empty bucket that the classifier exercised as empty-verified', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [consolidatedRow],
			bucketsExercised: new Set(['consolidated', 'shadowIt', 'indeterminate', 'impersonation']),
		});
		expect(html).toMatch(/data-bucket="shadowIt"[^>]*data-state="empty-verified"/);
		expect(html).toMatch(/data-bucket="impersonation"[^>]*data-state="empty-verified"/);
	});

	it('marks an empty bucket that the classifier did NOT exercise as not-run', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [],
			bucketsExercised: new Set(['consolidated']),
		});
		expect(html).toMatch(/data-bucket="shadowIt"[^>]*data-state="not-run"/);
	});

	it('omits the data-state attribute when the bucket has candidates', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [
				{
					domain: 'a.example.com',
					bucket: 'shadowIt',
					relationshipType: 'owned_off_primary_registrar',
					registrar: 'X',
					registrarSource: 'rdap',
					reasons: [],
					signals: [],
					combinedConfidence: 0.9,
				},
			],
			bucketsExercised: new Set(['shadowIt']),
		});
		// The shadowIt section has rows, so no empty-state badge
		expect(html).not.toMatch(/data-bucket="shadowIt"[^>]*data-state=/);
	});

	it('back-compat: input without bucketsExercised treats every empty bucket as empty-verified', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [],
		});
		expect(html).toMatch(/data-bucket="shadowIt"[^>]*data-state="empty-verified"/);
	});

	it('does NOT regress existing structure (citations column still present)', () => {
		const html = renderBrandAuditHtml({
			...baseInput,
			candidates: [
				{
					domain: 'a.example.com',
					bucket: 'consolidated',
					relationshipType: 'owned_primary',
					registrar: 'X',
					registrarSource: 'rdap',
					reasons: ['NS overlap'],
					signals: ['ns_overlap'],
					combinedConfidence: 0.9,
				},
			],
		});
		expect(html).toContain('Sources'); // header
		expect(html).toContain('crt.sh'); // citation link
		expect(html).toContain('rdap');
	});
});

describe('citation links (byte-pinned)', () => {
	function sourcesCell(signals: string[], domain = 'a.example.com'): string {
		const html = renderBrandAuditHtml({ ...baseInput, candidates: [{ ...consolidatedRow, domain, signals }] });
		const match = html.match(/<td class="sources">(.*?)<\/td>/s);
		return match ? match[1] : '';
	}

	const crt = '<a class="cite" href="https://crt.sh/?q=a.example.com" target="_blank" rel="noopener">crt.sh</a>';
	const rdap = '<a class="cite" href="https://rdap.org/domain/a.example.com" target="_blank" rel="noopener">rdap</a>';
	const baseline = `${crt} ${rdap}`;
	const link = (href: string, label: string): string => `<a class="cite" href="${href}" target="_blank" rel="noopener">${label}</a>`;

	it('renders only the crt.sh and rdap baseline when there are no signals', () => {
		expect(sourcesCell([])).toBe(baseline);
	});

	it('emits exactly the pinned link for each signal family, in signal order', () => {
		expect(sourcesCell(['san_match'])).toBe(`${baseline} ${link('https://crt.sh/?q=a.example.com&amp;exclude=expired', 'cert')}`);
		expect(sourcesCell(['cert_overlap'])).toBe(`${baseline} ${link('https://crt.sh/?q=a.example.com&amp;exclude=expired', 'cert')}`);
		expect(sourcesCell(['ns_overlap'])).toBe(`${baseline} ${link('https://dns.google/resolve?name=a.example.com&amp;type=NS', 'ns')}`);
		expect(sourcesCell(['ns_match'])).toBe(`${baseline} ${link('https://dns.google/resolve?name=a.example.com&amp;type=NS', 'ns')}`);
		expect(sourcesCell(['dkim_selector'])).toBe(
			`${baseline} ${link('https://dns.google/resolve?name=default._domainkey.a.example.com&amp;type=TXT', 'dkim')}`,
		);
		expect(sourcesCell(['dmarc_rua'])).toBe(
			`${baseline} ${link('https://dns.google/resolve?name=_dmarc.a.example.com&amp;type=TXT', 'dmarc')}`,
		);
		expect(sourcesCell(['spf_include'])).toBe(`${baseline} ${link('https://dns.google/resolve?name=a.example.com&amp;type=TXT', 'spf')}`);
		expect(sourcesCell(['txt_verification'])).toBe(`${baseline} ${link('https://dns.google/resolve?name=a.example.com&amp;type=TXT', 'spf')}`);
		expect(sourcesCell(['mx_platform'])).toBe(`${baseline} ${link('https://dns.google/resolve?name=a.example.com&amp;type=MX', 'mx')}`);
		expect(sourcesCell(['shared_mail'])).toBe(`${baseline} ${link('https://dns.google/resolve?name=a.example.com&amp;type=MX', 'mx')}`);
		expect(sourcesCell(['caa_issuer'])).toBe(`${baseline} ${link('https://dns.google/resolve?name=a.example.com&amp;type=CAA', 'caa')}`);
		expect(sourcesCell(['registrar_match'])).toBe(`${baseline} ${link('https://rdap.org/domain/a.example.com', 'whois')}`);
		expect(sourcesCell(['whois_org'])).toBe(`${baseline} ${link('https://rdap.org/domain/a.example.com', 'whois')}`);
		expect(sourcesCell(['markov_gen'])).toBe(baseline);
	});

	it('first matching rule wins when a signal name matches several families', () => {
		// san/cert beats mail, ns_ beats txt, dkim beats spf, txt beats rdap.
		expect(sourcesCell(['san_mail'])).toContain('>cert</a>');
		expect(sourcesCell(['san_mail'])).not.toContain('>mx</a>');
		expect(sourcesCell(['ns_txt'])).toContain('>ns</a>');
		expect(sourcesCell(['ns_txt'])).not.toContain('>spf</a>');
		expect(sourcesCell(['dkim_spf'])).toContain('>dkim</a>');
		expect(sourcesCell(['dkim_spf'])).not.toContain('>spf</a>');
		expect(sourcesCell(['rdap_txt'])).toContain('>spf</a>');
		expect(sourcesCell(['rdap_txt'])).not.toContain('>whois</a>');
	});

	it('dedupes signals case-insensitively and keeps first-seen order across families', () => {
		expect(sourcesCell(['DMARC_rua', 'dmarc_RUA', 'caa_x', 'NS_match', 'unknown'])).toBe(
			[
				baseline,
				link('https://dns.google/resolve?name=_dmarc.a.example.com&amp;type=TXT', 'dmarc'),
				link('https://dns.google/resolve?name=a.example.com&amp;type=CAA', 'caa'),
				link('https://dns.google/resolve?name=a.example.com&amp;type=NS', 'ns'),
			].join(' '),
		);
	});

	it('URL-encodes the domain in every link', () => {
		const cell = sourcesCell(['ns_overlap'], 'a b.example.com');
		expect(cell).toContain('https://crt.sh/?q=a%20b.example.com');
		expect(cell).toContain('https://dns.google/resolve?name=a%20b.example.com&amp;type=NS');
	});
});
