import { describe, it, expect, vi } from 'vitest';
import { parseAsnFromCymru, mapAsnToCdn, detectCdnFromAsn } from '../src/lib/cdn-asn-detection';

/**
 * Build a fake DoH resolver whose `queryTxt(name)` returns the configured
 * answer for an exact `<reversed-ip>.origin.asn.cymru.com` name, or [] for
 * any unmapped name. Mirrors the real `queryTxtRecords(name) => Promise<string[]>`
 * seam (concatenated, unquoted answer strings).
 */
function mockDoh(answers: Record<string, string>): { queryTxt: ReturnType<typeof vi.fn> } {
	return {
		queryTxt: vi.fn(async (name: string) => {
			const answer = answers[name];
			return answer !== undefined ? [answer] : [];
		}),
	};
}

describe('parseAsnFromCymru', () => {
	it('extracts the ASN from a team-cymru origin TXT answer', () => {
		expect(parseAsnFromCymru('16625 | 118.215.88.0/21 | SG | apnic | 2007-10-30')).toBe(16625);
	});
	it('handles multiple ASNs (returns the first) — multi-origin prefixes', () => {
		expect(parseAsnFromCymru('13335 14618 | 162.159.128.0/19 | US | arin')).toBe(13335);
	});
	it('returns null for malformed / empty answers', () => {
		expect(parseAsnFromCymru('')).toBeNull();
		expect(parseAsnFromCymru('NXDOMAIN')).toBeNull();
		expect(parseAsnFromCymru('| no asn |')).toBeNull();
	});
});

describe('mapAsnToCdn', () => {
	it('maps Akamai ASNs', () => {
		expect(mapAsnToCdn(16625)).toBe('Akamai');
		expect(mapAsnToCdn(20940)).toBe('Akamai');
	});
	it('maps Cloudflare / Fastly / Imperva ASNs', () => {
		expect(mapAsnToCdn(13335)).toBe('Cloudflare');
		expect(mapAsnToCdn(54113)).toBe('Fastly');
		expect(mapAsnToCdn(19551)).toBe('Imperva');
	});
	it('does NOT map AWS AS16509 (ambiguous — EC2/ELB, not CDN-exclusive)', () => {
		expect(mapAsnToCdn(16509)).toBeNull();
	});
	it('returns null for unknown ASNs', () => {
		expect(mapAsnToCdn(64512)).toBeNull();
	});
});

describe('detectCdnFromAsn', () => {
	it('attributes Akamai when an A-record IP resolves to an Akamai ASN (mit.edu pattern)', async () => {
		const doh = mockDoh({ '214.90.215.118.origin.asn.cymru.com': '16625 | 118.215.88.0/21 | SG | apnic' });
		const r = await detectCdnFromAsn(['118.215.90.214'], doh);
		expect(r).toEqual({ provider: 'Akamai', confidence: 'heuristic', asn: 16625 });
	});
	it('returns null when no A-record maps to a known CDN ASN', async () => {
		const doh = mockDoh({ '8.8.8.8.origin.asn.cymru.com': '15169 | 8.8.8.0/24 | US | arin' }); // Google, not in CDN map
		expect(await detectCdnFromAsn(['8.8.8.8'], doh)).toBeNull();
	});
	it('returns null and never throws on DoH failure (fail-soft)', async () => {
		const doh = { queryTxt: vi.fn().mockRejectedValue(new Error('timeout')) };
		expect(await detectCdnFromAsn(['1.2.3.4'], doh)).toBeNull();
	});
	it('checks at most N A-records (bounds outbound query count)', async () => {
		const doh = mockDoh({});
		await detectCdnFromAsn(['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5'], doh);
		expect(doh.queryTxt).toHaveBeenCalledTimes(3); // MAX_ASN_LOOKUPS = 3
	});
	it('short-circuits on first CDN match (does not query remaining IPs)', async () => {
		const doh = mockDoh({ '1.0.0.1.origin.asn.cymru.com': '13335 | 1.0.0.0/24 | US | arin' });
		const r = await detectCdnFromAsn(['1.0.0.1', '2.2.2.2'], doh);
		expect(r?.provider).toBe('Cloudflare');
		expect(doh.queryTxt).toHaveBeenCalledTimes(1);
	});
});

describe('mapAsnToHosting (Task 3 — cloud-hosting tier)', () => {
	it('maps major cloud-hosting ASNs', async () => {
		const { mapAsnToHosting } = await import('../src/lib/cdn-asn-detection');
		expect(mapAsnToHosting(16509)).toBe('AWS');
		expect(mapAsnToHosting(15169)).toBe('GCP');
		expect(mapAsnToHosting(8075)).toBe('Azure');
	});
	it('does NOT map CDN-exclusive ASNs (those belong to the CDN tier)', async () => {
		const { mapAsnToHosting } = await import('../src/lib/cdn-asn-detection');
		expect(mapAsnToHosting(13335)).toBeNull(); // Cloudflare
		expect(mapAsnToHosting(20940)).toBeNull(); // Akamai
	});
	it('returns null for unknown ASNs', async () => {
		const { mapAsnToHosting } = await import('../src/lib/cdn-asn-detection');
		expect(mapAsnToHosting(64512)).toBeNull();
	});
});

describe('detectHostingFromAsn (Task 3)', () => {
	function mockDoh2(answers: Record<string, string>): { queryTxt: ReturnType<typeof vi.fn> } {
		return { queryTxt: vi.fn(async (name: string) => (answers[name] !== undefined ? [answers[name]] : [])) };
	}
	it('attributes a cloud host when an A-record resolves to a hosting ASN', async () => {
		const { detectHostingFromAsn } = await import('../src/lib/cdn-asn-detection');
		const doh = mockDoh2({ '20.2.0.192.origin.asn.cymru.com': '16509 | 192.0.2.0/24 | US | arin' });
		const r = await detectHostingFromAsn(['192.0.2.20'], doh);
		expect(r).toEqual({ provider: 'AWS', confidence: 'heuristic', asn: 16509 });
	});
	it('returns null when no A-record maps to a known hosting ASN', async () => {
		const { detectHostingFromAsn } = await import('../src/lib/cdn-asn-detection');
		const doh = mockDoh2({ '10.2.0.192.origin.asn.cymru.com': '13335 | 192.0.2.0/24 | US | arin' }); // CF, not hosting
		expect(await detectHostingFromAsn(['192.0.2.10'], doh)).toBeNull();
	});
});
