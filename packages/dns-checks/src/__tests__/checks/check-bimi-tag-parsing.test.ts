// SPDX-License-Identifier: BUSL-1.1

/**
 * Coverage for BIMI's tag extraction (packages/dns-checks/src/checks/check-bimi.ts).
 *
 * The record used to be read with two unanchored scans — `/\bl=([^\s;]+)/i` and
 * `/\ba=([^\s;]+)/i`. `\b` is not an anchor for these two characters: `?`, `=` and `&` are
 * all non-word, so a boundary exists before them, and a logo URL whose query string happens
 * to contain `a=` was parsed as a published mark certificate. Likewise `endsWith('.svg')`
 * rejected every CDN- or SAS-signed logo URL, and a single greedy capture swallowed the
 * spec-legal comma-separated URI list as one URL.
 *
 * Each case holds everything else constant and compares against a well-formed baseline, so a
 * failure points at the one extraction rule under test.
 */

import { describe, it, expect } from 'vitest';
import { checkBIMI, logoReferenceIsSvg, parseBimiLogoUrls, parseBimiTags } from '../../checks/check-bimi';
import type { DNSQueryFunction, FetchFunction } from '../../types';

const BIMI_DOMAIN = 'default._bimi.example.com';
const DMARC_DOMAIN = '_dmarc.example.com';
const VALID_SVG = '<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2"><title>Example Corp</title></svg>';

function dnsFor(bimiRecord: string): DNSQueryFunction {
	return (async (fqdn: string, type: string) => {
		if (fqdn === BIMI_DOMAIN && type === 'TXT') return [bimiRecord];
		if (fqdn === DMARC_DOMAIN && type === 'TXT') return ['v=DMARC1; p=reject'];
		return [];
	}) as DNSQueryFunction;
}

/** Fetch mock that records every URL it was asked for, so "was the logo even fetched" is observable. */
function recordingFetch(): { fetchFn: FetchFunction; fetched: string[] } {
	const fetched: string[] = [];
	const fetchFn = (async (input: string | URL | Request) => {
		const url = String(input);
		fetched.push(url);
		return new Response(VALID_SVG, { status: 200, headers: { 'content-type': 'image/svg+xml' } });
	}) as unknown as FetchFunction;
	return { fetchFn, fetched };
}

async function run(bimiRecord: string) {
	const { fetchFn, fetched } = recordingFetch();
	const result = await checkBIMI('example.com', dnsFor(bimiRecord), { fetchFn });
	return { result, fetched };
}

const BASELINE = 'v=BIMI1; l=https://cdn.example.com/mark.svg';

describe('parseBimiTags', () => {
	it('reads tags anchored on the delimiter and preserves the case of the value', () => {
		const tags = parseBimiTags('v=BIMI1; l=https://cdn.example.com/Mark.SVG?v=2&A=1; a=https://pki.example.com/cert');
		expect(tags.get('l')).toBe('https://cdn.example.com/Mark.SVG?v=2&A=1');
		expect(tags.get('a')).toBe('https://pki.example.com/cert');
	});

	it('does not invent a tag from a delimiter-free query string', () => {
		const tags = parseBimiTags('v=BIMI1; l=https://cdn.example.com/mark.svg?source=a=1');
		expect(tags.get('a')).toBeUndefined();
		expect(tags.get('l')).toBe('https://cdn.example.com/mark.svg?source=a=1');
	});

	it('strips the quoting the draft allows around a URL containing whitespace', () => {
		expect(parseBimiTags('v=BIMI1; l="https://cdn.example.com/my mark.svg"').get('l')).toBe('https://cdn.example.com/my mark.svg');
	});
});

describe('parseBimiLogoUrls / logoReferenceIsSvg', () => {
	it('splits the spec-legal URI list', () => {
		expect(parseBimiLogoUrls('https://a.example.com/x.svg, https://b.example.com/y.svg')).toEqual([
			'https://a.example.com/x.svg',
			'https://b.example.com/y.svg',
		]);
	});

	it('judges the SVG reference on the path, not the whole string', () => {
		expect(logoReferenceIsSvg('https://cdn.example.com/mark.svg?Policy=abc&Signature=xyz')).toBe(true);
		expect(logoReferenceIsSvg('https://cdn.example.com/mark.svg')).toBe(true);
		expect(logoReferenceIsSvg('https://cdn.example.com/mark.png?x=1.svg')).toBe(false);
	});
});

describe('checkBIMI tag extraction', () => {
	it('rates a logo URL whose query string contains a= exactly like the clean baseline', async () => {
		const tricky = await run('v=BIMI1; l=https://cdn.example.com/mark.svg?source=a=1');
		const baseline = await run(BASELINE);
		expect(tricky.result.findings.map((f) => f.title)).toEqual(baseline.result.findings.map((f) => f.title));
		expect(tricky.result.score).toBe(baseline.result.score);
		expect(tricky.result.findings.some((f) => f.title === 'BIMI authority evidence present')).toBe(false);
	});

	it('fetches a signed CDN logo URL instead of calling it invalid format', async () => {
		const { result, fetched } = await run('v=BIMI1; l=https://cdn.example.com/mark.svg?Policy=abc&Signature=xyz');
		expect(result.findings.some((f) => f.title === 'BIMI logo URL invalid format')).toBe(false);
		expect(fetched[0]).toBe('https://cdn.example.com/mark.svg?Policy=abc&Signature=xyz');
	});

	it('accepts the quoted form the draft allows for a URL containing whitespace', async () => {
		const { result } = await run('v=BIMI1; l="https://cdn.example.com/my mark.svg"');
		expect(result.findings.some((f) => f.title === 'BIMI logo URL invalid format')).toBe(false);
	});

	it('judges every entry of a URI list, while still fetching only one logo', async () => {
		const good = await run('v=BIMI1; l=https://a.example.com/x.svg,https://b.example.com/y.svg');
		expect(good.result.findings.some((f) => f.title === 'BIMI logo URL invalid format')).toBe(false);
		expect(good.fetched).toEqual(['https://a.example.com/x.svg']);

		// The finding names the offending reference, so a bad second entry cannot hide
		// behind a well-formed first one.
		const oneBad = await run('v=BIMI1; l=https://a.example.com/x.svg,http://b.example.com/y.png');
		const format = oneBad.result.findings.find((f) => f.title === 'BIMI logo URL invalid format');
		expect(format?.detail).toContain('http://b.example.com/y.png');
		expect(format?.detail).toContain('must use HTTPS and must be an SVG file');

		const twoBad = await run('v=BIMI1; l=https://a.example.com/x.svg,http://b.example.com/y.png,https://c.example.com/z.gif');
		expect(twoBad.result.findings.find((f) => f.title === 'BIMI logo URL invalid format')?.detail).toContain('2 of 3 logo URLs are invalid');
	});

	it('still reports a genuinely published a= tag', async () => {
		const { result } = await run('v=BIMI1; l=https://cdn.example.com/mark.svg; a=https://pki.example.com/cert');
		expect(result.findings.some((f) => f.title === 'BIMI authority evidence present')).toBe(true);
	});
});
