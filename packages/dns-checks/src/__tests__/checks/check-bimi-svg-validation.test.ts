// SPDX-License-Identifier: BUSL-1.1

/**
 * Coverage for `validateBimiSvg` (packages/dns-checks/src/checks/check-bimi.ts), the BIMI
 * logo-fetch-and-validate helper. It is not exported, so it is driven through the public
 * `checkBIMI` entry point with a mocked DNS resolver (a BIMI TXT record carrying `l=`) and a
 * mocked `fetchFn` returning canned SVG responses — the same pattern check-bimi-robots.test.ts
 * and check-bimi-non-sending.test.ts already use for this module.
 *
 * Each case below isolates exactly one rule `validateBimiSvg` enforces (per the source at the
 * time of writing: redirect, non-2xx status, size cap, Content-Type, script-tag prohibition,
 * missing baseProfile="tiny-ps", fetch failure/timeout, and the all-clear pass) by holding every
 * other rule satisfied, so a failing assertion points at the one rule under test.
 */

import { describe, it, expect } from 'vitest';
import { checkBIMI } from '../../checks/check-bimi';
import { RobotsDisallowedError } from '../../robots-gate';
import type { DNSQueryFunction, FetchFunction } from '../../types';

const BIMI_DOMAIN = 'default._bimi.example.com';
const DMARC_DOMAIN = '_dmarc.example.com';
const LOGO_URL = 'https://example.com/logo.svg';

// DMARC enforcing (p=reject) so the BIMI record is treated as functional, and a BIMI TXT
// record whose l= tag points at LOGO_URL, so `checkBIMI` always reaches `validateBimiSvg`.
const bimiTxt = `v=BIMI1; l=${LOGO_URL}; a=https://example.com/vmc.pem`;
const dmarcEnforcing = 'v=DMARC1; p=reject';

function makeQueryDNS(): DNSQueryFunction {
	return (async (fqdn: string, type: string) => {
		if (fqdn === BIMI_DOMAIN && type === 'TXT') return [bimiTxt];
		if (fqdn === DMARC_DOMAIN && type === 'TXT') return [dmarcEnforcing];
		return [];
	}) as DNSQueryFunction;
}

/** A minimal, otherwise-valid BIMI SVG Tiny PS logo: correct baseProfile, no script tags. */
const VALID_SVG = '<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2"><title>Example Corp</title></svg>';

function svgResponse(body: string, init?: ResponseInit): Response {
	return new Response(body, {
		status: 200,
		...init,
		headers: { 'content-type': 'image/svg+xml', ...(init?.headers as Record<string, string> | undefined) },
	});
}

async function runWithFetch(fetchFn: FetchFunction) {
	return checkBIMI('example.com', makeQueryDNS(), { fetchFn });
}

/**
 * Only the findings `validateBimiSvg` itself can emit (title prefix "BIMI logo"). The bimiTxt
 * fixture's `a=` tag always earns checkBIMI its own "BIMI authority evidence present" finding
 * before validateBimiSvg ever runs, so isolating one SVG rule means filtering that out rather
 * than asserting on `result.findings` directly.
 */
function logoFindings(result: Awaited<ReturnType<typeof checkBIMI>>) {
	return result.findings.filter((f) => f.title.startsWith('BIMI logo'));
}

describe('checkBIMI → validateBimiSvg', () => {
	it('a valid minimal SVG Tiny PS logo passes every rule', async () => {
		const result = await runWithFetch(async () => svgResponse(VALID_SVG));
		const validated = result.findings.find((f) => f.title === 'BIMI logo SVG validated');
		expect(validated).toBeDefined();
		expect(validated!.severity).toBe('info');
		// No rule finding fired alongside the pass.
		expect(result.findings.some((f) => f.title.startsWith('BIMI logo') && f.title !== 'BIMI logo SVG validated')).toBe(false);
	});

	it('a redirect response is flagged and short-circuits further validation', async () => {
		const result = await runWithFetch(
			async () => new Response(null, { status: 302, headers: { location: 'https://example.com/moved-logo.svg' } }),
		);
		const finding = result.findings.find((f) => f.title === 'BIMI logo URL redirects');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
		expect(finding!.detail).toContain('302');
		// Redirect returns immediately — no Content-Type/size/script/baseProfile findings follow.
		expect(result.findings.some((f) => f.title === 'BIMI logo SVG validated')).toBe(false);
		expect(result.findings.some((f) => f.title === 'BIMI logo missing baseProfile="tiny-ps"')).toBe(false);
	});

	it('a non-2xx, non-redirect status is flagged as inaccessible', async () => {
		const result = await runWithFetch(async () => new Response('Not Found', { status: 404 }));
		const finding = result.findings.find((f) => f.title === 'BIMI logo URL not accessible');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
		expect(finding!.detail).toContain('404');
	});

	it('a body over the 32 KB cap is flagged and short-circuits further validation', async () => {
		const oversized = `<svg baseProfile="tiny-ps">${'x'.repeat(33 * 1024)}</svg>`;
		const result = await runWithFetch(async () => svgResponse(oversized));
		const finding = result.findings.find((f) => f.title === 'BIMI logo exceeds 32 KB');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
		// Size check returns immediately — a script tag or missing baseProfile in the (unread)
		// remainder must not also be reported.
		expect(logoFindings(result)).toHaveLength(1);
	});

	it('a wrong Content-Type is flagged on its own when the body is otherwise valid', async () => {
		const result = await runWithFetch(async () => svgResponse(VALID_SVG, { headers: { 'content-type': 'text/plain' } }));
		const finding = result.findings.find((f) => f.title === 'BIMI logo wrong Content-Type');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.detail).toContain('text/plain');
		// Content-Type does not short-circuit, but the body still passes every other rule.
		expect(logoFindings(result)).toHaveLength(1);
	});

	it('a missing/empty Content-Type header is reported with "(none)"', async () => {
		// A bare string body can make the platform's Response constructor default
		// Content-Type on its own, so the header is removed explicitly rather than
		// assumed absent — this test is about the missing-header branch, not the
		// constructor's defaulting behavior.
		const response = new Response(VALID_SVG, { status: 200 });
		response.headers.delete('content-type');
		expect(response.headers.get('content-type')).toBeNull();
		const result = await runWithFetch(async () => response);
		const finding = result.findings.find((f) => f.title === 'BIMI logo wrong Content-Type');
		expect(finding).toBeDefined();
		expect(finding!.detail).toContain('(none)');
	});

	it('a <script> element is flagged as high severity when the profile is otherwise valid', async () => {
		const withScript = '<svg baseProfile="tiny-ps"><script>alert(1)</script></svg>';
		const result = await runWithFetch(async () => svgResponse(withScript));
		const finding = result.findings.find((f) => f.title === 'BIMI logo contains script tags');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
		// baseProfile is present, so only the script finding should fire.
		expect(logoFindings(result)).toHaveLength(1);
	});

	it('a script tag with attributes before the closing bracket is still caught', async () => {
		const withScript = '<svg baseProfile="tiny-ps"><script type="text/javascript">alert(1)</script></svg>';
		const result = await runWithFetch(async () => svgResponse(withScript));
		expect(result.findings.some((f) => f.title === 'BIMI logo contains script tags')).toBe(true);
	});

	it('a missing baseProfile="tiny-ps" is flagged as medium severity when otherwise clean', async () => {
		const noBaseProfile = '<svg xmlns="http://www.w3.org/2000/svg"><title>Example Corp</title></svg>';
		const result = await runWithFetch(async () => svgResponse(noBaseProfile));
		const finding = result.findings.find((f) => f.title === 'BIMI logo missing baseProfile="tiny-ps"');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		// No script tag present, so only the baseProfile finding should fire.
		expect(logoFindings(result)).toHaveLength(1);
	});

	it('a baseProfile using single quotes is still recognized', async () => {
		const singleQuoted = "<svg baseProfile='tiny-ps'></svg>";
		const result = await runWithFetch(async () => svgResponse(singleQuoted));
		expect(result.findings.some((f) => f.title === 'BIMI logo missing baseProfile="tiny-ps"')).toBe(false);
	});

	it('a wrong baseProfile value (not tiny-ps) is still reported as missing', async () => {
		const wrongProfile = '<svg baseProfile="tiny"></svg>';
		const result = await runWithFetch(async () => svgResponse(wrongProfile));
		expect(result.findings.some((f) => f.title === 'BIMI logo missing baseProfile="tiny-ps"')).toBe(true);
	});

	it('a body that fails BOTH the script and baseProfile rules reports both findings', async () => {
		const bothIssues = '<svg><script>alert(1)</script></svg>';
		const result = await runWithFetch(async () => svgResponse(bothIssues));
		expect(result.findings.some((f) => f.title === 'BIMI logo contains script tags')).toBe(true);
		expect(result.findings.some((f) => f.title === 'BIMI logo missing baseProfile="tiny-ps"')).toBe(true);
		expect(result.findings.some((f) => f.title === 'BIMI logo SVG validated')).toBe(false);
	});

	it('a network failure (non-timeout) is reported as "fetch failed"', async () => {
		const result = await runWithFetch(async () => {
			throw new TypeError('network error');
		});
		const finding = result.findings.find((f) => f.title === 'BIMI logo fetch failed');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('a timeout/abort error is reported as "fetch timed out", not a generic failure', async () => {
		const result = await runWithFetch(async () => {
			throw new Error('The operation was aborted due to timeout');
		});
		const finding = result.findings.find((f) => f.title === 'BIMI logo fetch timed out');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
		expect(result.findings.some((f) => f.title === 'BIMI logo fetch failed')).toBe(false);
	});

	it('a robots.txt disallow abstains with an info finding instead of penalizing the fetch', async () => {
		// Full behavioral coverage of this branch (wording per scope, metadata shape) lives in
		// check-bimi-robots.test.ts; this asserts only that validateBimiSvg's catch routes here
		// rather than into the generic "fetch failed"/"timed out" findings, for this function's
		// own coverage.
		const result = await runWithFetch(async () => {
			throw new RobotsDisallowedError(LOGO_URL, 'blanket');
		});
		expect(result.findings.some((f) => f.title.includes('robots.txt'))).toBe(true);
		expect(result.findings.some((f) => f.title === 'BIMI logo fetch failed')).toBe(false);
		expect(result.findings.some((f) => f.title === 'BIMI logo fetch timed out')).toBe(false);
	});
});
