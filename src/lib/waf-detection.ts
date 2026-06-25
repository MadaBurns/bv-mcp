// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared WAF/CDN interception detection.
 *
 * The scanner runs inside a Cloudflare Worker, and many origins (including
 * Cloudflare-fronted ones) answer an automated probe with a WAF challenge or
 * access-block page — commonly served as HTTP 403 — instead of the real
 * resource. Reading such a page as if it were the resource produces false
 * findings (e.g. "MTA-STS policy file not accessible" on a policy that every
 * browser/MTA can actually fetch). These helpers fingerprint that interception
 * so callers can mark the result inconclusive rather than emit a confident
 * failure.
 *
 * Extracted from `check-http-security.ts` (where this logic originated) so the
 * MTA-STS policy fetch can reuse the identical detection — issue #455.
 */

/** A detected WAF interception — either an interstitial challenge or a terminal block. */
export type WafEvent = { provider: 'cloudflare' | 'akamai'; kind: 'challenge' | 'block' };

/** Cloudflare access-block body signatures (distinct from the "Just a moment" JS challenge). */
const CF_BLOCK_BODY = /sorry, you have been blocked|attention required|error 10(09|10|12|13|15|20)/i;

/** True when the response carries any Cloudflare/Akamai signal worth fetching the body to disambiguate. */
export function looksLikeWaf(headers: Headers): boolean {
	const server = (headers.get('server') ?? '').toLowerCase();
	return !!(headers.get('cf-ray') || headers.get('cf-mitigated') || server.includes('cloudflare') || server.includes('akamaighost'));
}

/**
 * Detect a WAF interception (challenge or block) from response headers, optional body, and status.
 *
 * Cloudflare events are commonly served as HTTP 403 (both the JS challenge and access blocks),
 * so detection is status-aware. A block requires a 4xx plus a block-body signature or a
 * `cf-mitigated` header — `cf-ray` + 403 alone is NOT treated as a block, since a real app may
 * legitimately 403 a request. The interstitial challenge is checked first.
 */
export function detectWafEvent(headers: Headers, body: string | undefined, status: number): WafEvent | null {
	const server = (headers.get('server') ?? '').toLowerCase();
	const cfRay = headers.get('cf-ray');
	const cfMitigated = headers.get('cf-mitigated');
	const b = body ?? '';

	if (cfRay || cfMitigated || server.includes('cloudflare')) {
		if (/just a moment/i.test(b) || cfMitigated === 'challenge') return { provider: 'cloudflare', kind: 'challenge' };
		if (status >= 400 && (CF_BLOCK_BODY.test(b) || !!cfMitigated)) return { provider: 'cloudflare', kind: 'block' };
	}
	if (server.includes('akamaighost')) return { provider: 'akamai', kind: 'block' };
	return null;
}
