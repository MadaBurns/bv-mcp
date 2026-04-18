// SPDX-License-Identifier: BUSL-1.1

/**
 * HTTP security headers check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all analysis to the shared package.
 * Post-augments with CDN provider detection from response headers.
 *
 * Dual-fetch with header union (stability fix): fires two parallel HEAD fetches
 * to eliminate score fluctuations caused by CDN edge nodes returning different
 * security header sets. Headers are merged (union semantics) before being
 * passed to the package's analysis layer.
 */

import { checkHTTPSecurity } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { buildCheckResult, createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';

/** User-Agent for outbound probes — matches the package's scanner UA. */
const SCANNER_USER_AGENT = 'Mozilla/5.0 (compatible; BlackVeilDNSScanner/1.0; +https://blackveilsecurity.com)';

/** WAF/CDN challenge page fingerprints. Matched against response headers (and optionally body). */
const WAF_CHALLENGE_FINGERPRINTS: Array<{
	name: string;
	matchHeaders: (h: Headers) => boolean;
	matchBody?: (body: string) => boolean;
}> = [
	{
		name: 'cloudflare',
		// cf-ray header is conclusive on its own; body title is a belt-and-suspenders signal
		matchHeaders: (h) =>
			!!(h.get('cf-ray') && (h.get('server') ?? '').toLowerCase().includes('cloudflare')),
		matchBody: (body) => /just a moment/i.test(body),
	},
	{
		name: 'akamai',
		matchHeaders: (h) => (h.get('server') ?? '').toLowerCase().includes('akamaighost'),
	},
];

/**
 * Detect a WAF/CDN challenge page from response headers and optional body.
 * Returns the WAF provider name if matched, null otherwise.
 */
function detectWafChallenge(headers: Headers, body?: string): string | null {
	for (const fp of WAF_CHALLENGE_FINGERPRINTS) {
		if (!fp.matchHeaders(headers)) continue;
		// If a body matcher is defined, at least one of headers or body must match
		if (fp.matchBody && body !== undefined && !fp.matchBody(body)) continue;
		return fp.name;
	}
	return null;
}

/** Security headers to merge (union) across dual fetches. */
const MERGE_HEADERS = [
	'content-security-policy',
	'x-frame-options',
	'x-content-type-options',
	'permissions-policy',
	'referrer-policy',
	'cross-origin-resource-policy',
	'cross-origin-opener-policy',
	'cross-origin-embedder-policy',
] as const;

/** Maximum manual redirect hops to follow during dual-fetch probes. */
const MAX_REDIRECT_HOPS = 3;

/** Detect CDN provider from HTTP response headers. Returns provider name or null. */
function detectCdnProvider(headers: Headers): string | null {
	if (headers.get('cf-ray') || headers.get('server')?.toLowerCase().includes('cloudflare')) {
		return 'Cloudflare';
	}
	if (headers.get('x-vercel-id') || headers.get('x-vercel-cache')) {
		return 'Vercel';
	}
	if (headers.get('x-amz-cf-id') || headers.get('via')?.includes('CloudFront')) {
		return 'CloudFront';
	}
	const servedBy = headers.get('x-served-by') ?? '';
	if (servedBy.includes('cache') || headers.get('via')?.toLowerCase().includes('varnish')) {
		return 'Fastly';
	}
	if (headers.get('x-akamai-transformed') || headers.get('x-check-cacheable')) {
		return 'Akamai';
	}
	return null;
}

/**
 * Fetch a URL with HEAD and follow up to 3 HTTPS redirects manually.
 * Mirrors the package's own redirect follow logic — used only for the
 * dual-fetch probe ahead of the package call.
 */
async function fetchWithRedirects(url: string, timeoutMs: number): Promise<Response> {
	let response = await fetch(url, {
		method: 'HEAD',
		redirect: 'manual',
		headers: { 'User-Agent': SCANNER_USER_AGENT },
		signal: AbortSignal.timeout(timeoutMs),
	});

	for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
		const status = response.status;
		const isRedirect =
			(status >= 300 && status < 400) ||
			response.type === 'opaqueredirect' ||
			(status === 0 && response.headers.get('location'));
		if (!isRedirect) break;

		const location = response.headers.get('location');
		if (!location) break;

		let nextUrl: string;
		try {
			nextUrl = new URL(location, response.url || undefined).href;
		} catch {
			break;
		}
		if (!nextUrl.startsWith('https://')) break;

		try {
			response = await fetch(nextUrl, {
				method: 'HEAD',
				redirect: 'manual',
				headers: { 'User-Agent': SCANNER_USER_AGENT },
				signal: AbortSignal.timeout(timeoutMs),
			});
		} catch {
			break;
		}
	}

	return response;
}

/**
 * Merge security headers from two responses using union semantics.
 * If a security header exists in either response, it is included in the result.
 * Non-security headers are preserved from the primary response, with any
 * additional non-security headers from the secondary response also included
 * (useful for CDN detection).
 */
function mergeSecurityHeaders(a: Headers, b: Headers): Headers {
	const merged = new Headers();
	// Copy everything from response A first (primary)
	a.forEach((value, key) => merged.set(key, value));
	// Union the security headers from B — only fill gaps, don't overwrite
	for (const header of MERGE_HEADERS) {
		if (!merged.has(header) && b.has(header)) {
			merged.set(header, b.get(header)!);
		}
	}
	// Copy any non-security headers from B that A didn't have (for CDN detection)
	b.forEach((value, key) => {
		if (!merged.has(key)) merged.set(key, value);
	});
	return merged;
}

/**
 * Fire two parallel HEAD fetches and return merged headers when at least one
 * returned a usable (2xx/3xx) response. Returns `null` when neither response
 * is usable so the package's own fetch path (including GET fallback for
 * 403/405) handles the error branch.
 */
async function dualFetchHeaders(
	domain: string,
	timeoutMs: number,
): Promise<{ headers: Headers; ok: boolean; status: number } | null> {
	const url = `https://${domain}`;
	const results = await Promise.allSettled([fetchWithRedirects(url, timeoutMs), fetchWithRedirects(url, timeoutMs)]);

	const responses = results
		.filter((r): r is PromiseFulfilledResult<Response> => r.status === 'fulfilled')
		.map((r) => r.value);

	if (responses.length === 0) return null;

	// Only use dual-fetch results when at least one response is usable (2xx or 3xx).
	// If both are 403/405/4xx, return null so the package's GET-fallback handles it.
	const usable = responses.filter((r) => r.ok || (r.status >= 300 && r.status < 400));
	if (usable.length === 0) return null;

	if (usable.length === 1) {
		return { headers: usable[0].headers, ok: usable[0].ok, status: usable[0].status };
	}

	const merged = mergeSecurityHeaders(usable[0].headers, usable[1].headers);
	const primary = usable[0].ok ? usable[0] : usable[1].ok ? usable[1] : usable[0];
	return { headers: merged, ok: primary.ok, status: primary.status };
}

/**
 * Fetch the page body for WAF challenge fingerprinting.
 * Returns an empty string on error (fail-open — WAF detection should not block normal analysis).
 */
async function fetchBodyForWafDetection(url: string, timeoutMs: number): Promise<string> {
	try {
		const response = await fetch(url, {
			method: 'GET',
			redirect: 'manual',
			headers: { 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(timeoutMs),
		});
		return await response.text();
	} catch {
		return '';
	}
}

/**
 * Check HTTP security headers for a domain.
 *
 * Strategy: fire two parallel HEAD fetches, union the security headers, then
 * pass a synthetic Response with the merged headers to `checkHTTPSecurity()`
 * from the package. If both probes fail (or both return non-usable statuses
 * like 403/405), fall through to the package's own fetch so it can surface
 * the right error finding (connection failed, WAF block with GET fallback,
 * etc.).
 *
 * Also detects CDN provider from the analyzed headers and adds an info
 * finding when a CDN is fronting the origin.
 *
 * WAF/CDN challenge pages are fingerprinted early (after the dual-fetch)
 * and short-circuit the header analysis — returning checkStatus='error'
 * with a single info finding instead of misleading header-missing findings.
 */
export async function checkHttpSecurity(domain: string): Promise<CheckResult> {
	const dualResult = await dualFetchHeaders(domain, HTTPS_TIMEOUT_MS);

	// WAF/CDN challenge detection — short-circuit before header analysis
	if (dualResult) {
		const headersForWaf = dualResult.headers;
		const needsBody = WAF_CHALLENGE_FINGERPRINTS.some((fp) => fp.matchHeaders(headersForWaf) && fp.matchBody);
		const body = needsBody ? await fetchBodyForWafDetection(`https://${domain}`, HTTPS_TIMEOUT_MS) : undefined;
		const wafName = detectWafChallenge(headersForWaf, body);
		if (wafName) {
			const finding = createFinding(
				'http_security',
				`${wafName.charAt(0).toUpperCase() + wafName.slice(1)} WAF challenge intercepted`,
				'info',
				`The fetched response appears to be a WAF/CDN challenge page, not the real site. Header analysis is inconclusive.`,
				{ wafChallenge: wafName, inconclusive: true },
			);
			const base = buildCheckResult('http_security', [finding]);
			return { ...base, checkStatus: 'error' };
		}
	}

	let capturedHeaders: Headers | null = null;

	const capturingFetch: typeof fetch = async (input, init) => {
		if (dualResult) {
			capturedHeaders = dualResult.headers;
			// Synthetic response with the merged headers — the package will
			// analyze this as if it were the real response.
			return new Response(null, {
				status: dualResult.status,
				headers: dualResult.headers,
			});
		}
		// Dual-fetch unusable — delegate to the real fetch so the package
		// can run its own error handling and GET fallback.
		const response = await fetch(input, init);
		capturedHeaders = response.headers;
		return response;
	};

	const result = (await checkHTTPSecurity(domain, capturingFetch, { timeout: HTTPS_TIMEOUT_MS })) as CheckResult;

	if (!capturedHeaders) return result;

	const cdnProvider = detectCdnProvider(capturedHeaders);
	if (!cdnProvider) return result;

	// Only annotate CDN when headers were actually analyzed.
	// If the check was blocked (WAF, connection refused, etc.) or timed out,
	// capturedHeaders may reflect the error response, not the security response.
	const isUnanalyzable =
		result.checkStatus === 'error' ||
		result.checkStatus === 'timeout' ||
		result.findings.some((f) => f.metadata?.missingControl === true);
	if (isUnanalyzable) return result;

	const cdnFinding = createFinding(
		'http_security',
		`HTTP headers via ${cdnProvider} CDN`,
		'info',
		`HTTP security headers may be provided by ${cdnProvider} CDN rather than the origin server. CDN-applied headers do not reflect the origin server's security configuration.`,
		{ cdnProvider },
	);

	return { ...result, findings: [...result.findings, cdnFinding] };
}
