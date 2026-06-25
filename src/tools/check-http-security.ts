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
import { safeFetch } from '../lib/safe-fetch';
import { composeSignal, withAbortSignal } from '../lib/abort-signal';
import { looksLikeWaf, detectWafEvent } from '../lib/waf-detection';

/** User-Agent for outbound probes — matches the package's scanner UA. */
const SCANNER_USER_AGENT = 'Mozilla/5.0 (compatible; BlackVeilDNSScanner/1.0; +https://blackveilsecurity.com)';

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
const MAX_REDIRECT_HOPS = 5;

/**
 * Vendor-specific, origin-set CDN headers worth carrying forward across redirect
 * hops. These are exactly the tier-1 signals `detectCdnProvider` inspects — they
 * cannot be injected by a transit edge (unlike `server`, which the Cloudflare
 * Worker egress rewrites to `cloudflare` on every hop; see v3.3.12 lesson). A CDN
 * commonly fronts the FINAL hop of a chain (e.g. apex → intermediate → CDN-fronted
 * target), but the signal can also appear on an intermediate hop; the final
 * response captured for security analysis would otherwise lose it.
 *
 * `server` is deliberately excluded — carrying it forward would resurrect the
 * 100%-false-positive Cloudflare bug.
 */
const CDN_SIGNAL_HEADERS = [
	'x-cdn',
	'x-iinfo',
	'x-sucuri-id',
	'x-sucuri-cache',
	'x-vercel-id',
	'x-vercel-cache',
	'x-amz-cf-id',
	'via',
	'x-akamai-transformed',
	'x-check-cacheable',
	'x-served-by',
] as const;

/** Copy any CDN-signal headers present on `from` into `into` (first writer wins). */
function accumulateCdnSignals(into: Headers, from: Headers): void {
	for (const header of CDN_SIGNAL_HEADERS) {
		const value = from.get(header);
		if (value !== null && !into.has(header)) into.set(header, value);
	}
}

/**
 * Detect CDN provider from HTTP response headers. Returns provider name or null.
 *
 * Vendor-specific high-precision headers are checked BEFORE generic Cloudflare
 * signals, because `cf-ray` alone is not a reliable origin-CDN signal: the
 * scanner runs inside a Cloudflare Worker, and Cloudflare's edge adds `cf-ray`
 * to the response of every outbound `fetch()` for tracing — even when the
 * origin is on Imperva, Akamai, AWS, etc. Detecting Cloudflare requires an
 * origin-set signal (`server: cloudflare`, `cf-cache-status`, or `cf-mitigated`),
 * not just a `cf-ray` that may have been injected by our own egress.
 */
function detectCdnProvider(headers: Headers): string | null {
	// 1. Vendor-specific headers (high-precision, can't be spoofed by transit edges).
	if (headers.get('x-cdn')?.toLowerCase() === 'imperva' || headers.get('x-iinfo')) {
		return 'Imperva';
	}
	if (headers.get('x-sucuri-id') || headers.get('x-sucuri-cache')) {
		return 'Sucuri';
	}
	if (headers.get('x-vercel-id') || headers.get('x-vercel-cache')) {
		return 'Vercel';
	}
	if (headers.get('x-amz-cf-id') || headers.get('via')?.includes('CloudFront')) {
		return 'CloudFront';
	}
	if (headers.get('x-akamai-transformed') || headers.get('x-check-cacheable')) {
		return 'Akamai';
	}
	const servedBy = headers.get('x-served-by') ?? '';
	if (servedBy.includes('cache') || headers.get('via')?.toLowerCase().includes('varnish')) {
		return 'Fastly';
	}
	// 2. Cloudflare — **removed.** No header-based detection of Cloudflare is
	// possible when the scanner runs from inside a Cloudflare Worker, because
	// CF's outbound `fetch()` infrastructure rewrites the response's `server`
	// header to `cloudflare` on EVERY response — confirmed empirically by
	// v3.3.11's diagnostic instrumentation, which observed `server: cloudflare`
	// on responses from google.com (origin: `server: gws`) and github.com
	// (origin: `server: github.com`). `cf-ray` is added for tracing and
	// `cf-cache-status: DYNAMIC` is added by CF's edge cache layer. None of
	// these signals can distinguish "origin is on CF" from "response transited
	// CF's edge", so this function returns null for Cloudflare. The
	// vendor-specific rules above (Imperva, Sucuri, Vercel, CloudFront,
	// Akamai, Fastly) still work because they use origin-set headers that
	// CF cannot impersonate.
	//
	// NOTE: Cloudflare customers are NOT undetected overall — the header path
	// just abstains. The scan-level CDN attribution closes the CF case via the
	// ASN tier (`src/lib/cdn-asn-detection.ts`, v3.3.20): the apex A-record
	// resolves to AS13335 → "Cloudflare", origin-set and immune to the
	// `server:` rewrite. Verified live (discord.com, 1password.com →
	// "Cloudflare"). That is the IP-range/ASN path foreshadowed here; it lives
	// in the post-processing CDN tier, not in this header function.
	return null;
}

/**
 * The final response of a redirect chain, plus a union of vendor-specific CDN
 * signal headers observed only on the chain's INTERMEDIATE (redirecting) hops.
 * The final response keeps its own headers intact (inspect them directly for the
 * ORIGIN's CDN); `edgeSignals` captures any CDN fronting a redirect hop (e.g. an
 * apex 301 served by CloudFront ahead of a Fastly-served www origin) so the two
 * can be attributed separately ("origin: Fastly, edge: CloudFront") instead of
 * the edge signal shadowing the origin.
 */
type RedirectResult = { response: Response; edgeSignals: Headers };

/**
 * Fetch a URL with HEAD and follow up to MAX_REDIRECT_HOPS HTTPS redirects
 * manually. Mirrors the package's own redirect follow logic — used only for the
 * dual-fetch probe ahead of the package call. Accumulates vendor-specific CDN
 * headers from each hop that REDIRECTS (intermediate hops only) into
 * `edgeSignals`; the final (non-redirect) response is returned with its own
 * headers untouched so origin-vs-edge CDN attribution stays distinct.
 */
async function fetchWithRedirects(url: string, timeoutMs: number, callerSignal?: AbortSignal): Promise<RedirectResult> {
	const edgeSignals = new Headers();
	// Initial fetch goes to https://<domain> where <domain> is already validated
	// upstream. Use raw fetch to keep the cost off the validation path. Subsequent
	// redirect targets ARE attacker-controlled (Location header) and go via
	// safeFetch (H3 fix from 2026-05-08 security audit).
	//
	// R7: compose the per-fetch timeout with the caller's scan-/per-check-level
	// abort signal so a scan timeout cancels the in-flight HTTPS probe instead of
	// orphaning the subrequest. Absent caller signal → timeout-only (unchanged).
	let response = await fetch(
		url,
		composeSignal(
			{
				method: 'HEAD',
				redirect: 'manual',
				headers: { 'User-Agent': SCANNER_USER_AGENT },
				signal: AbortSignal.timeout(timeoutMs),
			},
			callerSignal,
		),
	);

	for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
		const status = response.status;
		const isRedirect =
			(status >= 300 && status < 400) || response.type === 'opaqueredirect' || (status === 0 && response.headers.get('location'));
		if (!isRedirect) break;

		// This hop redirects, so it is an intermediate/edge hop — harvest its CDN
		// signals into edgeSignals BEFORE following. The hop we eventually stop on
		// (non-redirect) is the origin and is left out of edgeSignals.
		accumulateCdnSignals(edgeSignals, response.headers);

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
			response = await safeFetch(
				nextUrl,
				composeSignal(
					{
						method: 'HEAD',
						redirect: 'manual',
						headers: { 'User-Agent': SCANNER_USER_AGENT },
						signal: AbortSignal.timeout(timeoutMs),
					},
					callerSignal,
				),
			);
		} catch {
			// safeFetch throws TypeError on a blocked target (SSRF protection); fall
			// out of the redirect loop and let analysis run with whatever headers we
			// already collected. Treat exactly like a network error — it's a hostile
			// redirect destination, not a real failure.
			break;
		}
	}

	return { response, edgeSignals };
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
	callerSignal?: AbortSignal,
): Promise<{ headers: Headers; edgeSignals: Headers; ok: boolean; status: number; usable: boolean } | null> {
	const url = `https://${domain}`;
	const results = await Promise.allSettled([
		fetchWithRedirects(url, timeoutMs, callerSignal),
		fetchWithRedirects(url, timeoutMs, callerSignal),
	]);

	const settled = results.filter((r): r is PromiseFulfilledResult<RedirectResult> => r.status === 'fulfilled').map((r) => r.value);

	if (settled.length === 0) return null;

	// Union of vendor-specific CDN signals seen on the INTERMEDIATE (redirecting)
	// hops of EITHER probe's chain. Returned alongside (NOT folded into) the
	// analysed headers so the caller can attribute the redirector's CDN (edge)
	// separately from the final origin's own headers, instead of an edge signal
	// shadowing the origin. Not in MERGE_HEADERS, so security analysis is unaffected.
	const edgeSignals = new Headers();
	for (const s of settled) accumulateCdnSignals(edgeSignals, s.edgeSignals);

	const responses = settled.map((s) => s.response);

	// Only treat 2xx/3xx as usable headers for analysis.
	const usable = responses.filter((r) => r.ok || (r.status >= 300 && r.status < 400));
	if (usable.length === 0) {
		// Both probes are 4xx. Surface a Cloudflare-flagged response so WAF-event detection can
		// attribute/short-circuit it; otherwise return null so the package's GET-fallback handles
		// it as a generic block. usable:false means "don't analyze these headers as the site's".
		const cf = responses.find((r) => looksLikeWaf(r.headers));
		if (cf) return { headers: cf.headers, edgeSignals, ok: false, status: cf.status, usable: false };
		return null;
	}

	if (usable.length === 1) {
		return { headers: usable[0].headers, edgeSignals, ok: usable[0].ok, status: usable[0].status, usable: true };
	}

	const merged = mergeSecurityHeaders(usable[0].headers, usable[1].headers);
	const primary = usable[0].ok ? usable[0] : usable[1].ok ? usable[1] : usable[0];
	return { headers: merged, edgeSignals, ok: primary.ok, status: primary.status, usable: true };
}

/**
 * Fetch the page body for WAF challenge fingerprinting.
 * Returns an empty string on error (fail-open — WAF detection should not block normal analysis).
 */
async function fetchBodyForWafDetection(url: string, timeoutMs: number, callerSignal?: AbortSignal): Promise<string> {
	try {
		const response = await fetch(
			url,
			composeSignal(
				{
					method: 'GET',
					redirect: 'manual',
					headers: { 'User-Agent': SCANNER_USER_AGENT },
					signal: AbortSignal.timeout(timeoutMs),
				},
				callerSignal,
			),
		);
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
/**
 * Total wall-clock budget across all fetches (dual-fetch + WAF body + package
 * GET fallback). Protects against compound timeouts when remote hosts stall
 * partway through the handshake. Production telemetry (2026-04-25 probe)
 * observed a single domain driving p99 to 28s — this cap guarantees any
 * single-domain pathology stays well under the Cloudflare Worker CPU ceiling.
 */
const TOTAL_BUDGET_MS = 10_000;

export async function checkHttpSecurity(domain: string, options: { signal?: AbortSignal } = {}): Promise<CheckResult> {
	let budgetTimeoutId: ReturnType<typeof setTimeout> | undefined;
	const budgetExceeded = new Promise<'budget_exceeded'>((resolve) => {
		budgetTimeoutId = setTimeout(() => resolve('budget_exceeded'), TOTAL_BUDGET_MS);
	});
	try {
		const raced = await Promise.race([checkHttpSecurityInner(domain, options.signal), budgetExceeded]);
		if (raced === 'budget_exceeded') {
			const finding = createFinding(
				'http_security',
				'HTTP security check timed out',
				'high',
				`Could not complete HTTP security header analysis for ${domain} within ${TOTAL_BUDGET_MS}ms. Host was likely unreachable or extremely slow.`,
				{ missingControl: true, confidence: 'heuristic', errorKind: 'timeout' },
			);
			const base = buildCheckResult('http_security', [finding]);
			return { ...base, score: 0, passed: false, checkStatus: 'timeout' };
		}
		return raced;
	} finally {
		if (budgetTimeoutId !== undefined) clearTimeout(budgetTimeoutId);
	}
}

async function checkHttpSecurityInner(domain: string, callerSignal?: AbortSignal): Promise<CheckResult> {
	const dualResult = await dualFetchHeaders(domain, HTTPS_TIMEOUT_MS, callerSignal);

	// WAF/CDN event detection — runs on usable (2xx/3xx) AND Cloudflare-flagged 4xx responses,
	// short-circuiting before header analysis so a challenge/block page is never mis-read as the site.
	if (dualResult) {
		const headersForWaf = dualResult.headers;
		const body = looksLikeWaf(headersForWaf)
			? await fetchBodyForWafDetection(`https://${domain}`, HTTPS_TIMEOUT_MS, callerSignal)
			: undefined;
		const event = detectWafEvent(headersForWaf, body, dualResult.status);
		if (event) {
			const provider = event.provider.charAt(0).toUpperCase() + event.provider.slice(1);
			const finding = createFinding(
				'http_security',
				event.kind === 'block' ? `${provider} WAF blocked external header inspection` : `${provider} WAF challenge intercepted`,
				'info',
				event.kind === 'block'
					? `https://${domain} returned an HTTP ${dualResult.status} ${provider} block page, not the site. Security headers cannot be inspected externally.`
					: `The fetched response appears to be a ${provider} challenge page, not the real site. Header analysis is inconclusive.`,
				{
					wafEvent: event.provider,
					wafKind: event.kind,
					// Back-compat: challenges previously carried `wafChallenge` with the provider name.
					...(event.kind === 'challenge' ? { wafChallenge: event.provider } : {}),
					httpStatus: dualResult.status,
					inconclusive: true,
					missingControl: true,
				},
			);
			const base = buildCheckResult('http_security', [finding]);
			return { ...base, score: 0, passed: false, checkStatus: 'error' };
		}
	}

	let capturedHeaders: Headers | null = null;

	const capturingFetch: typeof fetch = async (input, init) => {
		// Only feed the dual-fetch headers to the package when they came from a usable (2xx/3xx)
		// response. A non-event 4xx (usable:false) falls through to the package's GET-fallback,
		// which surfaces the generic "blocked by security appliance" finding.
		if (dualResult && dualResult.usable) {
			capturedHeaders = dualResult.headers;
			// Synthetic response with the merged headers — the package will
			// analyze this as if it were the real response.
			return new Response(null, {
				status: dualResult.status,
				headers: dualResult.headers,
			});
		}
		// Dual-fetch unusable — delegate to safeFetch so the package's GET
		// fallback (and any redirect target it follows via its own fetchFn)
		// is protected against SSRF redirect targets (H3 fix, 2026-05-08).
		// R7: compose the caller signal so the package's GET-fallback fetch is
		// also abortable on a scan-/per-check-level timeout.
		const response = await safeFetch(input, composeSignal(init, callerSignal));
		capturedHeaders = response.headers;
		return response;
	};

	// withAbortSignal is a no-op when callerSignal is undefined, so the package
	// sees the bare capturingFetch (unchanged) on direct/BSL calls.
	const result = (await checkHTTPSecurity(domain, withAbortSignal(capturingFetch, callerSignal), {
		timeout: HTTPS_TIMEOUT_MS,
	})) as CheckResult;

	if (!capturedHeaders) return result;

	// Attribute the ORIGIN's CDN from the final analyzed response's own headers,
	// and any redirector's CDN from the intermediate-hop (edge) signals — kept
	// distinct so an apex 301 fronted by one CDN (e.g. CloudFront) doesn't shadow
	// a different origin CDN (e.g. Fastly serving www). edgeSignals is only
	// populated on the dual-fetch path; the safeFetch fallback has no edge tracking.
	const originCdn = detectCdnProvider(capturedHeaders);
	let edgeCdn = dualResult ? detectCdnProvider(dualResult.edgeSignals) : null;
	// A CDN fronting the whole chain (same front-to-back) is one provider, not an
	// origin/edge split — collapse it so we don't redundantly name it twice.
	if (edgeCdn === originCdn) edgeCdn = null;
	if (!originCdn && !edgeCdn) return result;

	// Only annotate CDN when headers were actually analyzed.
	// If the check was blocked (WAF, connection refused, etc.) or timed out,
	// capturedHeaders may reflect the error response, not the security response.
	const isUnanalyzable =
		result.checkStatus === 'error' || result.checkStatus === 'timeout' || result.findings.some((f) => f.metadata?.missingControl === true);
	if (isUnanalyzable) return result;

	let title: string;
	let detail: string;
	let metadata: Record<string, unknown>;
	if (originCdn && edgeCdn) {
		// Both present and distinct — name the origin as primary, edge separately.
		title = `HTTP headers via ${originCdn} CDN (origin), ${edgeCdn} at edge`;
		detail =
			`Security headers were analyzed from the ${originCdn}-served origin response; an intermediate redirect hop is fronted by ${edgeCdn}. ` +
			`CDN-applied headers do not reflect the origin server's own security configuration.`;
		// cdnProvider stays the ORIGIN so scan-level CDN attribution (format-report)
		// names where the site is actually served from, not the redirector.
		metadata = { cdnProvider: originCdn, edgeCdnProvider: edgeCdn };
	} else if (originCdn) {
		title = `HTTP headers via ${originCdn} CDN`;
		detail = `HTTP security headers may be provided by ${originCdn} CDN rather than the origin server. CDN-applied headers do not reflect the origin server's security configuration.`;
		metadata = { cdnProvider: originCdn };
	} else {
		// edge-only: the origin exposed no recognizable CDN signal; only a redirect
		// hop is CDN-fronted. Flag the role so the provider isn't read as the origin's.
		title = `HTTP headers via ${edgeCdn} CDN (edge/redirect hop)`;
		detail =
			`An intermediate redirect hop for this domain is fronted by ${edgeCdn} CDN; the final origin response exposed no recognizable CDN signal. ` +
			`CDN-applied headers do not reflect the origin server's security configuration.`;
		metadata = { cdnProvider: edgeCdn, cdnRole: 'edge' };
	}

	const cdnFinding = createFinding('http_security', title, 'info', detail, metadata);

	return { ...result, findings: [...result.findings, cdnFinding] };
}
