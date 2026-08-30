// SPDX-License-Identifier: BUSL-1.1

/**
 * SSL/TLS certificate check.
 * Validates SSL certificate by attempting HTTPS connection,
 * checks HSTS configuration, and verifies HTTP->HTTPS redirect.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { getHttpRedirectFindings, getHttpsErrorFinding, getHttpsFindings, getRobotsDisallowedFinding } from './ssl-analysis';
import { RobotsDisallowedError } from '../robots-gate';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/**
 * Check SSL/TLS configuration for a domain.
 * Validates HTTPS connectivity, HSTS headers, and HTTP->HTTPS redirect.
 *
 * Requires a fetch function for making HTTP requests.
 */
export async function checkSSL(domain: string, fetchFn: FetchFunction, options?: { timeout?: number }): Promise<CheckResult> {
	const timeoutMs = options?.timeout ?? HTTPS_TIMEOUT_MS;
	const findings: Finding[] = [];

	const { findings: httpsFindings, reachable, robotsDisallowed, inconclusive } = await checkHttps(domain, fetchFn, timeoutMs);
	findings.push(...httpsFindings);

	// The entire `ssl` category signal comes from fetching the target — when robots.txt disallows
	// it, exclude the category (checkStatus: 'error') rather than scoring a false pass (no other
	// findings = 100) or letting a downstream check run against a target we were told not to touch.
	if (robotsDisallowed) {
		return { ...buildCheckResult('ssl', findings, undefined), checkStatus: 'error' };
	}

	// A transient connection failure/timeout, or an origin the server itself could not serve
	// (status 0 / 5xx), means the HTTPS/HSTS posture could not be MEASURED. Exclude the category
	// (checkStatus) so a momentary blip doesn't score a false "No HSTS"/"redirect" deficiency, and
	// skip the HTTP-redirect leg (there's nothing reliable to compare it against).
	if (inconclusive) {
		return { ...buildCheckResult('ssl', findings, reachable), checkStatus: inconclusive };
	}

	// Only check HTTP redirect if HTTPS is working (no critical findings)
	const hasCritical = findings.some((f) => f.severity === 'critical');
	if (!hasCritical) {
		const redirectResult = await checkHttpRedirect(domain, fetchFn, timeoutMs);
		findings.push(...redirectResult);
	}

	if (findings.length === 0) {
		findings.push(
			createFinding(
				'ssl',
				'HTTPS and HSTS properly configured',
				'info',
				`HTTPS connection succeeded and HSTS header is properly configured for ${domain}. Note: This check scores HTTPS reachability and HSTS policy only. Certificate issuer and expiry are available separately as non-scoring metadata from Certificate Transparency (see the cert module); negotiated TLS version and cipher suite still require a dedicated TLS scanner.`,
			),
		);
	}

	// controlPresent: HTTPS was reachable (the TLS handshake completed). A connection failure/timeout
	// means no working web TLS endpoint → web control absent for profile detection.
	return buildCheckResult('ssl', findings, reachable);
}

/**
 * Check HTTPS connectivity by attempting a fetch.
 * `reachable` is true when the TLS handshake completed (any HTTP response was received, including
 * redirects/errors); false when the connection failed or timed out; undefined (with
 * `robotsDisallowed: true`) when robots.txt disallowed the fetch and reachability was never determined.
 */
async function checkHttps(
	domain: string,
	fetchFn: FetchFunction,
	timeoutMs: number,
): Promise<{ findings: Finding[]; reachable: boolean | undefined; robotsDisallowed: boolean; inconclusive?: 'timeout' | 'error' }> {
	const findings: Finding[] = [];
	let reachable = false;
	// Set when the HTTPS/HSTS posture could not actually be MEASURED (execution failure or an
	// unassessable origin), as opposed to a real header gap. checkSSL excludes the category from
	// scoring when this is set — see the scoring-engine transientFailures handling.
	let inconclusive: 'timeout' | 'error' | undefined;

	try {
		const response = await fetchFn(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs),
		});
		reachable = true;

		if (response.status === 0 || response.status >= 500) {
			// Origin-unreachable / server error (e.g. Cloudflare 530): the page is NOT assessable, so
			// do NOT emit the "No HSTS"/redirect scored findings — a transient origin blip must not
			// read as a security deficiency. One honest info finding + exclude from scoring.
			inconclusive = 'error';
			findings.push(
				createFinding(
					'ssl',
					`HTTPS endpoint not assessable (status ${response.status})`,
					'info',
					`https://${domain} returned status ${response.status}; the HTTPS endpoint could not be reached to assess HSTS/redirect posture, so this control was not assessed.`,
				),
			);
		} else if (response.status === 204 || response.status === 205) {
			// Issue #806 follow-up: a no-content 2xx satisfies neither the redirect nor the error
			// branch, so before this guard its (by definition empty) header set flowed into
			// getHttpsFindings() and produced a confident scored "No HSTS header" finding from a
			// response that delivered no page — the exact defect family #819 fixed on the http://
			// leg (getHttpRedirectFindings) and in the sibling check-http-security. Route it to
			// the same inconclusive/'error' lane as the unassessable-origin branch above so the
			// category is EXCLUDED from scoring and the transient-zero retry can fire. Never
			// `missingControl`: a 204 measured nothing (issue #638 law) — `inconclusive` +
			// `errorKind` are the honest unmeasured markers.
			inconclusive = 'error';
			findings.push(
				createFinding(
					'ssl',
					'HTTPS response carried no content',
					'info',
					`https://${domain} answered the scanner with HTTP ${response.status} (no content). No page was delivered, so HSTS/redirect posture could not be verified — the response may be an egress anomaly or challenge rather than the site.`,
					{ inconclusive: true, confidence: 'heuristic', errorKind: 'no_content' },
				),
			);
		} else {
			const isRedirect = response.status >= 300 && response.status < 400;
			const location = isRedirect ? response.headers.get('location') : null;
			const isDowngrade = location?.startsWith('http://') ?? false;
			const isHttpsRedirect = isRedirect && !isDowngrade && location !== null;

			const redirectTarget = isDowngrade ? (location ?? undefined) : undefined;
			const hstsHeader = response.headers.get('strict-transport-security');

			// HTTPS→HTTPS redirects: HSTS on the redirect hop itself is complete evidence (it is
			// where hstspreload.org requires the header), so analyze it directly. When the hop
			// lacks HSTS, the header may still live on the terminal response only — a common CDN /
			// bare-domain→www layout — so follow the chain and score the final page instead of the
			// hop. History: an unconditional read here was reverted once already (642cbb3c,
			// 2026-03) because the hop-only read penalized correctly-configured sites, and the
			// replacement guard silently skipped measurement, which #839 showed reads as a false
			// "properly configured" pass. Follow-or-abstain is the resolution of that pair: an
			// unresolvable chain routes to the inconclusive lane below, never to a scored absence.
			if (!isHttpsRedirect || hstsHeader !== null) {
				findings.push(...getHttpsFindings(domain, redirectTarget, hstsHeader));
			} else {
				const followed = await followHttpsRedirectChain(response, fetchFn, timeoutMs);
				if (followed.kind === 'downgrade') {
					// The chain left HTTPS mid-flight — same critical downgrade the first-hop
					// `isDowngrade` branch scores, just discovered a hop later.
					findings.push(...getHttpsFindings(domain, followed.target, null));
				} else if (followed.kind === 'final' && followed.response.status !== 0 && followed.response.status < 500) {
					findings.push(...getHttpsFindings(domain, undefined, followed.response.headers.get('strict-transport-security')));
				} else {
					// Chain cut (fetch failure / hop cap / unassessable terminal status): HSTS was
					// never measured, so exclude the category (#638 law — a cut probe must not be
					// recorded as absence) instead of scoring "No HSTS header" from a hop nobody
					// would ever land on, or letting the empty finding set read as a clean pass.
					inconclusive = followed.kind === 'unresolved' && followed.reason === 'timeout' ? 'timeout' : 'error';
					findings.push(
						createFinding(
							'ssl',
							'HTTPS redirect chain not assessable',
							'info',
							`https://${domain} redirects to another HTTPS URL, and the redirect chain could not be followed to a final response, so HSTS posture could not be verified.`,
							{ inconclusive: true, confidence: 'heuristic', errorKind: 'redirect_chain_unresolved' },
						),
					);
				}
			}
		}
	} catch (err) {
		if (err instanceof RobotsDisallowedError) {
			return {
				findings: [getRobotsDisallowedFinding(domain, err.scope)],
				reachable: undefined,
				robotsDisallowed: true,
			};
		}
		const message =
			err instanceof Error && (err.message.includes('timeout') || err.message.includes('abort'))
				? 'Connection timeout'
				: 'Connection failed';
		// A thrown fetch is a transient execution failure — exclude the category rather than scoring
		// the connection-failure finding as a real deficiency. The existing finding is retained.
		inconclusive = message === 'Connection timeout' ? 'timeout' : 'error';
		findings.push(getHttpsErrorFinding(domain, message));
	}

	return { findings, reachable, robotsDisallowed: false, inconclusive };
}

/** Maximum HTTPS→HTTPS hops to follow when hunting the terminal response's HSTS header. */
const MAX_REDIRECT_HOPS = 3;

type RedirectChainResult =
	| { kind: 'final'; response: Response }
	| { kind: 'downgrade'; target: string }
	| { kind: 'unresolved'; reason: 'timeout' | 'error' };

/**
 * Follow an HTTPS→HTTPS redirect chain to its terminal response so HSTS can be read from the
 * page users actually land on. Mirrors `followRedirects` in check-http-security, with one
 * deliberate divergence: where that check analyzes whatever headers it holds when a chain
 * breaks, this one reports `unresolved` so the caller can route to the inconclusive lane —
 * check-ssl's HSTS verdict is scored, and a broken chain measured nothing.
 *
 * SSRF note (same contract as check-http-security's follower): each hop's target hostname is
 * attacker-controlled (`Location:` header). Callers must pass a `fetchFn` that validates the
 * destination before issuing the request — the bv-mcp Worker passes a safeFetch-based wrapper.
 * Embedders that pass raw `fetch` are responsible for their own SSRF protection.
 */
async function followHttpsRedirectChain(response: Response, fetchFn: FetchFunction, timeoutMs: number): Promise<RedirectChainResult> {
	let current = response;
	for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
		const isRedirect = current.status >= 300 && current.status < 400;
		const location = isRedirect ? current.headers.get('location') : null;
		// A non-redirect (or a 3xx with no Location, which delivers its own headers) terminates
		// the chain: analyzable.
		if (!location) return { kind: 'final', response: current };

		let nextUrl: string;
		try {
			nextUrl = new URL(location, current.url || undefined).href;
		} catch {
			return { kind: 'unresolved', reason: 'error' };
		}
		if (nextUrl.startsWith('http://')) return { kind: 'downgrade', target: nextUrl };
		if (!nextUrl.startsWith('https://')) return { kind: 'unresolved', reason: 'error' };

		try {
			// Release the abandoned hop's body so workerd doesn't cancel a stalled stream.
			void current.body?.cancel().catch(() => undefined);
			current = await fetchFn(nextUrl, {
				method: 'HEAD',
				redirect: 'manual',
				signal: AbortSignal.timeout(timeoutMs),
			});
		} catch (err) {
			// Includes SSRF/robots rejection from a gated fetchFn — the chain is unmeasurable,
			// which the caller must NOT score as a header absence.
			const timedOut = err instanceof Error && (err.message.includes('timeout') || err.message.includes('abort'));
			return { kind: 'unresolved', reason: timedOut ? 'timeout' : 'error' };
		}
	}
	const stillRedirecting = current.status >= 300 && current.status < 400 && current.headers.get('location') !== null;
	return stillRedirecting ? { kind: 'unresolved', reason: 'error' } : { kind: 'final', response: current };
}

/** Check if HTTP redirects to HTTPS */
async function checkHttpRedirect(domain: string, fetchFn: FetchFunction, timeoutMs: number): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const response = await fetchFn(`http://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs),
		});
		findings.push(...getHttpRedirectFindings(domain, response.status, response.headers.get('location')));
	} catch {
		// HTTP not available or blocked — not necessarily an issue, skip silently. (Unreachable in
		// the robots-disallowed case: checkSSL returns before this function is ever called.)
	}
	return findings;
}
