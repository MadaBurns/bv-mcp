// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { CheckResult, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { analyzeSecurityHeaders } from './http-security-analysis';
import { GET_FALLBACK_MIN_BUDGET_MS, tryGetFallback } from './probe-fetch';
import { isBlockedProbeStatus } from './ssl-analysis';
import {
	SCANNER_USER_AGENT,
	RobotsDisallowedError,
	describeRobotsScope,
	robotsAbstentionMetadata,
} from '../robots-gate';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/**
 * Maximum redirect hops to follow.
 *
 * Exported so the Worker wrapper (`src/tools/check-http-security.ts`) can import this instead
 * of hardcoding its own separate cap (SQ-204) — two independent hop limits meant the wrapper's
 * dual-fetch pre-probe could exhaust its own cap while still redirecting and hand this check a
 * synthetic "final" response that was never actually final, defeating the abstention below.
 */
export const MAX_REDIRECT_HOPS = 3;

/**
 * No-content 2xx statuses (issue #806). A terminal 204/205 satisfies `response.ok`
 * but by definition delivered no page, so its (typically empty) header set must never
 * be analyzed as the site's — doing so manufactured the entire confident
 * missing-header slate from a response that measured nothing (observed live on
 * google.com via an egress anomaly: the real answer is a 301/200 chain carrying
 * `x-frame-options`, yet the scan reported "No X-Frame-Options"). WAF detection
 * cannot rescue this case — it requires status >= 400 or a body signature — so the
 * guard routes it to the same unmeasured shape as the WAF-blocked/never-completed
 * probe branches below.
 */
const NO_CONTENT_STATUSES = new Set([204, 205]);

/**
 * The one honest finding for a no-content terminal response (issue #806).
 * No `missingControl` — that flag asserts "we measured and the control is absent",
 * and a 204 measured nothing (issue #638 law). `inconclusive` + `errorKind` are the
 * honest unmeasured markers; the score-0/passed-false shape is applied by the caller
 * via `unmeasuredZero`, exactly like the blocked-probe branches.
 */
function noContentFinding(domain: string, status: number): Finding {
	return createFinding(
		'http_security',
		'HTTP response carried no content',
		'info',
		`https://${domain} answered the scanner with HTTP ${status} (no content). No page was delivered, so security headers could not be verified — the response may be an egress anomaly or challenge rather than the site.`,
		{ inconclusive: true, confidence: 'heuristic', errorKind: 'no_content' },
	);
}

/**
 * The finding for a 2xx-shaped edge/WAF/rate-limit block (issue #972). `isBlockedProbeStatus()`
 * (shared with check-ssl/ssl-analysis, issue #972) classifies 202 as a blocked-probe status, but
 * 202 still satisfies `response.ok` — so without this guard an unfingerprinted origin's 202
 * interstitial (no CF/Akamai signal for `detectWafEvent` in waf-detection.ts to match) fell
 * straight into `analyzeSecurityHeaders()` and produced a full slate of confident "No <header>"
 * findings from a probe that never reached the real page. No `missingControl` — a blocked probe
 * measured nothing (issue #638 law); the score-0/passed-false shape is applied via
 * `unmeasuredZero` at the call sites, same as the no-content branch above.
 */
function blockedProbeFinding(domain: string, status: number): Finding {
	return createFinding(
		'http_security',
		'HTTP check blocked',
		'info',
		`https://${domain} answered the scanner with HTTP ${status}, an edge/WAF/rate-limit-shaped response with no vendor fingerprint to match. Security headers could not be verified — the response is likely an interstitial or challenge page rather than the site's own answer.`,
		{ inconclusive: true },
	);
}

/**
 * Follow redirects manually to get the final response with security headers.
 * Redirect responses (e.g., nist.gov → www.nist.gov) typically lack security
 * headers, causing false negatives if we analyze the 301 instead of the 200.
 *
 * Handles Cloudflare Workers opaque redirect responses (status 0) and standard
 * 3xx redirects. Only follows HTTPS redirects (no protocol downgrade).
 *
 * `budgetMs` is what's LEFT of the check's total `timeoutMs` when this is called — HEAD, any
 * GET fallback, and this chain share ONE budget from `headStartedAt` (#1093), not a fresh
 * `timeoutMs` per hop. Below `GET_FALLBACK_MIN_BUDGET_MS` remaining, a hop cannot return a
 * genuine answer, so it is never issued and `deadlineExceeded: true` tells the caller so —
 * analyzing whatever headers a stalled/aborted hop last held would score a probe that never
 * reached a final page as if it had.
 *
 * SSRF note (H3 fix, 2026-05-08): the redirect target hostname is attacker-
 * controlled (it's whatever the origin's `Location:` header says). Callers must
 * pass a `fetchFn` that validates the destination before issuing the request —
 * the bv-mcp Worker passes `safeFetch` which gates the URL via
 * validateOutboundUrl(). Embedders that pass raw `fetch` are responsible for
 * their own SSRF protection.
 *
 * `hopCapExceeded` (SQ-204 / chaos SQ-194 H3) is true ONLY when the loop ran through all
 * `MAX_REDIRECT_HOPS` iterations and the last fetched response is STILL a redirect — a
 * persistent/looping chain that never reached a final page within the hop budget. It is
 * deliberately NOT set on the other early-exit paths (no `Location` header, a protocol
 * downgrade/unparseable target, a hostile/SSRF-rejected hop) — those are different,
 * pre-existing shapes this ticket does not touch, and the caller's "still a redirect after
 * max hops" branch remains their (unchanged) landing spot.
 */
async function followRedirects(
	response: Response,
	fetchFn: FetchFunction,
	budgetMs: number,
): Promise<{ response: Response; deadlineExceeded: boolean; hopCapExceeded: boolean }> {
	const deadlineAt = Date.now() + budgetMs;
	for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
		const status = response.status;
		const isRedirect = (status >= 300 && status < 400) || response.type === 'opaqueredirect' || (status === 0 && response.headers.get('location'));
		if (!isRedirect) return { response, deadlineExceeded: false, hopCapExceeded: false };

		const location = response.headers.get('location');
		if (!location) return { response, deadlineExceeded: false, hopCapExceeded: false };

		let nextUrl: string;
		try {
			nextUrl = new URL(location, response.url || undefined).href;
		} catch {
			return { response, deadlineExceeded: false, hopCapExceeded: false };
		}

		// Only follow HTTPS redirects
		if (!nextUrl.startsWith('https://')) return { response, deadlineExceeded: false, hopCapExceeded: false };

		const remainingMs = deadlineAt - Date.now();
		if (remainingMs < GET_FALLBACK_MIN_BUDGET_MS) {
			return { response, deadlineExceeded: true, hopCapExceeded: false };
		}

		try {
			// Release the body of the response we're about to abandon (e.g. a GET
			// fallback that itself redirects) so workerd doesn't cancel a stalled stream.
			void response.body?.cancel().catch(() => undefined);
			response = await fetchFn(nextUrl, {
				method: 'HEAD',
				redirect: 'manual',
				headers: { 'User-Agent': SCANNER_USER_AGENT },
				signal: AbortSignal.timeout(remainingMs),
			});
		} catch (err) {
			// AbortSignal.timeout() rejects with a DOMException named 'TimeoutError';
			// 'AbortError' covers runtimes and mocks that report a plain abort. Message
			// text is NOT consulted: SSRF rejection messages embed the origin-controlled
			// redirect hostname (src/lib/safe-fetch.ts:39, src/lib/sanitize.ts:126-151), so
			// matching on message text would let an attacker steer this classification.
			const e = err as { name?: string; message?: string };
			const isTimeout = e?.name === 'TimeoutError' || e?.name === 'AbortError';
			if (isTimeout) {
				return { response, deadlineExceeded: true, hopCapExceeded: false };
			}
			// Includes SSRF rejection from a safeFetch wrapper — fall out of the
			// redirect loop and let analysis run with whatever headers we already
			// have, treating the hostile redirect target as a network failure.
			return { response, deadlineExceeded: false, hopCapExceeded: false };
		}
	}

	// The loop ran through every hop without an early return — the chain kept redirecting
	// (or the mock/origin never stopped). If the LAST fetched response is still a redirect,
	// this is the persistent-loop case (SQ-204): the probe never reached a final page, so the
	// headers it happens to be holding are just another hop, not the site's answer.
	const status = response.status;
	const stillRedirecting = (status >= 300 && status < 400) || response.type === 'opaqueredirect' || (status === 0 && response.headers.get('location'));
	return { response, deadlineExceeded: false, hopCapExceeded: Boolean(stillRedirecting) };
}

/**
 * The finding for a HEAD+GET+redirect-chain probe that ran out of its shared time budget
 * mid-flight (#1093). Distinct from the bottom-of-function catch's "Connection timed out" —
 * that one never got a response at all, this one has a response but the chain that would
 * resolve it to an analyzable final page could not complete in time.
 */
function deadlineExceededFinding(domain: string): Finding {
	return createFinding(
		'http_security',
		'HTTPS connection timed out',
		'medium',
		`Could not fetch https://${domain} to check security headers: the HEAD/GET/redirect-chain probe exceeded its time budget.`,
		// No `missingControl` (issue #638) — the chain never reached a final, analyzable page, so
		// nothing about the headers was established. See `unmeasuredZero` at the call site.
		{ inconclusive: true },
	);
}

/**
 * The finding for a redirect chain that never resolved to a final page within the hop cap
 * (SQ-204 / chaos SQ-194 H3) — the origin kept redirecting past `MAX_REDIRECT_HOPS`, so the
 * response `followRedirects` is still holding is just another hop, not a page a browser would
 * ever render. Scoring its (typically security-header-sparse) headers as the site's own
 * fabricated a confident "header missing" slate from a probe that never reached the origin
 * (issue #638 law). `errorKind: 'redirect_chain_unresolved'` reuses the vocabulary the sibling
 * `check-ssl.ts` already established for the identical situation on its own redirect chain.
 */
function redirectLoopFinding(domain: string): Finding {
	return createFinding(
		'http_security',
		'HTTP redirect chain did not resolve',
		'medium',
		`https://${domain} kept redirecting past the maximum of ${MAX_REDIRECT_HOPS} hops without reaching a final page. Security headers could not be verified — this may be a redirect loop or misconfiguration.`,
		{ inconclusive: true, confidence: 'heuristic', errorKind: 'redirect_chain_unresolved' },
	);
}

/**
 * Check HTTP security headers for a domain.
 * Fetches the HTTPS endpoint and analyzes browser security headers.
 *
 * Requires a fetch function for making HTTP requests.
 */
export async function checkHTTPSecurity(
	domain: string,
	fetchFn: FetchFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeoutMs = options?.timeout ?? HTTPS_TIMEOUT_MS;
	const findings: Finding[] = [];
	// Set when the headers could not actually be evaluated (inconclusive execution, not a real
	// header gap). The scoring engine treats checkStatus 'timeout'/'error' as a transient failure
	// and EXCLUDES the category from scoring (renormalized) rather than zeroing it — so a flaky
	// fetch can't make the overall score fluctuate between a real value and 0.
	let inconclusive: 'timeout' | 'error' | undefined;
	// Set on every branch where THE PROBE NEVER COMPLETED, so no header was ever observed:
	// the WAF/appliance block, the 401, the residual 4xx, and the connection failure/timeout.
	// All four used to stamp their finding with `missingControl: true` — but that flag means
	// "we measured, and the control is ABSENT", which none of them established (issue #638).
	// The flag was doing double duty: it was ALSO the only thing forcing the score-0 /
	// passed-false shape, so dropping it alone would let these findings compute to a PASS
	// (an `info` finding → 100/passed, a `medium` → 85/passed) — i.e. an unmeasured check
	// reported as a clean one, the opposite defect. The zeroing is therefore expressed
	// directly here, with no false claim of absence attached.
	//
	// The `checkStatus` set alongside is what makes the scoring engine EXCLUDE the category
	// rather than score the 0 — see `transientFailures` in scoring/engine.ts.
	//
	// Deliberately NOT set on the two other `inconclusive` branches, which never carried
	// `missingControl` and so are not part of this defect:
	//   - the 5xx "Server error" branch — the origin WAS reached and answered (score 85);
	//   - the robots.txt skip — a voluntary abstention, not a failed probe (score 100).
	// Generalising "inconclusive ⇒ zero" would silently rescore both. It is scoped to the
	// branches that made the contradictory claim.
	let unmeasuredZero = false;
	// Set on the TRANSIENT unmeasured branches: the two no-content (204/205) answers (issue
	// #806 follow-up — an egress blip or challenge, not an origin-persistent state) and the
	// connection failure/timeout catch (#900 class — the probe never reached the origin). The
	// result carries `partial: true` to stay OUT of the 5-min per-check cache (scan-domain's
	// runWithCache predicate is `(r) => !r.partial`), matching the buildDnsErrorResult /
	// buildNotAssessedResult convention for transient states, so the next call re-measures.
	// Deliberately NOT set on the WAF-block/401/other-4xx branches: those describe
	// origin-persistent states and cache deliberately.
	let transientUnmeasured = false;

	try {
		const headStartedAt = Date.now();
		let response = await fetchFn(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			headers: { 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(timeoutMs),
		});

		// Follow redirects to get the final destination's headers. Bounded by what's LEFT of
		// timeoutMs after the HEAD probe already spent part of it — HEAD + this chain share ONE
		// total budget (#1093), same contract #1088 established for HEAD+GET.
		const headFollowed = await followRedirects(response, fetchFn, Math.max(0, timeoutMs - (Date.now() - headStartedAt)));
		response = headFollowed.response;

		if (headFollowed.deadlineExceeded) {
			// The redirect chain ran out of the shared HEAD+GET+chain budget mid-flight. Route to
			// the same abstention a caller-thrown timeout uses — analyzing whatever headers a
			// stalled hop is still holding (e.g. a 301's) would score a probe that never reached a
			// final page as if it had (#1093).
			inconclusive = 'timeout';
			unmeasuredZero = true;
			transientUnmeasured = true;
			findings.push(deadlineExceededFinding(domain));
		} else if (headFollowed.hopCapExceeded) {
			// SQ-204 (chaos SQ-194 H3) — the chain hit MAX_REDIRECT_HOPS while STILL redirecting: a
			// persistent/looping chain, not a legitimate final answer. Route to the same abstention
			// shape as a deadline cut, mirroring `check-ssl.ts`'s `redirect_chain_unresolved` lane
			// for its own unresolved chain. `transientUnmeasured` (not origin-persistent) because a
			// stuck redirect chain may resolve differently on the next probe.
			inconclusive = 'error';
			unmeasuredZero = true;
			transientUnmeasured = true;
			findings.push(redirectLoopFinding(domain));
		} else if (NO_CONTENT_STATUSES.has(response.status)) {
			// Issue #806 — the terminal response is accepted here, so the no-content guard
			// runs BEFORE any header-read branch (it also structurally shields the still-3xx
			// branch below, where a 204/205 can never appear). `checkStatus: 'error'` makes
			// the scoring engine EXCLUDE the category (transient-failure renormalization)
			// rather than score the 0 — so the transient-zero retry can fire.
			inconclusive = 'error';
			unmeasuredZero = true;
			transientUnmeasured = true;
			findings.push(noContentFinding(domain, response.status));
		} else if (isBlockedProbeStatus(response.status) && response.ok) {
			// Issue #972 — a 2xx-shaped edge/WAF/rate-limit block (202 "Accepted" is the only
			// isBlockedProbeStatus member that satisfies response.ok). Must be checked before the
			// generic response.ok branch below, or the block page's headers are read as the site's.
			// Treated as origin-persistent (no `transientUnmeasured`/`partial`), same as the
			// 401/403/"other 4xx" blocked-probe branches further down, not the transient no-content
			// pair above.
			inconclusive = 'error';
			unmeasuredZero = true;
			findings.push(blockedProbeFinding(domain, response.status));
		} else if (response.ok) {
			// 200-299: analyze headers normally
			findings.push(...analyzeSecurityHeaders(response.headers));
		} else if (response.status === 0 || response.status >= 500) {
			inconclusive = 'error';
			findings.push(
				createFinding(
					'http_security',
					'Server error',
					'medium',
					`HTTPS returned status ${response.status} for ${domain}. Cannot analyze security headers.`,
				),
			);
		} else if (response.status >= 300 && response.status < 400) {
			// Still a redirect after max hops — analyze whatever headers we have
			findings.push(...analyzeSecurityHeaders(response.headers));
		} else if (response.status === 403 || response.status === 405) {
			// WAF block or HEAD not allowed — retry with GET to get real headers. The GET gets
			// what's LEFT of timeoutMs (which the HEAD + any followRedirects hops already spent
			// part of), not a fresh copy of it — the pair is bounded by ONE total budget (#1088).
			// tryGetFallback skips the request (and returns null, same as a fetch error) once too
			// little remains for a real answer.
			const remainingMs = Math.max(0, timeoutMs - (Date.now() - headStartedAt));
			const getResponse = await tryGetFallback(`https://${domain}`, fetchFn, remainingMs);
			if (getResponse && (getResponse.ok || (getResponse.status >= 300 && getResponse.status < 400))) {
				// Same shared-budget contract as the HEAD-triggered call above (#1093): what's LEFT
				// of timeoutMs, not a fresh copy of it.
				const getFollowed = await followRedirects(getResponse, fetchFn, Math.max(0, timeoutMs - (Date.now() - headStartedAt)));
				if (getFollowed.deadlineExceeded) {
					inconclusive = 'timeout';
					unmeasuredZero = true;
					transientUnmeasured = true;
					findings.push(deadlineExceededFinding(domain));
				} else if (getFollowed.hopCapExceeded) {
					// SQ-204 — identical guard as the HEAD-triggered call above, needed here too
					// since the GET fallback's own chain can independently hit the hop cap.
					inconclusive = 'error';
					unmeasuredZero = true;
					transientUnmeasured = true;
					findings.push(redirectLoopFinding(domain));
				} else {
					const followed = getFollowed.response;
					if (NO_CONTENT_STATUSES.has(followed.status)) {
						// Issue #806 — the GET fallback's terminal response is accepted here, so the
						// same no-content guard applies before analysis.
						inconclusive = 'error';
						unmeasuredZero = true;
						transientUnmeasured = true;
						findings.push(noContentFinding(domain, followed.status));
					} else if (isBlockedProbeStatus(followed.status) && followed.ok) {
						// Issue #972 — the GET fallback itself can land on the same 2xx-shaped block
						// (e.g. HEAD 403 -> GET 202), so it needs the identical guard as the initial
						// HEAD probe above before analysis.
						inconclusive = 'error';
						unmeasuredZero = true;
						findings.push(blockedProbeFinding(domain, followed.status));
					} else {
						findings.push(...analyzeSecurityHeaders(followed.headers));
					}
					// GET fallback returns a real body we never read (followRedirects only
					// cancels it when it redirects); release it so workerd doesn't cancel a
					// stalled stream.
					void followed.body?.cancel().catch(() => undefined);
				}
			} else {
				inconclusive = 'error';
				unmeasuredZero = true;
				findings.push(
					createFinding(
						'http_security',
						'HTTP check blocked by security appliance',
						'info',
						`The site returned HTTP ${response.status} for ${domain}. A WAF or firewall is blocking external header inspection. Security headers cannot be verified.`,
						// No `missingControl` (issue #638) — a blocked probe measured nothing, so it must not
						// also claim the control is absent. `inconclusive: true` is the honest marker; the
						// score-0/passed-false shape is applied via `unmeasuredZero` at the return below.
						{ inconclusive: true },
					),
				);
			}
		} else if (response.status === 401) {
			inconclusive = 'error';
			unmeasuredZero = true;
			findings.push(
				createFinding(
					'http_security',
					'HTTP check requires authentication',
					'info',
					`The site returned HTTP 401 for ${domain}. The endpoint requires authentication; security headers cannot be verified externally.`,
					// No `missingControl` (issue #638) — an auth-gated endpoint refused the probe, which
					// says nothing about whether the headers exist behind it. See `unmeasuredZero` above.
					{ inconclusive: true },
				),
			);
		} else {
			// Other 4xx (404, 429, etc.) — blocked or rejected
			inconclusive = 'error';
			unmeasuredZero = true;
			findings.push(
				createFinding(
					'http_security',
					'HTTP request rejected',
					'medium',
					`HTTPS returned status ${response.status} for ${domain}. Cannot analyze security headers.`,
					// No `missingControl` (issue #638) — the request was rejected before any header was
					// observed. See `unmeasuredZero` above.
					{ inconclusive: true },
				),
			);
		}
	} catch (err) {
		if (err instanceof RobotsDisallowedError) {
			inconclusive = 'error';
			findings.push(
				createFinding(
					'http_security',
					'HTTP security check skipped (robots.txt)',
					'info',
					`${domain}'s robots.txt ${describeRobotsScope(err.scope)}, so HTTP security headers could not be independently verified. Not scored — see https://www.blackveilsecurity.com/bot-policy.`,
					robotsAbstentionMetadata(err.scope),
				),
			);
		} else {
			// AbortSignal.timeout throws a DOMException named 'TimeoutError' (message "The operation
			// timed out"); also match abort/timeout phrasings from other runtimes.
			const e = err as { name?: string; message?: string };
			const isTimeout = e?.name === 'TimeoutError' || /timed?\s*out|abort|timeout/i.test(e?.message ?? '');
			inconclusive = isTimeout ? 'timeout' : 'error';
			unmeasuredZero = true;
			// A thrown fetch is transient: without `partial` the score-0 abstention was cached
			// for the 5-minute TTL and re-served to every direct check_http_security call.
			transientUnmeasured = true;
			const message = isTimeout ? 'Connection timed out' : 'Connection failed';
			findings.push(
				createFinding(
					'http_security',
					`HTTPS ${message.toLowerCase()}`,
					'medium',
					`Could not fetch https://${domain} to check security headers: ${message}.`,
					// No `missingControl` (issue #638) — the connection never delivered a response, so
					// nothing about the headers was established. See `unmeasuredZero` above.
					{ inconclusive: true },
				),
			);
		}
	}

	const base = buildCheckResult('http_security', findings);
	// Preserves the exact score-0/passed-false shape the removed `missingControl` flags used to
	// produce on the four never-completed-probe paths, without asserting the control is absent
	// (issue #638).
	const zeroed = unmeasuredZero ? { ...base, score: 0, passed: false } : base;
	// `partial: true` (transient branches only) keeps the non-answer out of the 5-min cache —
	// see the `transientUnmeasured` note above.
	const result = transientUnmeasured ? { ...zeroed, partial: true } : zeroed;
	return inconclusive ? { ...result, checkStatus: inconclusive } : result;
}
