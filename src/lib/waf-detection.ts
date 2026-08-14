// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared WAF/CDN interception detection.
 *
 * The scanner runs inside a Cloudflare Worker, and many origins (including
 * Cloudflare-fronted ones) answer an automated probe with a WAF challenge or
 * access-block page — commonly served as HTTP 403 — instead of the real
 * resource. Reading such a page as if it were the resource turns "our probe
 * never reached the origin" into a confident claim ABOUT the origin (e.g.
 * "MTA-STS policy file not accessible"). These helpers fingerprint that
 * interception so callers can mark the result inconclusive rather than emit a
 * confident failure.
 *
 * ⚠️ **What a detection here does and does not license (issue #664).** It
 * establishes that THIS probe was stopped at the edge. It does NOT establish
 * that other clients succeed: an edge rule aimed at automated clients as a
 * class stops real sending MTAs too, since an MTA is an automated, non-browser
 * client of the same shape as this scanner and can no more solve an interactive
 * challenge than we can. Distinguishing "the rule targets our User-Agent" from
 * "the rule covers automated clients generally" needs a signal one intercepted
 * fetch does not carry. So callers may say the result is UNMEASURED; they must
 * not go on to reassure the reader that real senders are unaffected. The
 * remedy is exclusion from scoring, not a compensating optimistic claim.
 *
 * Extracted from `check-http-security.ts` (where this logic originated) so the
 * MTA-STS policy fetch can reuse the identical detection — issue #455.
 */

import { createFinding } from './scoring';
import type { CheckCategory, Finding } from './scoring';

/**
 * A detected WAF interception:
 * - `challenge` — an interstitial JS/interactive challenge page.
 * - `block` — a terminal access-block page.
 * - `edge-artifact` — the edge answered the automated probe with an HTTP 401 that is edge
 *   fingerprinting/challenge, NOT an origin auth requirement, so the "requires authentication"
 *   label would be misleading (issue #567, same class as the #455 403-challenge case). What it
 *   licenses is "we did not reach the origin" — not a claim about what other client classes get
 *   at the same URL (issue #664).
 */
export type WafEvent = { provider: 'cloudflare' | 'akamai'; kind: 'challenge' | 'block' | 'edge-artifact' };

/** Cloudflare access-block body signatures (distinct from the "Just a moment" JS challenge). */
const CF_BLOCK_BODY = /sorry, you have been blocked|attention required|error 10(09|10|12|13|15|20)/i;

/**
 * Akamai access-denied body signatures. `AkamaiGHost` is a generic Akamai edge
 * Server header present on ordinary responses, so the Server header alone must
 * never be treated as a block — a body signature on a 4xx is required to
 * distinguish a WAF block from a genuine origin failure.
 */
const AKAMAI_BLOCK_BODY = /access denied|reference\s*#[0-9a-f.]+|you don't have permission/i;

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
 *
 * The Akamai branch mirrors the same rigor: a bare `Server: AkamaiGHost` header is present on
 * ordinary responses, so a block requires a 4xx PLUS an Akamai access-denied body signature —
 * a genuine origin 403/404/500 behind Akamai is NOT mis-attributed to a WAF block.
 *
 * HTTP 401 special case (issue #567): a Cloudflare-fronted origin frequently answers an
 * automated probe with `401` that is edge fingerprinting/challenge rather than the origin's own
 * auth requirement. Unlike the 403 block path this carries NO block-body signature —
 * the returned page is often the real (or a generic) page — so the 401 status ITSELF, combined
 * with a Cloudflare edge signal, is the discriminator. It is classified as `edge-artifact` so the
 * caller can label it "challenged/blocked at the edge" instead of the misleading "endpoint
 * requires authentication". A 401 with NO Cloudflare signal (a genuine auth-gated origin) is left
 * untouched → `null` → the caller keeps the honest auth-required finding. The challenge and block
 * classifications are still checked FIRST, so a 401 that IS a "Just a moment" challenge or a
 * block-body page keeps its more specific kind.
 */
export function detectWafEvent(headers: Headers, body: string | undefined, status: number): WafEvent | null {
	const server = (headers.get('server') ?? '').toLowerCase();
	const cfRay = headers.get('cf-ray');
	const cfMitigated = headers.get('cf-mitigated');
	const b = body ?? '';

	if (cfRay || cfMitigated || server.includes('cloudflare')) {
		if (/just a moment/i.test(b) || cfMitigated === 'challenge') return { provider: 'cloudflare', kind: 'challenge' };
		if (status >= 400 && (CF_BLOCK_BODY.test(b) || !!cfMitigated)) return { provider: 'cloudflare', kind: 'block' };
		if (status === 401) return { provider: 'cloudflare', kind: 'edge-artifact' };
	}
	if (server.includes('akamaighost') && status >= 400 && AKAMAI_BLOCK_BODY.test(b)) {
		return { provider: 'akamai', kind: 'block' };
	}
	return null;
}

/**
 * Build the canonical inconclusive WAF info-finding. Callers pass the (kind-aware) title + detail.
 *
 * Carries `inconclusive: true` and deliberately NOT `missingControl: true` (issue #638). The two
 * are mutually exclusive by the scoring model's own semantics:
 *   - `missingControl` = "we measured, and the control is absent" → ZEROES the category
 *     (`buildCheckResult` forces score 0 / passed false; `computeCategoryScore` zeroes the
 *     contribution).
 *   - `inconclusive`   = "we could not measure this at all" → the category is EXCLUDED and the
 *     overall score renormalised over what WAS measured (`transientFailures` in
 *     packages/dns-checks/src/scoring/engine.ts, keyed off `checkStatus`).
 *
 * A WAF challenge/block is unambiguously the second: the probe never reached the origin, so
 * asserting absence would be a claim of fact derived from a failed measurement. Asserting BOTH
 * left a latent trap — if the flag-precedence ever changed, a WAF page would zero a category as
 * though the control were genuinely missing.
 *
 * The scoring exclusion is driven by the caller's `checkStatus: 'error'`, not by this metadata —
 * same convention as `src/lib/dns-error-result.ts`. Callers therefore keep setting
 * `score: 0, passed: false, checkStatus: 'error'` explicitly on the CheckResult so an unmeasured
 * category is never reported as a PASS.
 */
export function buildWafFinding(category: string, event: WafEvent, status: number, text: { title: string; detail: string }): Finding {
	return createFinding(category as CheckCategory, text.title, 'info', text.detail, {
		wafEvent: event.provider,
		wafKind: event.kind,
		...(event.kind === 'challenge' ? { wafChallenge: event.provider } : {}),
		httpStatus: status,
		inconclusive: true,
	});
}
