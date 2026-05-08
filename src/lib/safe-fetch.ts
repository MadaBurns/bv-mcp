// SPDX-License-Identifier: BUSL-1.1

/**
 * Safe-fetch wrapper for outbound HTTPS to attacker-controllable URLs.
 *
 * Used by tool wrappers (BIMI logo fetch, HTTP-security redirect follower,
 * MTA-STS policy fetch, etc.) to validate the destination's hostname before
 * making the request. The runtime `global_fetch_strictly_public` flag blocks
 * RFC1918 destinations at the network layer; this gate adds protection
 * against Cloudflare-internal hostnames and userinfo-spoofed targets that
 * the runtime flag does not reach.
 *
 * H2/H3 fix (2026-05-08 security audit). See validateOutboundUrl in
 * src/lib/sanitize.ts for the validation rules.
 */

import { validateOutboundUrl } from './sanitize';

function urlOf(input: RequestInfo | URL): string {
	if (typeof input === 'string') return input;
	if (input instanceof URL) return input.href;
	return input.url;
}

/**
 * Validate the URL, then delegate to the underlying fetch. Returns a `Response`
 * with status 0 and a `BlockedByPolicy:` URL when validation fails — callers
 * already handle non-ok responses, so this surfaces as a finding rather than
 * an unhandled exception. The `cause` Error keeps the rejection reason
 * available for callers that want to log it.
 */
export const safeFetch: typeof fetch = async (input, init) => {
	const url = urlOf(input);
	const validation = validateOutboundUrl(url);
	if (!validation.valid) {
		// Throwing matches `fetch`'s native error semantics — code paths that
		// catch network errors (TypeError) treat this the same as a connection
		// refusal, which is exactly what we want on a blocked SSRF target.
		throw new TypeError(`Outbound fetch blocked: ${validation.error ?? 'invalid URL'}`);
	}
	return fetch(input, init);
};
