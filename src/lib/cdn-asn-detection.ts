// SPDX-License-Identifier: BUSL-1.1

/**
 * ASN-based CDN attribution fallback.
 *
 * Header-based CDN detection (see check-http-security.ts) can miss CDNs that
 * don't emit a vendor-specific header — eg. Akamai serving with `Server:
 * AkamaiGHost` but no `x-akamai-transformed` / `x-check-cacheable` header. The
 * `server` header is also unusable from inside a Cloudflare Worker, whose
 * outbound fetch() rewrites it to `cloudflare`. The CF NS+IP+cert heuristic
 * (cdn-fallback-detection.ts) closes the Cloudflare case, but Akamai has
 * thousands of dynamic prefixes — a hardcoded CIDR list would be unmaintainable.
 *
 * This module attributes a CDN by resolving each A-record IP to its origin
 * ASN via team-cymru's DoH endpoint, then mapping ASN -> CDN provider:
 *
 *   <reversed-ip>.origin.asn.cymru.com  TXT  ->  "16625 | <origin-prefix> | SG | apnic | ..."
 *                                                 ^^^^^ ASN
 *
 * Why ASN over per-provider IP-range lists:
 *   - Origin-set: the ASN derives from the *resolved IP*, not a response header
 *     — immune to the CF-Worker `server:` rewrite that killed header detection.
 *   - Generalizes: one ASN_TO_CDN table covers Akamai, Cloudflare, Fastly,
 *     Imperva, etc. — no per-provider CIDR maintenance.
 *   - No new dependency: the scanner already does DoH TXT lookups; this is just
 *     a new query name passed to the same resolver.
 *
 * CRITICAL scoping rule — only map ASNs that are CDN-EXCLUSIVE. AS16509 (AWS)
 * is deliberately EXCLUDED: it covers all EC2/ELB, not just CloudFront, so
 * mapping it would false-positive every EC2-hosted app. CloudFront is reliably
 * caught by the existing `x-amz-cf-id` header check.
 *
 * Best-effort and fail-soft: bounded to MAX_ASN_LOOKUPS outbound queries,
 * short-circuits on the first CDN match, and any DoH error falls through to the
 * next IP (never throws). The DoH resolver already enforces its own per-query
 * timeout (see dns-transport.ts), so no extra timeout wrapper is needed here.
 */

/**
 * CDN-exclusive origin ASNs -> canonical provider name.
 *
 * Akamai operates many ASNs (acquisitions + regional registries); the set
 * below covers the common origin ASNs observed for Akamai edge IPs. AS16509
 * (AWS) is deliberately absent — see the module docblock.
 */
export const ASN_TO_CDN: ReadonlyMap<number, string> = new Map([
	[13335, 'Cloudflare'],
	[16625, 'Akamai'],
	[20940, 'Akamai'],
	[16702, 'Akamai'],
	[21342, 'Akamai'],
	[21357, 'Akamai'],
	[23454, 'Akamai'],
	[35994, 'Akamai'],
	[34164, 'Akamai'],
	[43639, 'Akamai'],
	[54113, 'Fastly'],
	[19551, 'Imperva'],
	[15133, 'Edgecast'],
	[60068, 'CDN77'],
	// AS16509 (AWS) deliberately excluded — not CDN-exclusive; CloudFront caught by x-amz-cf-id header.
]);

/** Bound on outbound team-cymru queries per detection run. */
const MAX_ASN_LOOKUPS = 3;

/** team-cymru origin-ASN reverse-DNS zone (queried over DoH TXT). */
const CYMRU_ORIGIN_ZONE = 'origin.asn.cymru.com';

/**
 * A minimal DoH-resolver seam: `queryTxt(name)` resolves a TXT query to its
 * answer strings. Matches the real `queryTxtRecords(name) => Promise<string[]>`
 * helper (concatenated, unquoted answer strings) so the call site can pass the
 * production resolver directly.
 */
export interface AsnDohResolver {
	queryTxt: (name: string) => Promise<string[]>;
}

/** Result of a successful ASN-based CDN attribution. */
export interface AsnCdnResult {
	provider: string;
	confidence: 'heuristic';
	asn: number;
}

/**
 * Parse the origin ASN from a team-cymru origin TXT answer.
 *
 * The answer's first `|`-delimited field holds one or more space-separated
 * ASNs (multi-origin prefixes list several). We take the first ASN token.
 * Returns null for empty / malformed answers (no leading numeric token).
 */
export function parseAsnFromCymru(txt: string): number | null {
	const firstField = txt.split('|')[0]?.trim() ?? '';
	if (firstField.length === 0) return null;
	const firstToken = firstField.split(/\s+/)[0] ?? '';
	if (!/^\d+$/.test(firstToken)) return null;
	const asn = Number.parseInt(firstToken, 10);
	return Number.isSafeInteger(asn) ? asn : null;
}

/** Map an origin ASN to its canonical CDN provider name, or null if not CDN-exclusive. */
export function mapAsnToCdn(asn: number): string | null {
	return ASN_TO_CDN.get(asn) ?? null;
}

/**
 * Attribute a CDN provider by resolving up to MAX_ASN_LOOKUPS A-record IPs to
 * their origin ASN and mapping ASN -> CDN. Short-circuits on the first CDN
 * match. Fail-soft: any DoH error or unparseable answer falls through to the
 * next IP; returns null when no IP maps to a known CDN ASN.
 */
export async function detectCdnFromAsn(aRecords: string[], doh: AsnDohResolver): Promise<AsnCdnResult | null> {
	for (const ip of aRecords.slice(0, MAX_ASN_LOOKUPS)) {
		const reversed = ip.split('.').reverse().join('.');
		try {
			const answers = await doh.queryTxt(`${reversed}.${CYMRU_ORIGIN_ZONE}`);
			const asn = answers.length > 0 ? parseAsnFromCymru(answers[0]) : null;
			if (asn !== null) {
				const provider = mapAsnToCdn(asn);
				if (provider) return { provider, confidence: 'heuristic', asn };
			}
		} catch {
			// Fail-soft — try the next IP.
		}
	}
	return null;
}
