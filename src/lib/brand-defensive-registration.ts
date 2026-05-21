// SPDX-License-Identifier: BUSL-1.1

/**
 * Defensive-registration heuristic.
 *
 * A "defensive registration" is a typosquat-shaped domain the brand owns on
 * purpose — registered to prevent attackers from grabbing it, then parked
 * (no real mail flow, NS at a parking provider, or a simple 301 redirect
 * back to the canonical brand domain). Customers reading a brand-audit PDF
 * cannot visually distinguish these from operational infrastructure even
 * though the operational implications are very different.
 *
 * This module ships a pure annotation function. It is intentionally
 * label-only and `bucket`-agnostic — the existing classifier still decides
 * the bucket, and this heuristic only stamps `defensive: true` plus a
 * `defensiveReason` token on the candidate metadata. The markdown / HTML
 * renderers consume the annotation to surface a `(defensive registration)`
 * suffix next to the candidate's line.
 *
 * Wiring note: today the candidate enrichment pipeline does not surface
 * per-candidate MX records or HTTP redirect targets, so the heuristic only
 * fires when the discovery pipeline already attached `sharedNs` metadata
 * (the NS-correlator path). Adding a small enrichment pass for typo-close
 * candidates is the production follow-up that turns the brandepsilon.com PDF
 * fix on for the user-visible case.
 *
 * Worker-runtime safe — pure string + Set operations, no Node APIs.
 */

import { extractBrandName } from './public-suffix';

/** Maximum Damerau-Levenshtein distance between candidate label and target label. */
const MAX_LABEL_DISTANCE = 2;

/**
 * Apex domains of NS providers we treat as "parked" — i.e. seeing a
 * candidate's NS land on one of these is a strong signal the domain is not
 * operationally hosting anything. Distinct from `SHARED_NS_APEXES` in
 * `src/tenants/discovery/shared-ns-hosts.ts`: that set is consumed by the
 * NS-correlator to suppress shared-tenant inflation of co-ownership
 * confidence; this set is consumed by the defensive-registration label and
 * uses a tighter "parking-only" definition (no registrar defaults like
 * `domaincontrol.com` / `secureserver.net`, which can legitimately host
 * production mail/web).
 */
const PARKING_NS_APEXES: ReadonlySet<string> = new Set([
	'sedoparking.com',
	'dan.com',
	'parkingcrew.com',
	'parkingcrew.net',
	'bodis.com',
	'uniregistry.com',
	'afternic.com',
	'namebright-dns.com',
	'dotster.com',
]);

/** Discriminated token explaining why the heuristic decided a candidate is defensive. */
export type DefensiveReason = 'redirect-to-target' | 'no-mx' | 'parked-ns';

export interface DefensiveRegistrationInput {
	/** Candidate domain (e.g. `brandepsiln.com`). */
	candidateDomain: string;
	/** Target domain the audit is anchored to (e.g. `brandepsilon.com`). */
	targetDomain: string;
	/**
	 * Candidate's MX records (hostnames only). `undefined` means "unknown
	 * — heuristic abstains on this signal"; an empty array means "we looked
	 * and there are no MX records" (drives the `no-mx` reason).
	 */
	mxRecords?: readonly string[];
	/**
	 * Candidate's NS hostnames. `undefined` → heuristic abstains. Used to
	 * detect parking providers.
	 */
	nsHosts?: readonly string[];
	/**
	 * `Location:` header value the candidate's HTTP root served on a 301/302
	 * response, if any. Used to detect "redirects back to the target".
	 * Caller is responsible for limiting follow depth (we just inspect the
	 * first hop). `undefined` → heuristic abstains.
	 */
	httpRedirectLocation?: string;
}

export interface DefensiveRegistrationResult {
	defensive: boolean;
	reason?: DefensiveReason;
}

/**
 * Damerau-Levenshtein distance with adjacent-transposition. Worker-safe,
 * O(|a|·|b|) time and space — strings are short (domain labels, ≤63 chars
 * by RFC 1035), so this is trivially cheap.
 *
 * Distinct from plain Levenshtein: a single adjacent character swap (e.g.
 * `appel` vs `apple`) costs 1 here, not 2. That branch is the reason this
 * heuristic catches transposition typos, which are a common defensive
 * registration shape.
 */
export function damerauLevenshtein(a: string, b: string): number {
	const lenA = a.length;
	const lenB = b.length;
	if (lenA === 0) return lenB;
	if (lenB === 0) return lenA;

	// `d[i][j]` = distance between a[..i] and b[..j].
	const d: number[][] = Array.from({ length: lenA + 1 }, () => new Array(lenB + 1).fill(0));
	for (let i = 0; i <= lenA; i++) d[i]![0] = i;
	for (let j = 0; j <= lenB; j++) d[0]![j] = j;

	for (let i = 1; i <= lenA; i++) {
		for (let j = 1; j <= lenB; j++) {
			const cost = a[i - 1] === b[j - 1] ? 0 : 1;
			let best = Math.min(
				d[i - 1]![j]! + 1, // deletion
				d[i]![j - 1]! + 1, // insertion
				d[i - 1]![j - 1]! + cost, // substitution
			);
			// Damerau adjacent-transposition branch.
			if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
				best = Math.min(best, d[i - 2]![j - 2]! + 1);
			}
			d[i]![j] = best;
		}
	}

	return d[lenA]![lenB]!;
}

/**
 * Return the registered apex of an NS hostname. Pure string operation —
 * takes the last two labels. For `ns1.sedoparking.com` → `sedoparking.com`.
 * For hosts with longer eTLDs (`ns1.example.co.uk`) this is best-effort and
 * may match too coarsely; we mitigate by gating callers on a small,
 * curated allowlist of `PARKING_NS_APEXES`.
 */
function registeredApex(host: string): string {
	const trimmed = host.trim().toLowerCase().replace(/\.$/, '');
	if (!trimmed) return '';
	const parts = trimmed.split('.');
	if (parts.length <= 2) return trimmed;
	return parts.slice(-2).join('.');
}

/** True if `nsHost` is a nameserver hostname operated by a known parking provider. */
export function isParkingNsHost(nsHost: string): boolean {
	if (!nsHost) return false;
	return PARKING_NS_APEXES.has(registeredApex(nsHost));
}

/**
 * Extract the second-level label from a domain, stripping the eTLD. Wraps
 * `extractBrandName()` from `public-suffix.ts` so the comparison is
 * label-only (`brandepsiln` vs `brandepsilon`), never against the full TLD.
 */
function brandLabel(domain: string): string | null {
	const label = extractBrandName(domain);
	return label ? label.toLowerCase() : null;
}

/**
 * True if `redirectLocation` is a URL whose host equals the target or
 * `www.<target>`. Conservative: anything else (path-relative redirects,
 * other domains, malformed URLs) returns false.
 */
function redirectsBackToTarget(redirectLocation: string, targetDomain: string): boolean {
	const target = targetDomain.trim().toLowerCase();
	if (!target) return false;
	let url: URL;
	try {
		url = new URL(redirectLocation);
	} catch {
		return false;
	}
	const host = url.hostname.toLowerCase().replace(/\.$/, '');
	return host === target || host === `www.${target}`;
}

/**
 * Decide whether a candidate looks like a defensive registration.
 *
 * Returns `{ defensive: true, reason }` when ALL of:
 *   - candidate's second-level label is within Damerau-Levenshtein distance
 *     ≤ 2 of the target's second-level label, AND
 *   - any ONE of the "minimal infrastructure" signals fires:
 *       - HTTP 301/302 to a Location whose host is the target or `www.<target>`
 *         → `'redirect-to-target'`
 *       - MX record set is empty (caller looked and found none)
 *         → `'no-mx'`
 *       - any NS hostname matches a known parking-provider apex
 *         → `'parked-ns'`
 *
 * Reason precedence (most-specific first): `redirect-to-target` >
 * `parked-ns` > `no-mx`. The redirect signal is the strongest evidence
 * (someone configured a redirect intentionally); parked-ns is more specific
 * than absence-of-MX (parking is an active choice; missing MX could just
 * mean a web-only domain).
 *
 * Pure function: callers (e.g. the brand-audit pipeline) feed the inputs;
 * this returns the decision without DNS or fetch I/O.
 */
export function evaluateDefensiveRegistration(input: DefensiveRegistrationInput): DefensiveRegistrationResult {
	const candidateLabel = brandLabel(input.candidateDomain);
	const targetLabel = brandLabel(input.targetDomain);
	if (!candidateLabel || !targetLabel) return { defensive: false };

	const distance = damerauLevenshtein(candidateLabel, targetLabel);
	if (distance > MAX_LABEL_DISTANCE) return { defensive: false };

	// Reason precedence — redirect is the strongest declaration of intent.
	if (input.httpRedirectLocation && redirectsBackToTarget(input.httpRedirectLocation, input.targetDomain)) {
		return { defensive: true, reason: 'redirect-to-target' };
	}

	if (input.nsHosts && input.nsHosts.some((ns) => isParkingNsHost(ns))) {
		return { defensive: true, reason: 'parked-ns' };
	}

	// `mxRecords === undefined` means "we didn't look" — abstain.
	// `mxRecords.length === 0` means "we looked, nothing there" — fire.
	if (input.mxRecords !== undefined && input.mxRecords.length === 0) {
		return { defensive: true, reason: 'no-mx' };
	}

	return { defensive: false };
}
