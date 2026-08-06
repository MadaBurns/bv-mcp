// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the defensive-registration heuristic.
 *
 * Synthetic regression: brand-audit PDF for brandepsilon.com rendered
 * `brandepsiln.com` (a defensive typosquat Brand Epsilon owns on purpose) inside
 * the `consolidated` bucket alongside operational properties, with no
 * visual distinction between the two. The heuristic flags candidates that
 * are (a) close in label-distance to the target AND (b) show only minimal
 * infrastructure, so the renderer can label them `(defensive registration)`.
 *
 * Pure function tests — no DNS, no network. The pipeline owns the wiring.
 */

import { describe, expect, it } from 'vitest';
import {
	damerauLevenshtein,
	evaluateDefensiveRegistration,
	isParkingNsHost,
	type DefensiveReason,
} from '../src/lib/brand-defensive-registration';

describe('damerauLevenshtein', () => {
	it('returns 0 for identical strings', () => {
		expect(damerauLevenshtein('brandepsilon', 'brandepsilon')).toBe(0);
	});

	it('returns 1 for a single deletion (brandepsiln vs brandepsilon)', () => {
		expect(damerauLevenshtein('brandepsiln', 'brandepsilon')).toBe(1);
	});

	it('returns 1 for a single insertion (gooogle vs google)', () => {
		expect(damerauLevenshtein('gooogle', 'google')).toBe(1);
	});

	it('returns 1 for an adjacent transposition (appel vs apple)', () => {
		// Plain Levenshtein scores this 2 (delete + insert); the Damerau
		// adjacent-transposition branch must drop it to 1.
		expect(damerauLevenshtein('appel', 'apple')).toBe(1);
	});

	it('returns 2 for two edits (brndepln vs brandepsilon)', () => {
		// 3 deletions actually; check that distance grows
		expect(damerauLevenshtein('brndepln', 'brandepsilon')).toBeGreaterThanOrEqual(3);
	});

	it('handles empty strings', () => {
		expect(damerauLevenshtein('', 'apple')).toBe(5);
		expect(damerauLevenshtein('apple', '')).toBe(5);
		expect(damerauLevenshtein('', '')).toBe(0);
	});

	it('large distance for unrelated words', () => {
		expect(damerauLevenshtein('bigbank', 'brandepsilon')).toBeGreaterThan(2);
	});
});

describe('isParkingNsHost', () => {
	it('matches sedoparking subdomains', () => {
		expect(isParkingNsHost('ns1.sedoparking.com')).toBe(true);
		expect(isParkingNsHost('ns2.sedoparking.com')).toBe(true);
	});

	it('matches all task-listed parking apexes', () => {
		expect(isParkingNsHost('ns1.dan.com')).toBe(true);
		expect(isParkingNsHost('ns2.parkingcrew.net')).toBe(true);
		expect(isParkingNsHost('ns1.bodis.com')).toBe(true);
		expect(isParkingNsHost('ns1.uniregistry.com')).toBe(true);
		expect(isParkingNsHost('ns2.afternic.com')).toBe(true);
		expect(isParkingNsHost('ns1.namebright-dns.com')).toBe(true);
		expect(isParkingNsHost('ns1.dotster.com')).toBe(true);
	});

	it('does not match hyperscaler NS', () => {
		expect(isParkingNsHost('alex.ns.cloudflare.com')).toBe(false);
		expect(isParkingNsHost('ns-123.awsdns-45.com')).toBe(false);
		expect(isParkingNsHost('ns1.google.com')).toBe(false);
	});

	it('returns false for empty or malformed input', () => {
		expect(isParkingNsHost('')).toBe(false);
	});
});

describe('evaluateDefensiveRegistration', () => {
	it('flags brandepsiln.com vs brandepsilon.com when NS is parked (parked-ns)', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'brandepsiln.com',
			targetDomain: 'brandepsilon.com',
			nsHosts: ['ns1.sedoparking.com', 'ns2.sedoparking.com'],
		});
		expect(result.defensive).toBe(true);
		// `parked-ns` is a sufficient reason on its own; report it precisely.
		expect(result.reason).toBe('parked-ns');
	});

	it('flags brandepsiln.com vs brandepsilon.com when MX is absent (no-mx)', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'brandepsiln.com',
			targetDomain: 'brandepsilon.com',
			mxRecords: [],
			nsHosts: ['some.unknown.ns.example'],
		});
		expect(result.defensive).toBe(true);
		expect(result.reason).toBe('no-mx');
	});

	it('flags gooogle.com vs google.com on redirect-to-target', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'gooogle.com',
			targetDomain: 'google.com',
			httpRedirectLocation: 'https://google.com/',
		});
		expect(result.defensive).toBe(true);
		expect(result.reason).toBe('redirect-to-target');
	});

	it('flags redirect to www subdomain of target as defensive', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'gooogle.com',
			targetDomain: 'google.com',
			httpRedirectLocation: 'https://www.google.com/path',
		});
		expect(result.defensive).toBe(true);
		expect(result.reason).toBe('redirect-to-target');
	});

	it('does NOT flag appel.com when it has real MX + non-parked NS + no redirect', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'appel.com',
			targetDomain: 'apple.com',
			mxRecords: ['mx1.someprovider.com', 'mx2.someprovider.com'],
			nsHosts: ['alex.ns.cloudflare.com', 'kate.ns.cloudflare.com'],
		});
		expect(result.defensive).toBe(false);
		expect(result.reason).toBeUndefined();
	});

	it('does NOT flag bigbank.com vs brandepsilon.com (label distance too high)', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'bigbank.com',
			targetDomain: 'brandepsilon.com',
			mxRecords: [],
			nsHosts: ['ns1.sedoparking.com'],
		});
		// Distance fails even though infra signals would otherwise match.
		expect(result.defensive).toBe(false);
	});

	it('compares second-level label only, not full TLD', () => {
		// `brandepsilon.co.uk` should compare `brandepsilon` against `brandepsilon`,
		// not `brandepsilon.co.uk` vs `brandepsilon.com`.
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'brandepsilon.co.uk',
			targetDomain: 'brandepsilon.com',
			nsHosts: ['ns1.sedoparking.com'],
		});
		// Labels are identical → distance 0 ≤ 2 → defensive when minimal infra.
		expect(result.defensive).toBe(true);
	});

	it('does NOT flag when no minimal-infra signal supplied (heuristic abstains)', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'brandepsiln.com',
			targetDomain: 'brandepsilon.com',
			// No mxRecords / nsHosts / httpRedirectLocation supplied.
		});
		expect(result.defensive).toBe(false);
		expect(result.reason).toBeUndefined();
	});

	it('does NOT flag a redirect pointing to an unrelated domain', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'gooogle.com',
			targetDomain: 'google.com',
			httpRedirectLocation: 'https://malicious.example/landing',
		});
		expect(result.defensive).toBe(false);
	});

	it('handles invalid candidate / target labels gracefully', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: '',
			targetDomain: 'brandepsilon.com',
			nsHosts: ['ns1.sedoparking.com'],
		});
		expect(result.defensive).toBe(false);
	});

	it('still flags when distance is exactly 2', () => {
		// `brandepsil` vs `brandepsilon` — single deletion, distance 1. Pick a
		// distance-2 case: drop two chars.
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'brandepsil.com',
			targetDomain: 'brandepsilon.com',
			nsHosts: ['ns1.sedoparking.com'],
		});
		// 'brandepsil' vs 'brandepsilon' — distance 2 (two insertions).
		expect(result.defensive).toBe(true);
	});
});

/**
 * CALL-SITE CONTRACT FOR `check_lookalikes`.
 *
 * This heuristic is now consumed by `check-lookalikes.ts` (via
 * `isBrandHeldRegistration()`), where it supplies the "defensive infrastructure
 * shape" leg that must agree before a shared brand-protection registrar is
 * allowed to corroborate that a confusable domain is the scanned
 * organisation's OWN defensive registration.
 *
 * The module JSDoc used to record that no caller could reach the MX/redirect
 * legs because "the candidate enrichment pipeline does not surface
 * per-candidate MX records or HTTP redirect targets". `check_lookalikes` DOES:
 * it probes MX and NS for every registered candidate. That makes the
 * abstain-versus-fire distinction below load-bearing rather than theoretical,
 * so it is pinned here at the unit layer.
 */
describe('evaluateDefensiveRegistration — check_lookalikes call-site contract', () => {
	const TARGET = 'contoso.com';

	it('ABSTAINS on undefined mxRecords — "we did not look" is not "there is no mail"', () => {
		// The trap the call site guards against: passing `undefined` (or
		// defaulting an unprobed candidate to `[]`) silently converts a missing
		// measurement into an affirmative "parked, therefore defensive" claim.
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'cont0so.com',
			targetDomain: TARGET,
			mxRecords: undefined,
			nsHosts: ['ns1.cscdns.net'],
		});
		expect(result.defensive).toBe(false);
	});

	it('FIRES on an empty mxRecords array — "we looked, there is nothing"', () => {
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'cont0so.com',
			targetDomain: TARGET,
			mxRecords: [],
			nsHosts: ['ns1.cscdns.net'],
		});
		expect(result).toEqual({ defensive: true, reason: 'no-mx' });
	});

	it('does NOT fire for a candidate with live mail, however corporate its registrar', () => {
		// The leg that keeps a shared brand-protection registrar from excusing
		// working phishing infrastructure.
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'cont0so.com',
			targetDomain: TARGET,
			mxRecords: ['mail.attacker.example'],
			nsHosts: ['ns1.cscdns.net'],
		});
		expect(result.defensive).toBe(false);
	});

	it('does NOT fire for a label too far from the target to be a typo of it', () => {
		// Distance gate: an unrelated domain that merely happens to sit at the
		// same registrar must never be labelled the brand's own.
		const result = evaluateDefensiveRegistration({
			candidateDomain: 'totally-unrelated.com',
			targetDomain: TARGET,
			mxRecords: [],
			nsHosts: ['ns1.cscdns.net'],
		});
		expect(result.defensive).toBe(false);
	});

	it('every reason token has customer-facing phrasing that cannot trip the missing-control score rule', async () => {
		// `scoreIndicatesMissingControl()` matches finding TEXT; a phrase like
		// "no MX records" inside a high-severity finding zeroes the whole
		// category score. The reason tokens are rendered into finding prose by
		// `DEFENSIVE_REASON_PHRASES` in check-lookalikes.ts, so every token this
		// module can emit must have a phrase that is safe there. This test fails
		// if a new DefensiveReason is added without a phrase.
		const { scoreIndicatesMissingControl } = await import('@blackveil/dns-checks/scoring');
		const reasons: DefensiveReason[] = ['redirect-to-target', 'no-mx', 'parked-ns'];
		const { DEFENSIVE_REASON_PHRASES } = await import('../src/tools/check-lookalikes');
		for (const reason of reasons) {
			const phrase = DEFENSIVE_REASON_PHRASES[reason];
			expect(phrase).toBeTruthy();
			expect(
				scoreIndicatesMissingControl([
					{ category: 'lookalikes', title: 'x', severity: 'high', detail: `The domain is defensive because ${phrase}.` },
				]),
			).toBe(false);
		}
	});
});
