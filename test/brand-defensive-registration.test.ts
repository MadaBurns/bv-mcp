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
