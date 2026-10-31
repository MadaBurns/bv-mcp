// SPDX-License-Identifier: BUSL-1.1

/**
 * RFC 8461 §4.1: an `mx:` pattern beginning `*.` matches exactly ONE left-most label.
 * `*.example.com` matches `mx1.example.com`, never `a.b.example.com` and never the apex.
 */

import { describe, it, expect } from 'vitest';
import { getUncoveredMxHostFindings, matchesMxPattern } from '../../checks/mta-sts-analysis';

describe('matchesMxPattern — RFC 8461 §4.1 one-label wildcard', () => {
	it('matches a single label under the wildcard', () => {
		expect(matchesMxPattern('mx1.example.com', '*.example.com')).toBe(true);
	});

	it('rejects two labels under the wildcard', () => {
		expect(matchesMxPattern('a.b.example.com', '*.example.com')).toBe(false);
	});

	it('rejects the bare apex', () => {
		expect(matchesMxPattern('example.com', '*.example.com')).toBe(false);
	});

	it('rejects an empty left-most label', () => {
		expect(matchesMxPattern('.example.com', '*.example.com')).toBe(false);
	});

	it('rejects a host that merely shares the suffix characters', () => {
		expect(matchesMxPattern('notexample.com', '*.example.com')).toBe(false);
	});

	it('is case-insensitive on both sides', () => {
		expect(matchesMxPattern('MX1.Example.COM', '*.example.com')).toBe(true);
		expect(matchesMxPattern('mx1.example.com', '*.EXAMPLE.com')).toBe(true);
	});

	it('accepts one trailing dot on both sides', () => {
		expect(matchesMxPattern('mx1.example.com.', '*.example.com')).toBe(true);
		expect(matchesMxPattern('mx1.example.com', '*.example.com.')).toBe(true);
	});

	it('leaves the non-wildcard exact match unchanged', () => {
		expect(matchesMxPattern('mx1.example.com', 'mx1.example.com')).toBe(true);
		expect(matchesMxPattern('mx2.example.com', 'mx1.example.com')).toBe(false);
		expect(matchesMxPattern('a.mx1.example.com', 'mx1.example.com')).toBe(false);
	});

	it('matches the real-world Microsoft 365 MX under its published wildcard', () => {
		expect(
			matchesMxPattern('contoso-com.mail.protection.outlook.com', '*.mail.protection.outlook.com'),
		).toBe(true);
	});
});

describe('getUncoveredMxHostFindings — consumer of the one-label rule', () => {
	it('raises the existing high-severity finding for a two-label MX under a wildcard', () => {
		const findings = getUncoveredMxHostFindings(['a.b.example.com'], ['*.example.com']);
		expect(findings).toHaveLength(1);
		expect(findings[0].title).toBe('MTA-STS policy does not cover MX host a.b.example.com');
		expect(findings[0].severity).toBe('high');
	});

	it('raises the finding for the apex MX under a wildcard', () => {
		expect(getUncoveredMxHostFindings(['example.com'], ['*.example.com'])).toHaveLength(1);
	});

	it('raises no finding for a one-label MX under a wildcard', () => {
		expect(getUncoveredMxHostFindings(['mx1.example.com'], ['*.example.com'])).toHaveLength(0);
	});
});
