// SPDX-License-Identifier: BUSL-1.1

/**
 * RFC 6797 §6.1: `max-age` is REQUIRED in a Strict-Transport-Security header and its
 * value may be a quoted-string. A header without a usable `max-age` is not valid HSTS
 * (a user agent ignores it), so it must surface a finding rather than read as silence.
 */

import { describe, it, expect } from 'vitest';
import { getHttpsFindings } from '../../checks/ssl-analysis';

const HTTPS = 'https://example.com/';

function titles(hsts: string): string[] {
	return getHttpsFindings('example.com', HTTPS, hsts).map((f) => f.title);
}

describe('HSTS header parsing (RFC 6797 §6.1)', () => {
	it('flags a header with no max-age directive as invalid HSTS', () => {
		const findings = getHttpsFindings('example.com', HTTPS, 'includeSubDomains; preload');
		const invalid = findings.find((f) => f.title === 'Invalid HSTS header (no max-age)');
		expect(invalid).toBeDefined();
		expect(invalid?.severity).toBe('medium');
		// It is present-but-invalid, not absent.
		expect(findings.map((f) => f.title)).not.toContain('No HSTS header');
	});

	it('flags a max-age with a non-numeric value as invalid HSTS', () => {
		expect(titles('max-age=abc; includeSubDomains')).toContain('Invalid HSTS header (no max-age)');
	});

	it('parses a quoted max-age value and applies the short-max-age check', () => {
		const result = titles('max-age="300"; includeSubDomains');
		expect(result).toContain('HSTS max-age too short');
		expect(result).not.toContain('Invalid HSTS header (no max-age)');
	});

	it('accepts a quoted full-year max-age without findings', () => {
		expect(titles('max-age="31536000"; includeSubDomains')).toEqual([]);
	});

	it('does not mistake a directive whose name merely contains max-age', () => {
		expect(titles('x-max-age=31536000; includeSubDomains')).toContain('Invalid HSTS header (no max-age)');
	});

	it('is case-insensitive on the directive name', () => {
		expect(titles('Max-Age=31536000; IncludeSubDomains')).toEqual([]);
	});

	it('leaves the existing well-formed paths unchanged', () => {
		expect(titles('max-age=3600')).toEqual(['HSTS max-age too short', 'HSTS missing includeSubDomains']);
		expect(titles('max-age=31536000; includeSubDomains; preload')).toEqual([]);
	});
});
