import { describe, it, expect } from 'vitest';
import { validateDomain, sanitizeDomain } from '../src/lib/sanitize';

describe('sanitize library', () => {
	describe('validateDomain', () => {
		it('accepts valid domains', () => {
			expect(validateDomain('example.com')).toEqual({ valid: true });
			expect(validateDomain('sub.example.com')).toEqual({ valid: true });
			expect(validateDomain('example.co.uk')).toEqual({ valid: true });
		});

		it('rejects empty/null/undefined/non-string input', () => {
			const expected = { valid: false, error: 'Domain name is required' };
			expect(validateDomain('')).toEqual(expected);
			expect(validateDomain(null as unknown as string)).toEqual(expected);
			expect(validateDomain(undefined as unknown as string)).toEqual(expected);
			expect(validateDomain(123 as unknown as string)).toEqual(expected);
		});

		it('trims whitespace and normalizes case', () => {
			expect(validateDomain('  Example.COM  ')).toEqual({ valid: true });
		});

		it('removes trailing dot (FQDN notation)', () => {
			expect(validateDomain('example.com.')).toEqual({ valid: true });
		});

		it('rejects domains exceeding 253 characters', () => {
			const longDomain = 'a'.repeat(63) + '.' + 'b'.repeat(63) + '.' + 'c'.repeat(63) + '.' + 'd'.repeat(63) + '.com';
			expect(longDomain.length).toBeGreaterThan(253);
			const result = validateDomain(longDomain);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('maximum length');
		});

		it('rejects reserved hostnames', () => {
			for (const host of ['localhost', 'localhost.localdomain']) {
				const result = validateDomain(host);
				expect(result.valid).toBe(false);
				expect(result.error).toContain('reserved hostname');
			}
		});

		it('rejects reserved TLDs', () => {
			const reservedTLDs = [
				'.local',
				'.localhost',
				'.internal',
				'.example',
				'.invalid',
				'.test',
				'.onion',
				'.lan',
				'.home',
				'.corp',
				'.intranet',
			];
			for (const tld of reservedTLDs) {
				const domain = `host${tld}`;
				const result = validateDomain(domain);
				expect(result.valid).toBe(false);
				expect(result.error).toContain('reserved TLD');
			}
		});

		it('rejects bare reserved TLD names', () => {
			// e.g. "local" alone matches suffix ".local" via normalized === suffix.slice(1)
			// But "local" is a single label so it would fail the two-label check first.
			// "test" similarly. The two-label check fires before suffix check.
			const result = validateDomain('test');
			expect(result.valid).toBe(false);
		});

		it('rejects IPv4 loopback addresses', () => {
			const result = validateDomain('127.0.0.1');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('IP addresses');
		});

		it('rejects IPv4 private addresses', () => {
			for (const ip of ['10.0.0.1', '192.168.1.1', '172.16.0.1']) {
				const result = validateDomain(ip);
				expect(result.valid).toBe(false);
				expect(result.error).toContain('IP addresses');
			}
		});

		it('rejects IPv4 link-local and special addresses', () => {
			for (const ip of ['169.254.1.1', '0.0.0.0']) {
				const result = validateDomain(ip);
				expect(result.valid).toBe(false);
				expect(result.error).toContain('IP addresses');
			}
		});

		it('rejects IPv6 addresses', () => {
			for (const ip of ['::1', 'fe80::1', 'fc00::1', 'fd00::1']) {
				const result = validateDomain(ip);
				expect(result.valid).toBe(false);
				// IPv6 with colons will either match IP patterns or fail label validation
				expect(result.valid).toBe(false);
			}
		});

		it('rejects DNS rebinding services', () => {
			for (const suffix of ['.nip.io', '.sslip.io', '.xip.io', '.nip.direct']) {
				const domain = `app${suffix}`;
				const result = validateDomain(domain);
				expect(result.valid).toBe(false);
				expect(result.error).toContain('DNS rebinding');
			}
		});

		it('rejects single-label domains', () => {
			const result = validateDomain('myhost');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('two labels');
		});

		it('rejects domains with consecutive dots', () => {
			const result = validateDomain('example..com');
			expect(result.valid).toBe(false);
			expect(result.error).toContain('empty label');
		});

		it('rejects labels exceeding 63 characters', () => {
			const longLabel = 'a'.repeat(64) + '.com';
			const result = validateDomain(longLabel);
			expect(result.valid).toBe(false);
			expect(result.error).toContain('maximum length');
		});

		it('rejects labels with invalid characters', () => {
			expect(validateDomain('under_score.com').valid).toBe(false);
			expect(validateDomain('-leading.com').valid).toBe(false);
			expect(validateDomain('trailing-.com').valid).toBe(false);

			const underscoreResult = validateDomain('under_score.com');
			expect(underscoreResult.error).toContain('invalid characters');
		});

		it('rejects whitespace-only input', () => {
			const result = validateDomain('   ');
			expect(result.valid).toBe(false);
			expect(result.error).toBe('Domain name is required');
		});
	});

	describe('sanitizeDomain', () => {
		it('trims whitespace, lowercases, and removes trailing dot', () => {
			expect(sanitizeDomain('  Example.COM.  ')).toBe('example.com');
		});

		it('returns empty string for empty input', () => {
			expect(sanitizeDomain('')).toBe('');
		});

		it('handles domain without trailing dot', () => {
			expect(sanitizeDomain('Example.COM')).toBe('example.com');
		});
	});

});
