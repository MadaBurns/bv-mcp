import { describe, it, expect } from 'vitest';
import {
	validateDomain,
	sanitizeDomain,
	sanitizeInput,
	mcpError,
	mcpText,
	withErrorHandling,
} from '../src/lib/sanitize';

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
				'.local', '.localhost', '.internal', '.example', '.invalid',
				'.test', '.onion', '.lan', '.home', '.corp', '.intranet',
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

	describe('sanitizeInput', () => {
		it('removes control characters but keeps newline and tab', () => {
			const input = 'hello\x00\x01\x08\x0B\x0C\x0E\x1F\x7Fworld\n\ttab';
			expect(sanitizeInput(input)).toBe('helloworld\n\ttab');
		});

		it('truncates to default maxLength of 500', () => {
			const long = 'a'.repeat(600);
			expect(sanitizeInput(long)).toHaveLength(500);
		});

		it('truncates to custom maxLength', () => {
			const input = 'a'.repeat(100);
			expect(sanitizeInput(input, 50)).toHaveLength(50);
		});

		it('returns empty string for non-string input', () => {
			expect(sanitizeInput(null as unknown as string)).toBe('');
			expect(sanitizeInput(undefined as unknown as string)).toBe('');
			expect(sanitizeInput(123 as unknown as string)).toBe('');
		});

		it('returns the string unchanged when no control chars and under maxLength', () => {
			expect(sanitizeInput('normal text')).toBe('normal text');
		});
	});

	describe('mcpError', () => {
		it('returns error content with correct structure', () => {
			expect(mcpError('something failed')).toEqual({
				type: 'text',
				text: 'Error: something failed',
			});
		});
	});

	describe('mcpText', () => {
		it('returns text content with correct structure', () => {
			expect(mcpText('hello world')).toEqual({
				type: 'text',
				text: 'hello world',
			});
		});
	});

	describe('withErrorHandling', () => {
		it('returns resolved value on success', async () => {
			const result = await withErrorHandling(() => Promise.resolve('ok'));
			expect(result).toBe('ok');
		});

		it('returns mcpError when Error is thrown', async () => {
			const result = await withErrorHandling(() => Promise.reject(new Error('fail')));
			expect(result).toEqual({ type: 'text', text: 'Error: fail' });
		});

		it('uses fallback message for non-Error throw', async () => {
			const result = await withErrorHandling(
				() => Promise.reject('string error'),
				'custom fallback',
			);
			expect(result).toEqual({ type: 'text', text: 'Error: custom fallback' });
		});

		it('uses default fallback message when no custom message provided', async () => {
			const result = await withErrorHandling(() => Promise.reject('string error'));
			expect(result).toEqual({ type: 'text', text: 'Error: An unexpected error occurred' });
		});
	});
});
