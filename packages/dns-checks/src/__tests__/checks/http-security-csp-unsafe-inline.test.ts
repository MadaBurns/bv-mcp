// SPDX-License-Identifier: BUSL-1.1

/**
 * CSP3 §6.7.3: when a `script-src` source list carries a nonce-source, a hash-source,
 * or `'strict-dynamic'`, a browser that understands those ignores `'unsafe-inline'`.
 * The remaining `'unsafe-inline'` is the documented backwards-compat fallback for
 * CSP1 browsers, so it must not be reported as weakening XSS protection.
 */

import { describe, it, expect } from 'vitest';
import { analyzeSecurityHeaders } from '../../checks/http-security-analysis';

const UNSAFE_INLINE_TITLE = 'CSP allows unsafe-inline scripts';

function titles(csp: string): string[] {
	return analyzeSecurityHeaders(new Headers({ 'content-security-policy': csp })).map((f) => f.title);
}

describe('CSP unsafe-inline is inert next to nonce / hash / strict-dynamic (CSP3 §6.7.3)', () => {
	it('still flags a bare unsafe-inline in script-src', () => {
		expect(titles("script-src 'self' 'unsafe-inline'")).toContain(UNSAFE_INLINE_TITLE);
	});

	it('does not flag unsafe-inline alongside a nonce source', () => {
		expect(titles("script-src 'nonce-abc123' 'unsafe-inline'")).not.toContain(UNSAFE_INLINE_TITLE);
	});

	it('does not flag unsafe-inline alongside a sha256 hash source', () => {
		expect(titles("script-src 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'unsafe-inline'")).not.toContain(UNSAFE_INLINE_TITLE);
	});

	it('does not flag unsafe-inline alongside sha384 / sha512 hash sources', () => {
		expect(titles("script-src 'sha384-abc' 'unsafe-inline'")).not.toContain(UNSAFE_INLINE_TITLE);
		expect(titles("script-src 'sha512-abc' 'unsafe-inline'")).not.toContain(UNSAFE_INLINE_TITLE);
	});

	it('does not flag unsafe-inline alongside strict-dynamic', () => {
		expect(titles("script-src 'strict-dynamic' 'unsafe-inline' https:")).not.toContain(UNSAFE_INLINE_TITLE);
	});

	it('applies the same rule when the policy falls back to default-src', () => {
		expect(titles("default-src 'nonce-abc123' 'unsafe-inline'")).not.toContain(UNSAFE_INLINE_TITLE);
		expect(titles("default-src 'self' 'unsafe-inline'")).toContain(UNSAFE_INLINE_TITLE);
	});

	it('does not let a nonce in a different directive neutralise unsafe-inline in script-src', () => {
		expect(titles("script-src 'self' 'unsafe-inline'; style-src 'nonce-abc123'")).toContain(UNSAFE_INLINE_TITLE);
	});

	it('still reports unsafe-eval when unsafe-inline is neutralised', () => {
		const result = titles("script-src 'nonce-abc123' 'unsafe-inline' 'unsafe-eval'");
		expect(result).not.toContain(UNSAFE_INLINE_TITLE);
		expect(result).toContain('CSP allows unsafe-eval');
	});
});
