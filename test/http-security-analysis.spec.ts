// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';
import { analyzeSecurityHeaders } from '../src/tools/http-security-analysis';

describe('analyzeSecurityHeaders', () => {
	function makeHeaders(map: Record<string, string>): Headers {
		return new Headers(map);
	}

	it('should return info finding when all headers present and CSP is clean', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=(), microphone=()',
			'referrer-policy': 'strict-origin-when-cross-origin',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		expect(findings).toHaveLength(1);
		expect(findings[0].severity).toBe('info');
		expect(findings[0].title).toBe('HTTP security headers well configured');
	});

	it('should return high finding for missing CSP', () => {
		const headers = makeHeaders({
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const cspFinding = findings.find((f) => f.title === 'No Content-Security-Policy');
		expect(cspFinding).toBeDefined();
		expect(cspFinding!.severity).toBe('high');
	});

	it('should return medium finding for missing X-Frame-Options when CSP has no frame-ancestors', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'",
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const xfoFinding = findings.find((f) => f.title === 'No X-Frame-Options');
		expect(xfoFinding).toBeDefined();
		expect(xfoFinding!.severity).toBe('medium');
	});

	it('should NOT flag missing X-Frame-Options when CSP has frame-ancestors', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const xfoFinding = findings.find((f) => f.title === 'No X-Frame-Options');
		expect(xfoFinding).toBeUndefined();
	});

	it('should return low finding for missing X-Content-Type-Options', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'No X-Content-Type-Options');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return low finding for missing Permissions-Policy', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'No Permissions-Policy');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return low finding for missing Referrer-Policy', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'No Referrer-Policy');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return info finding for missing CORP', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'No CORP header');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('info');
	});

	it('should return info finding for missing COOP', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'No COOP header');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('info');
	});

	it('should return medium finding for CSP with unsafe-inline', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'CSP allows unsafe-inline scripts');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return medium finding for CSP with unsafe-eval', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'CSP allows unsafe-eval');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return medium finding for CSP with wildcard source', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; script-src *; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'CSP uses wildcard source');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should NOT flag wildcard in subdomain patterns like *.example.com', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self'; script-src 'self' *.cdn.example.com; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const wildcardFinding = findings.find((f) => f.title === 'CSP uses wildcard source');
		expect(wildcardFinding).toBeUndefined();
	});

	it('should detect unsafe-inline in default-src when no script-src is present', () => {
		const headers = makeHeaders({
			'content-security-policy': "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
			'x-frame-options': 'DENY',
			'x-content-type-options': 'nosniff',
			'permissions-policy': 'camera=()',
			'referrer-policy': 'no-referrer',
			'cross-origin-resource-policy': 'same-origin',
			'cross-origin-opener-policy': 'same-origin',
		});
		const findings = analyzeSecurityHeaders(headers);
		const finding = findings.find((f) => f.title === 'CSP allows unsafe-inline scripts');
		expect(finding).toBeDefined();
	});

	it('should return multiple findings when no headers at all', () => {
		const headers = makeHeaders({});
		const findings = analyzeSecurityHeaders(headers);
		// Missing CSP (high), XFO (medium), XCTO (low), PP (low), RP (low), CORP (info), COOP (info)
		expect(findings.length).toBe(7);
		expect(findings.filter((f) => f.severity === 'high')).toHaveLength(1);
		expect(findings.filter((f) => f.severity === 'medium')).toHaveLength(1);
		expect(findings.filter((f) => f.severity === 'low')).toHaveLength(3);
		expect(findings.filter((f) => f.severity === 'info')).toHaveLength(2);
	});

	it('should set category to http_security for all findings', () => {
		const headers = makeHeaders({});
		const findings = analyzeSecurityHeaders(headers);
		for (const finding of findings) {
			expect(finding.category).toBe('http_security');
		}
	});
});
