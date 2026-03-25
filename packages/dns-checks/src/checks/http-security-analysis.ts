// SPDX-License-Identifier: BUSL-1.1

/**
 * HTTP security headers analysis helpers.
 * Pure functions for analyzing browser security headers from HTTP responses.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { Finding } from '../types';
import { createFinding } from '../check-utils';

/** Headers checked by the HTTP security analysis. */
const SECURITY_HEADERS = [
	'content-security-policy',
	'x-frame-options',
	'x-content-type-options',
	'permissions-policy',
	'referrer-policy',
	'cross-origin-resource-policy',
	'cross-origin-opener-policy',
] as const;

/** CSP directive name for dynamic code execution. */
const CSP_UNSAFE_EVAL_DIRECTIVE = "'unsafe-eval'";

/**
 * Analyze CSP for unsafe directives.
 * Returns findings for unsafe-inline, unsafe-eval, and wildcard sources in script-src.
 */
function analyzeCspQuality(cspValue: string): Finding[] {
	const findings: Finding[] = [];
	const lower = cspValue.toLowerCase();

	// Check for unsafe-inline in script-src (or default-src if no script-src)
	const scriptSrcMatch = lower.match(/script-src\s+([^;]+)/);
	const defaultSrcMatch = lower.match(/default-src\s+([^;]+)/);
	const effectiveScriptSrc = scriptSrcMatch?.[1] ?? defaultSrcMatch?.[1] ?? '';

	if (effectiveScriptSrc.includes("'unsafe-inline'")) {
		findings.push(
			createFinding(
				'http_security',
				'CSP allows unsafe-inline scripts',
				'medium',
				"Content-Security-Policy contains 'unsafe-inline' in the script source, which undermines XSS protection. Use nonces or hashes instead.",
			),
		);
	}

	if (effectiveScriptSrc.includes(CSP_UNSAFE_EVAL_DIRECTIVE)) {
		findings.push(
			createFinding(
				'http_security',
				'CSP allows unsafe-eval',
				'medium',
				`Content-Security-Policy contains ${CSP_UNSAFE_EVAL_DIRECTIVE} in the script source, allowing dynamic code execution. This weakens XSS protection.`,
			),
		);
	}

	// Check for wildcard source in script-src or default-src
	// Match standalone * but not *.example.com
	const sources = effectiveScriptSrc.split(/\s+/);
	if (sources.some((s) => s === '*')) {
		findings.push(
			createFinding(
				'http_security',
				'CSP uses wildcard source',
				'medium',
				'Content-Security-Policy uses a wildcard (*) source, allowing scripts from any origin. This provides minimal XSS protection.',
			),
		);
	}

	return findings;
}

/**
 * Analyze HTTP security headers from a response.
 * Returns findings for missing or misconfigured headers.
 *
 * @param headers - The response headers to analyze
 * @returns Array of findings describing missing or weak security headers
 */
export function analyzeSecurityHeaders(headers: Headers): Finding[] {
	const findings: Finding[] = [];

	const csp = headers.get('content-security-policy');
	const xfo = headers.get('x-frame-options');
	const xcto = headers.get('x-content-type-options');
	const pp = headers.get('permissions-policy');
	const rp = headers.get('referrer-policy');
	const corp = headers.get('cross-origin-resource-policy');
	const coop = headers.get('cross-origin-opener-policy');

	// Track whether we have CSP frame-ancestors (supersedes X-Frame-Options)
	const cspHasFrameAncestors = csp ? /frame-ancestors/i.test(csp) : false;

	// Content-Security-Policy
	if (!csp) {
		findings.push(
			createFinding(
				'http_security',
				'No Content-Security-Policy',
				'high',
				'No Content-Security-Policy header found. CSP is a critical defense against cross-site scripting (XSS) and data injection attacks.',
			),
		);
	} else {
		findings.push(...analyzeCspQuality(csp));
	}

	// X-Frame-Options — only flag if CSP frame-ancestors is also missing
	if (!xfo && !cspHasFrameAncestors) {
		findings.push(
			createFinding(
				'http_security',
				'No X-Frame-Options',
				'medium',
				'No X-Frame-Options header and no CSP frame-ancestors directive found. The page may be vulnerable to clickjacking attacks.',
			),
		);
	}

	// X-Content-Type-Options
	if (!xcto) {
		findings.push(
			createFinding(
				'http_security',
				'No X-Content-Type-Options',
				'low',
				'No X-Content-Type-Options header found. Set to "nosniff" to prevent browsers from MIME-sniffing the content type.',
			),
		);
	}

	// Permissions-Policy
	if (!pp) {
		findings.push(
			createFinding(
				'http_security',
				'No Permissions-Policy',
				'low',
				'No Permissions-Policy header found. This header restricts access to browser features like camera, microphone, and geolocation.',
			),
		);
	}

	// Referrer-Policy
	if (!rp) {
		findings.push(
			createFinding(
				'http_security',
				'No Referrer-Policy',
				'low',
				'No Referrer-Policy header found. Without it, the full URL including query parameters may be leaked to third-party sites via the Referer header.',
			),
		);
	}

	// Cross-Origin-Resource-Policy
	if (!corp) {
		findings.push(
			createFinding(
				'http_security',
				'No CORP header',
				'info',
				'No Cross-Origin-Resource-Policy header found. CORP prevents other origins from loading your resources, mitigating Spectre-class side-channel attacks.',
			),
		);
	}

	// Cross-Origin-Opener-Policy
	if (!coop) {
		findings.push(
			createFinding(
				'http_security',
				'No COOP header',
				'info',
				'No Cross-Origin-Opener-Policy header found. COOP isolates the browsing context from cross-origin popups, mitigating cross-origin attacks.',
			),
		);
	}

	// All good case: all headers present and CSP has no unsafe directives
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'http_security',
				'HTTP security headers well configured',
				'info',
				`All ${SECURITY_HEADERS.length} security headers are present and Content-Security-Policy has no unsafe directives.`,
			),
		);
	}

	return findings;
}
