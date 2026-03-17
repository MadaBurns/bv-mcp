// SPDX-License-Identifier: BUSL-1.1

/**
 * HTTP security headers check tool.
 * Fetches the HTTPS endpoint and analyzes browser security headers
 * (CSP, X-Frame-Options, X-Content-Type-Options, Permissions-Policy,
 * Referrer-Policy, CORP, COOP).
 * Workers-compatible: uses fetch API only.
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { analyzeSecurityHeaders } from './http-security-analysis';
/**
 * Check HTTP security headers for a domain.
 * Fetches the HTTPS endpoint and analyzes browser security headers.
 */
export async function checkHttpSecurity(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	try {
		const response = await fetch(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual', // SSRF protection — never follow redirects
			signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
		});

		// Only analyze headers on successful or redirect responses
		if (response.status < 500) {
			findings.push(...analyzeSecurityHeaders(response.headers));
		} else {
			findings.push(
				createFinding(
					'http_security',
					'Server error',
					'medium',
					`HTTPS returned status ${response.status} for ${domain}. Cannot analyze security headers.`,
				),
			);
		}
	} catch (err) {
		const message =
			err instanceof Error && (err.message.includes('timeout') || err.message.includes('abort'))
				? 'Connection timed out'
				: 'Connection failed';
		findings.push(
			createFinding(
				'http_security',
				`HTTPS ${message.toLowerCase()}`,
				'medium',
				`Could not fetch https://${domain} to check security headers: ${message}.`,
			),
		);
	}

	return buildCheckResult('http_security', findings);
}
