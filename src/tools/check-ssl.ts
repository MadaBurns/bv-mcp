// SPDX-License-Identifier: MIT

/**
 * SSL/TLS certificate check tool.
 * Validates SSL certificate by attempting HTTPS connection,
 * checks HSTS configuration,
 * and verifies HTTP→HTTPS redirect.
 * Workers-compatible: uses fetch API only (cert expiry/chain require external APIs).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { getHttpRedirectFindings, getHttpsErrorFinding, getHttpsFindings } from './ssl-analysis';

/**
 * Check SSL/TLS configuration for a domain.
 * Validates HTTPS connectivity, HSTS headers, and HTTP→HTTPS redirect.
 */
export async function checkSsl(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	const httpsResult = await checkHttps(domain);
	findings.push(...httpsResult);

	// Only check HTTP redirect if HTTPS is working (no critical findings)
	const hasCritical = findings.some((f) => f.severity === 'critical');
	if (!hasCritical) {
		const redirectResult = await checkHttpRedirect(domain);
		findings.push(...redirectResult);
	}

	if (findings.length === 0) {
		findings.push(createFinding('ssl', 'HTTPS and HSTS properly configured', 'info', `HTTPS connection succeeded and HSTS header is properly configured for ${domain}. Note: This check verifies HTTPS reachability and HSTS policy. Certificate expiry, TLS version, and cipher suite analysis require a dedicated TLS scanner.`));
	}

	return buildCheckResult('ssl', findings);
}

/** Check HTTPS connectivity by attempting a fetch */
async function checkHttps(domain: string): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const response = await fetch(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
		});

		// For redirects, check Location header for HTTP downgrade instead of following
		const redirectTarget = (response.status >= 300 && response.status < 400)
			? response.headers.get('location') ?? undefined
			: undefined;
		findings.push(...getHttpsFindings(domain, redirectTarget, response.headers.get('strict-transport-security')));

	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		findings.push(getHttpsErrorFinding(domain, message));
	}

	return findings;
}

/** Check if HTTP redirects to HTTPS */
async function checkHttpRedirect(domain: string): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const response = await fetch(`http://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
		});
		findings.push(...getHttpRedirectFindings(domain, response.status, response.headers.get('location')));
	} catch {
		// HTTP not available or blocked — not necessarily an issue, skip silently
	}
	return findings;
}
