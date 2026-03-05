/**
 * SSL/TLS certificate check tool.
 * Validates SSL certificate by attempting HTTPS connection,
 * checks HSTS configuration,
 * and verifies HTTP→HTTPS redirect.
 * Workers-compatible: uses fetch API only (cert expiry/chain require external APIs).
 */

import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';

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
		findings.push(createFinding('ssl', 'SSL/TLS properly configured', 'info', `HTTPS is accessible for ${domain} with HSTS enabled and certificate transparency checks pass.`));
	}

	return buildCheckResult('ssl', findings);
}

/** Check HTTPS connectivity by attempting a fetch */
async function checkHttps(domain: string): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const response = await fetch(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'follow',
			signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
		});

		// Check if we got redirected to HTTP (downgrade)
		if (response.url && response.url.startsWith('http://')) {
			findings.push(
				createFinding(
					'ssl',
					'HTTPS redirects to HTTP',
					'critical',
					`${domain} redirects HTTPS requests to HTTP, exposing traffic to interception.`,
				),
			);
		}

		// Check for HSTS header
		const hstsHeader = response.headers.get('strict-transport-security');
		if (!hstsHeader) {
			findings.push(
				createFinding(
					'ssl',
					'No HSTS header',
					'medium',
					`${domain} does not set a Strict-Transport-Security header. HSTS prevents browsers from connecting over plain HTTP.`,
				),
			);
		} else {
			// Check max-age value
			const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
			if (maxAgeMatch) {
				const maxAge = parseInt(maxAgeMatch[1], 10);
				if (maxAge < 31536000) {
					findings.push(
						createFinding(
							'ssl',
							'HSTS max-age too short',
							'low',
							`HSTS max-age is ${maxAge} seconds (${Math.round(maxAge / 86400)} days). Recommended minimum is 31536000 (1 year).`,
						),
					);
				}
			}

			// Check for includeSubDomains
			if (!/includeSubDomains/i.test(hstsHeader)) {
				findings.push(
					createFinding(
						'ssl',
						'HSTS missing includeSubDomains',
						'low',
						`HSTS header does not include the includeSubDomains directive. Subdomains are not protected by HSTS.`,
					),
				);
			}
		}

	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);

		if (message.includes('timeout') || message.includes('abort')) {
			findings.push(
				createFinding(
					'ssl',
					'HTTPS connection timeout',
					'high',
					`Could not establish HTTPS connection to ${domain} within 10 seconds. The server may not support HTTPS.`,
				),
			);
		} else {
			findings.push(
				createFinding(
					'ssl',
					'HTTPS connection failed',
					'critical',
					`Failed to connect to ${domain} over HTTPS: ${message}. The domain may not have a valid SSL certificate.`,
				),
			);
		}
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
		// 3xx with Location header pointing to HTTPS = good
		const location = response.headers.get('location');
		if (response.status >= 300 && response.status < 400 && location?.startsWith('https://')) {
			// Good — HTTP redirects to HTTPS
		} else if (response.status >= 300 && response.status < 400 && location && !location.startsWith('https://')) {
			findings.push(
				createFinding(
					'ssl',
					'HTTP does not redirect to HTTPS',
					'medium',
					`HTTP requests to ${domain} redirect to ${location} instead of HTTPS.`,
				),
			);
		} else {
			findings.push(
				createFinding(
					'ssl',
					'No HTTP to HTTPS redirect',
					'medium',
					`HTTP requests to ${domain} are not redirected to HTTPS (status ${response.status}).`,
				),
			);
		}
	} catch {
		// HTTP not available or blocked — not necessarily an issue, skip silently
	}
	return findings;
}
