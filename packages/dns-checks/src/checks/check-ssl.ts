// SPDX-License-Identifier: BUSL-1.1

/**
 * SSL/TLS certificate check.
 * Validates SSL certificate by attempting HTTPS connection,
 * checks HSTS configuration, and verifies HTTP->HTTPS redirect.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { getHttpRedirectFindings, getHttpsErrorFinding, getHttpsFindings } from './ssl-analysis';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/**
 * Check SSL/TLS configuration for a domain.
 * Validates HTTPS connectivity, HSTS headers, and HTTP->HTTPS redirect.
 *
 * Requires a fetch function for making HTTP requests.
 */
export async function checkSSL(
	domain: string,
	fetchFn: FetchFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeoutMs = options?.timeout ?? HTTPS_TIMEOUT_MS;
	const findings: Finding[] = [];

	const httpsResult = await checkHttps(domain, fetchFn, timeoutMs);
	findings.push(...httpsResult);

	// Only check HTTP redirect if HTTPS is working (no critical findings)
	const hasCritical = findings.some((f) => f.severity === 'critical');
	if (!hasCritical) {
		const redirectResult = await checkHttpRedirect(domain, fetchFn, timeoutMs);
		findings.push(...redirectResult);
	}

	if (findings.length === 0) {
		findings.push(createFinding('ssl', 'HTTPS and HSTS properly configured', 'info', `HTTPS connection succeeded and HSTS header is properly configured for ${domain}. Note: This check verifies HTTPS reachability and HSTS policy. Certificate expiry, TLS version, and cipher suite analysis require a dedicated TLS scanner.`));
	}

	return buildCheckResult('ssl', findings);
}

/** Check HTTPS connectivity by attempting a fetch */
async function checkHttps(domain: string, fetchFn: FetchFunction, timeoutMs: number): Promise<Finding[]> {
	const findings: Finding[] = [];

	try {
		const response = await fetchFn(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs),
		});

		const isRedirect = response.status >= 300 && response.status < 400;
		const location = isRedirect ? response.headers.get('location') : null;
		const isDowngrade = location?.startsWith('http://') ?? false;
		const isHttpsRedirect = isRedirect && !isDowngrade;

		if (!isHttpsRedirect) {
			const redirectTarget = isDowngrade ? (location ?? undefined) : undefined;
			findings.push(...getHttpsFindings(domain, redirectTarget, response.headers.get('strict-transport-security')));
		}

	} catch (err) {
		const message = err instanceof Error && (err.message.includes('timeout') || err.message.includes('abort'))
			? err.message
			: 'Connection failed';
		findings.push(getHttpsErrorFinding(domain, message));
	}

	return findings;
}

/** Check if HTTP redirects to HTTPS */
async function checkHttpRedirect(domain: string, fetchFn: FetchFunction, timeoutMs: number): Promise<Finding[]> {
	const findings: Finding[] = [];
	try {
		const response = await fetchFn(`http://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs),
		});
		findings.push(...getHttpRedirectFindings(domain, response.status, response.headers.get('location')));
	} catch {
		// HTTP not available or blocked — not necessarily an issue, skip silently
	}
	return findings;
}
