// SPDX-License-Identifier: BUSL-1.1

/**
 * SSL/TLS certificate check.
 * Validates SSL certificate by attempting HTTPS connection,
 * checks HSTS configuration, and verifies HTTP->HTTPS redirect.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { getHttpRedirectFindings, getHttpsErrorFinding, getHttpsFindings, getRobotsDisallowedFinding } from './ssl-analysis';
import { RobotsDisallowedError } from '../robots-gate';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/**
 * Check SSL/TLS configuration for a domain.
 * Validates HTTPS connectivity, HSTS headers, and HTTP->HTTPS redirect.
 *
 * Requires a fetch function for making HTTP requests.
 */
export async function checkSSL(domain: string, fetchFn: FetchFunction, options?: { timeout?: number }): Promise<CheckResult> {
	const timeoutMs = options?.timeout ?? HTTPS_TIMEOUT_MS;
	const findings: Finding[] = [];

	const { findings: httpsFindings, reachable, robotsDisallowed } = await checkHttps(domain, fetchFn, timeoutMs);
	findings.push(...httpsFindings);

	// The entire `ssl` category signal comes from fetching the target — when robots.txt disallows
	// it, exclude the category (checkStatus: 'error') rather than scoring a false pass (no other
	// findings = 100) or letting a downstream check run against a target we were told not to touch.
	if (robotsDisallowed) {
		return { ...buildCheckResult('ssl', findings, undefined), checkStatus: 'error' };
	}

	// Only check HTTP redirect if HTTPS is working (no critical findings)
	const hasCritical = findings.some((f) => f.severity === 'critical');
	if (!hasCritical) {
		const redirectResult = await checkHttpRedirect(domain, fetchFn, timeoutMs);
		findings.push(...redirectResult);
	}

	if (findings.length === 0) {
		findings.push(
			createFinding(
				'ssl',
				'HTTPS and HSTS properly configured',
				'info',
				`HTTPS connection succeeded and HSTS header is properly configured for ${domain}. Note: This check verifies HTTPS reachability and HSTS policy. Certificate expiry, TLS version, and cipher suite analysis require a dedicated TLS scanner.`,
			),
		);
	}

	// controlPresent: HTTPS was reachable (the TLS handshake completed). A connection failure/timeout
	// means no working web TLS endpoint → web control absent for profile detection.
	return buildCheckResult('ssl', findings, reachable);
}

/**
 * Check HTTPS connectivity by attempting a fetch.
 * `reachable` is true when the TLS handshake completed (any HTTP response was received, including
 * redirects/errors); false when the connection failed or timed out; undefined (with
 * `robotsDisallowed: true`) when robots.txt disallowed the fetch and reachability was never determined.
 */
async function checkHttps(
	domain: string,
	fetchFn: FetchFunction,
	timeoutMs: number,
): Promise<{ findings: Finding[]; reachable: boolean | undefined; robotsDisallowed: boolean }> {
	const findings: Finding[] = [];
	let reachable = false;

	try {
		const response = await fetchFn(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs),
		});
		reachable = true;

		const isRedirect = response.status >= 300 && response.status < 400;
		const location = isRedirect ? response.headers.get('location') : null;
		const isDowngrade = location?.startsWith('http://') ?? false;
		const isHttpsRedirect = isRedirect && !isDowngrade;

		if (!isHttpsRedirect) {
			const redirectTarget = isDowngrade ? (location ?? undefined) : undefined;
			findings.push(...getHttpsFindings(domain, redirectTarget, response.headers.get('strict-transport-security')));
		}
	} catch (err) {
		if (err instanceof RobotsDisallowedError) {
			return {
				findings: [getRobotsDisallowedFinding(domain)],
				reachable: undefined,
				robotsDisallowed: true,
			};
		}
		const message =
			err instanceof Error && (err.message.includes('timeout') || err.message.includes('abort'))
				? 'Connection timeout'
				: 'Connection failed';
		findings.push(getHttpsErrorFinding(domain, message));
	}

	return { findings, reachable, robotsDisallowed: false };
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
		// HTTP not available or blocked — not necessarily an issue, skip silently. (Unreachable in
		// the robots-disallowed case: checkSSL returns before this function is ever called.)
	}
	return findings;
}
