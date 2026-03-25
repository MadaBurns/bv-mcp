// SPDX-License-Identifier: BUSL-1.1

/**
 * HTTP security headers check.
 * Fetches the HTTPS endpoint and analyzes browser security headers.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { CheckResult, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { analyzeSecurityHeaders } from './http-security-analysis';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/**
 * Check HTTP security headers for a domain.
 * Fetches the HTTPS endpoint and analyzes browser security headers.
 *
 * Requires a fetch function for making HTTP requests.
 */
export async function checkHTTPSecurity(
	domain: string,
	fetchFn: FetchFunction,
	options?: { timeout?: number },
): Promise<CheckResult> {
	const timeoutMs = options?.timeout ?? HTTPS_TIMEOUT_MS;
	const findings: Finding[] = [];

	try {
		const response = await fetchFn(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual', // SSRF protection — never follow redirects
			signal: AbortSignal.timeout(timeoutMs),
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
