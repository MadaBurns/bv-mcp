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

/** Maximum redirect hops to follow */
const MAX_REDIRECT_HOPS = 3;

/**
 * Follow redirects manually to get the final response with security headers.
 * Redirect responses (e.g., nist.gov → www.nist.gov) typically lack security
 * headers, causing false negatives if we analyze the 301 instead of the 200.
 *
 * Handles Cloudflare Workers opaque redirect responses (status 0) and standard
 * 3xx redirects. Only follows HTTPS redirects (no protocol downgrade).
 */
async function followRedirects(
	response: Response,
	fetchFn: FetchFunction,
	timeoutMs: number,
): Promise<Response> {
	for (let hop = 0; hop < MAX_REDIRECT_HOPS; hop++) {
		const status = response.status;
		const isRedirect = (status >= 300 && status < 400) || response.type === 'opaqueredirect' || (status === 0 && response.headers.get('location'));
		if (!isRedirect) break;

		const location = response.headers.get('location');
		if (!location) break;

		let nextUrl: string;
		try {
			nextUrl = new URL(location, response.url || undefined).href;
		} catch {
			break;
		}

		// Only follow HTTPS redirects
		if (!nextUrl.startsWith('https://')) break;

		try {
			response = await fetchFn(nextUrl, {
				method: 'HEAD',
				redirect: 'manual',
				signal: AbortSignal.timeout(timeoutMs),
			});
		} catch {
			break;
		}
	}

	return response;
}

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
		let response = await fetchFn(`https://${domain}`, {
			method: 'HEAD',
			redirect: 'manual',
			signal: AbortSignal.timeout(timeoutMs),
		});

		// Follow redirects to get the final destination's headers
		response = await followRedirects(response, fetchFn, timeoutMs);

		// Only analyze headers on successful responses (not redirects or errors)
		if (response.ok) {
			findings.push(...analyzeSecurityHeaders(response.headers));
		} else if (response.status >= 500) {
			findings.push(
				createFinding(
					'http_security',
					'Server error',
					'medium',
					`HTTPS returned status ${response.status} for ${domain}. Cannot analyze security headers.`,
				),
			);
		} else if (response.status >= 300 && response.status < 400) {
			// Still a redirect after max hops — analyze whatever headers we have
			findings.push(...analyzeSecurityHeaders(response.headers));
		} else if (response.status === 0) {
			findings.push(
				createFinding(
					'http_security',
					'Server error',
					'medium',
					`HTTPS returned status ${response.status} for ${domain}. Cannot analyze security headers.`,
				),
			);
		} else {
			findings.push(...analyzeSecurityHeaders(response.headers));
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
				{ missingControl: true },
			),
		);
	}

	return buildCheckResult('http_security', findings);
}
