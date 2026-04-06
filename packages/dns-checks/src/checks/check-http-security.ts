// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BlackVeil Security Ltd.

import type { CheckResult, FetchFunction, Finding } from '../types';
import { buildCheckResult, createFinding } from '../check-utils';
import { analyzeSecurityHeaders } from './http-security-analysis';

/** Default HTTPS timeout (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/** User-Agent sent with all outbound HTTP requests to reduce WAF false blocks. */
const SCANNER_USER_AGENT = 'Mozilla/5.0 (compatible; BlackVeilDNSScanner/1.0; +https://blackveilsecurity.com)';

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
				headers: { 'User-Agent': SCANNER_USER_AGENT },
				signal: AbortSignal.timeout(timeoutMs),
			});
		} catch {
			break;
		}
	}

	return response;
}

/**
 * Attempt a GET request as fallback when HEAD is blocked (403/405).
 * Returns null on any fetch error.
 */
async function tryGetFallback(url: string, fetchFn: FetchFunction, timeoutMs: number): Promise<Response | null> {
	try {
		return await fetchFn(url, {
			method: 'GET',
			redirect: 'manual',
			headers: { 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(timeoutMs),
		});
	} catch {
		return null;
	}
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
			headers: { 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(timeoutMs),
		});

		// Follow redirects to get the final destination's headers
		response = await followRedirects(response, fetchFn, timeoutMs);

		if (response.ok) {
			// 200-299: analyze headers normally
			findings.push(...analyzeSecurityHeaders(response.headers));
		} else if (response.status === 0 || response.status >= 500) {
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
		} else if (response.status === 403 || response.status === 405) {
			// WAF block or HEAD not allowed — retry with GET to get real headers
			const getResponse = await tryGetFallback(`https://${domain}`, fetchFn, timeoutMs);
			if (getResponse && (getResponse.ok || (getResponse.status >= 300 && getResponse.status < 400))) {
				const followed = await followRedirects(getResponse, fetchFn, timeoutMs);
				findings.push(...analyzeSecurityHeaders(followed.headers));
			} else {
				findings.push(
					createFinding(
						'http_security',
						'HTTP check blocked by security appliance',
						'info',
						`The site returned HTTP ${response.status} for ${domain}. A WAF or firewall is blocking external header inspection. Security headers cannot be verified.`,
						{ missingControl: true },
					),
				);
			}
		} else if (response.status === 401) {
			findings.push(
				createFinding(
					'http_security',
					'HTTP check requires authentication',
					'info',
					`The site returned HTTP 401 for ${domain}. The endpoint requires authentication; security headers cannot be verified externally.`,
					{ missingControl: true },
				),
			);
		} else {
			// Other 4xx (404, 429, etc.) — blocked or rejected
			findings.push(
				createFinding(
					'http_security',
					'HTTP request rejected',
					'medium',
					`HTTPS returned status ${response.status} for ${domain}. Cannot analyze security headers.`,
					{ missingControl: true },
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
				{ missingControl: true },
			),
		);
	}

	return buildCheckResult('http_security', findings);
}
