// SPDX-License-Identifier: BUSL-1.1

/**
 * HTTP security headers check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 * Post-augments with CDN provider detection from response headers.
 */

import { checkHTTPSecurity } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { createFinding } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';

/** Detect CDN provider from HTTP response headers. Returns provider name or null. */
function detectCdnProvider(headers: Headers): string | null {
	if (headers.get('cf-ray') || headers.get('server')?.toLowerCase().includes('cloudflare')) {
		return 'Cloudflare';
	}
	if (headers.get('x-vercel-id') || headers.get('x-vercel-cache')) {
		return 'Vercel';
	}
	if (headers.get('x-amz-cf-id') || headers.get('via')?.includes('CloudFront')) {
		return 'CloudFront';
	}
	const servedBy = headers.get('x-served-by') ?? '';
	if (servedBy.includes('cache') || headers.get('via')?.toLowerCase().includes('varnish')) {
		return 'Fastly';
	}
	if (headers.get('x-akamai-transformed') || headers.get('x-check-cacheable')) {
		return 'Akamai';
	}
	return null;
}

/**
 * Check HTTP security headers for a domain.
 * Fetches the HTTPS endpoint and analyzes browser security headers.
 * Detects CDN provider and adds an info finding when CDN headers are present.
 */
export async function checkHttpSecurity(domain: string): Promise<CheckResult> {
	let capturedHeaders: Headers | null = null;
	const capturingFetch: typeof fetch = async (input, init) => {
		const response = await fetch(input, init);
		capturedHeaders = response.headers;
		return response;
	};

	const result = await checkHTTPSecurity(domain, capturingFetch, { timeout: HTTPS_TIMEOUT_MS }) as CheckResult;

	if (!capturedHeaders) return result;

	const cdnProvider = detectCdnProvider(capturedHeaders);
	if (!cdnProvider) return result;

	const cdnFinding = createFinding(
		'http_security',
		`HTTP headers via ${cdnProvider} CDN`,
		'info',
		`HTTP security headers may be provided by ${cdnProvider} CDN rather than the origin server. CDN-applied headers do not reflect the origin server's security configuration.`,
		{ cdnProvider },
	);

	return { ...result, findings: [...result.findings, cdnFinding] };
}
