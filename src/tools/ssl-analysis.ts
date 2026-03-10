// SPDX-License-Identifier: MIT

import { type Finding, createFinding } from '../lib/scoring';

export function getHttpsFindings(domain: string, responseUrl: string | undefined, hstsHeader: string | null): Finding[] {
	const findings: Finding[] = [];

	if (responseUrl && responseUrl.startsWith('http://')) {
		findings.push(
			createFinding(
				'ssl',
				'HTTPS redirects to HTTP',
				'critical',
				`${domain} redirects HTTPS requests to HTTP, exposing traffic to interception.`,
			),
		);
	}

	if (!hstsHeader) {
		findings.push(
			createFinding(
				'ssl',
				'No HSTS header',
				'medium',
				`${domain} does not set a Strict-Transport-Security header. HSTS prevents browsers from connecting over plain HTTP.`,
			),
		);
		return findings;
	}

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

	if (!/includeSubDomains/i.test(hstsHeader)) {
		findings.push(
			createFinding(
				'ssl',
				'HSTS missing includeSubDomains',
				'low',
				'HSTS header does not include the includeSubDomains directive. Subdomains are not protected by HSTS.',
			),
		);
	}

	return findings;
}

export function getHttpsErrorFinding(domain: string, message: string): Finding {
	if (message.includes('timeout') || message.includes('abort')) {
		return createFinding(
			'ssl',
			'HTTPS connection timeout',
			'high',
			`Could not establish HTTPS connection to ${domain} within 10 seconds. The server may not support HTTPS.`,
		);
	}

	return createFinding(
		'ssl',
		'HTTPS connection failed',
		'critical',
		`Failed to connect to ${domain} over HTTPS: ${message}. The domain may not have a valid SSL certificate.`,
	);
}

export function getHttpRedirectFindings(domain: string, status: number, location: string | null): Finding[] {
	if (status >= 300 && status < 400 && location?.startsWith('https://')) {
		return [];
	}

	if (status >= 300 && status < 400 && location && !location.startsWith('https://')) {
		return [
			createFinding(
				'ssl',
				'HTTP does not redirect to HTTPS',
				'medium',
				`HTTP requests to ${domain} redirect to ${location} instead of HTTPS.`,
			),
		];
	}

	return [
		createFinding(
			'ssl',
			'No HTTP to HTTPS redirect',
			'medium',
			`HTTP requests to ${domain} are not redirected to HTTPS (status ${status}).`,
		),
	];
}