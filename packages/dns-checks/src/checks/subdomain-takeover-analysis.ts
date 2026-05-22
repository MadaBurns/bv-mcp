// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain takeover analysis helpers.
 * Scanning logic for detecting dangling CNAMEs and takeover vectors.
 *
 * Two-layer detection:
 *   1. DNS-NXDOMAIN: CNAME present, target does not resolve.
 *   2. Provider-deprovisioned fingerprint: CNAME resolves but provider returns
 *      a well-known "resource gone" body (NoSuchBucket, BlobNotFound,
 *      ResourceNotFound, etc.) — meaning the underlying bucket/endpoint can
 *      be re-claimed by another tenant.
 *
 * Copyright (c) 2023-2026 BlackVeil Security Ltd.
 * Licensed under BSL 1.1
 */

import type { DNSQueryFunction, FetchFunction, Finding } from '../types';
import { createFinding } from '../check-utils';

export type TakeoverVerificationStatus = 'potential' | 'verified' | 'not_exploitable';

/** Default HTTPS timeout for fingerprint probing (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

export const KNOWN_SUBDOMAINS = [
	'www',
	'app',
	'api',
	'staging',
	'dev',
	'admin',
	'cdn',
	'static',
	'mail',
	'blog',
	'docs',
	'status',
	'portal',
	'login',
	'support',
];

/**
 * Provider patterns that warrant a takeover probe when a CNAME resolves to
 * them. Order matters only for `SERVICE_DISPLAY_NAMES` lookup. Patterns are
 * `String.prototype.includes()` substrings, normalised to lower-case on the
 * CNAME side.
 */
const TAKEOVER_SERVICES = [
	// AWS
	'cloudfront.net',
	's3-website',
	's3.amazonaws.com',
	'amazonaws.com',
	'elasticbeanstalk.com',
	// Azure — distinct services with distinct fingerprints
	'afd.azureedge.net',
	'azureedge.net',
	'azurefd.net',
	'azurewebsites.net',
	'blob.core.windows.net',
	'web.core.windows.net',
	'file.core.windows.net',
	'trafficmanager.net',
	'cloudapp.net',
	'cloudapp.azure.com',
	'azurecontainerapps.io',
	// GCP
	'storage.googleapis.com',
	'appspot.com',
	// Hosting platforms — DNS-claim or app-deprovision takeover surface
	'herokuapp.com',
	'herokudns.com',
	'github.io',
	'pages.dev',
	'fastly.net',
	'netlify.app',
	'netlify.com',
	'fly.dev',
	'zeit.co',
	'webflow.io',
	'firebaseapp.com',
	'web.app',
	'vercel.app',
	'vercel-dns.com',
	'now.sh',
	'render.com',
	'onrender.com',
	'myshopify.com',
	'zendesk.com',
	'pantheonsite.io',
	'squarespace.com',
	'sqsp.net',
	'ghost.io',
	'surge.sh',
	'wpengine.com',
	'wordpress.com',
	'tumblr.com',
	'readme.io',
	'hs-sites.com',
	'freshdesk.com',
	'bitbucket.io',
];

/**
 * Provider-specific "this endpoint has been deprovisioned" body fragments.
 * A match means the target is takeover-eligible. Substrings are matched
 * case-insensitively. Multiple patterns per service are allowed — first match
 * wins. **Order longer matches first** to disambiguate sibling services
 * (e.g. AFD vs Azure CDN).
 */
const TAKEOVER_FINGERPRINTS: { service: string; patterns: string[] }[] = [
	// AWS
	{ service: 'amazonaws.com', patterns: ['NoSuchBucket', 'The specified bucket does not exist'] },
	{ service: 'cloudfront.net', patterns: ['NoSuchBucket', "Bad request.\nWe can't connect"] },
	// Azure
	// Azure Front Door / CDN / Storage all surface `<Code>ResourceNotFound</Code>`
	// when the underlying endpoint is gone. `BlobNotFound` is Azure Blob
	// specifically. `ContainerNotFound` is Azure Blob container-level.
	{ service: 'afd.azureedge.net', patterns: ['<Code>ResourceNotFound</Code>', 'ResourceNotFound'] },
	{ service: 'azureedge.net', patterns: ['<Code>ResourceNotFound</Code>', 'ResourceNotFound', "Our services aren't available right now"] },
	{ service: 'azurefd.net', patterns: ["Our services aren't available right now", '<Code>ResourceNotFound</Code>'] },
	{
		service: 'azurewebsites.net',
		patterns: ['<title>404 Web Site not found</title>', '<title>Web App - Unavailable</title>', 'web-app-not-found.html'],
	},
	{
		service: 'blob.core.windows.net',
		patterns: [
			'<Code>BlobNotFound</Code>',
			'<Code>ContainerNotFound</Code>',
			'The specified blob does not exist',
			'The specified container does not exist',
		],
	},
	{ service: 'web.core.windows.net', patterns: ['<Code>ResourceNotFound</Code>', '<Code>ContainerNotFound</Code>'] },
	{ service: 'file.core.windows.net', patterns: ['<Code>ShareNotFound</Code>', 'The specified share does not exist'] },
	{ service: 'trafficmanager.net', patterns: ['No endpoint found for this Traffic Manager profile'] },
	{ service: 'cloudapp.net', patterns: ['This domain name has expired'] },
	// GCP
	{ service: 'storage.googleapis.com', patterns: ['<Code>NoSuchBucket</Code>', 'The specified bucket does not exist'] },
	// Hosting platforms
	{ service: 'github.io', patterns: ["There isn't a GitHub Pages site here", '<h2>404</h2>'] },
	{ service: 'herokuapp.com', patterns: ['no-such-app', 'No such app', "There's nothing here, yet"] },
	{ service: 'fastly.net', patterns: ['Fastly error: unknown domain', 'unknown domain'] },
	{ service: 'netlify.app', patterns: ['Not Found - Request ID', '<h1>Not Found</h1>'] },
	{ service: 'pantheonsite.io', patterns: ['The gods are displeased'] },
	{ service: 'tumblr.com', patterns: ["There's nothing here", 'Whatever you were looking for'] },
	{ service: 'ghost.io', patterns: ['The thing you were looking for is no longer here'] },
	{ service: 'myshopify.com', patterns: ['<title>Sorry, this shop is currently unavailable', 'Only one step left'] },
	{ service: 'bitbucket.io', patterns: ['Repository not found'] },
	{ service: 'firebaseapp.com', patterns: ['Site Not Found', 'project has been deleted'] },
	{ service: 'web.app', patterns: ['Site Not Found', 'project has been deleted'] },
	{ service: 'vercel.app', patterns: ['<title>404: NOT_FOUND</title>', 'DEPLOYMENT_NOT_FOUND'] },
	{ service: 'onrender.com', patterns: ['Not Found', 'has not been deployed'] },
	{ service: 'surge.sh', patterns: ['project not found'] },
	{ service: 'webflow.io', patterns: ['The page you are looking for doesn'] },
	{ service: 'pages.dev', patterns: ['Failed to load Cloudflare Pages content'] },
];

const SERVICE_DISPLAY_NAMES: Record<string, string> = {
	'cloudfront.net': 'AWS CloudFront',
	's3.amazonaws.com': 'AWS S3',
	'amazonaws.com': 'AWS S3',
	's3-website': 'AWS S3 (website endpoint)',
	'elasticbeanstalk.com': 'AWS Elastic Beanstalk',
	'afd.azureedge.net': 'Azure Front Door',
	'azureedge.net': 'Azure CDN',
	'azurefd.net': 'Azure Front Door',
	'azurewebsites.net': 'Azure App Service',
	'blob.core.windows.net': 'Azure Blob Storage',
	'web.core.windows.net': 'Azure Static Web',
	'file.core.windows.net': 'Azure Files',
	'trafficmanager.net': 'Azure Traffic Manager',
	'cloudapp.net': 'Azure Cloud Services',
	'cloudapp.azure.com': 'Azure Cloud Services',
	'azurecontainerapps.io': 'Azure Container Apps',
	'storage.googleapis.com': 'GCP Cloud Storage',
	'appspot.com': 'GCP App Engine',
	'herokuapp.com': 'Heroku',
	'herokudns.com': 'Heroku',
	'github.io': 'GitHub Pages',
	'pages.dev': 'Cloudflare Pages',
	'fastly.net': 'Fastly',
	'netlify.app': 'Netlify',
	'netlify.com': 'Netlify',
	'fly.dev': 'Fly.io',
	'webflow.io': 'Webflow',
	'firebaseapp.com': 'Firebase Hosting',
	'web.app': 'Firebase Hosting',
	'vercel.app': 'Vercel',
	'render.com': 'Render',
	'onrender.com': 'Render',
	'myshopify.com': 'Shopify',
	'pantheonsite.io': 'Pantheon',
	'tumblr.com': 'Tumblr',
	'ghost.io': 'Ghost',
	'surge.sh': 'Surge',
	'bitbucket.io': 'Bitbucket Pages',
};

export function createTakeoverFinding(
	title: string,
	severity: 'critical' | 'high' | 'info',
	detail: string,
	verificationStatus: TakeoverVerificationStatus,
	evidence: string[],
): Finding {
	return createFinding('subdomain_takeover', title, severity, detail, {
		verificationStatus,
		evidence,
	});
}

export function isThirdPartyTakeoverService(cname: string): boolean {
	return TAKEOVER_SERVICES.some((service) => cname.includes(service));
}

/**
 * Probe an HTTP endpoint for known takeover fingerprints.
 * Returns the matched display-name for the deprovisioned service, or null.
 *
 * The fingerprint dictionary is ordered with longest/most-specific patterns
 * first so AFD vs Azure CDN (both `*.azureedge.net`) disambiguate correctly
 * — AFD's `*.afd.azureedge.net` rule matches first.
 */
export async function probeHttpFingerprint(fqdn: string, cname: string, fetchFn: FetchFunction): Promise<string | null> {
	const matchingEntries = TAKEOVER_FINGERPRINTS.filter((entry) => cname.includes(entry.service));
	if (matchingEntries.length === 0) return null;

	try {
		const response = await fetchFn(`https://${fqdn}`, {
			redirect: 'manual',
			signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
		});
		// Skip fingerprint matching on redirects — redirecting services are not deprovisioned.
		if (response.status >= 300 && response.status < 400) return null;

		const MAX_BODY_BYTES = 65_536; // 64 KB — no legitimate takeover fingerprint exceeds this
		const contentLength = parseInt(response.headers?.get('content-length') ?? '0', 10);
		if (contentLength > MAX_BODY_BYTES) return null;
		const body = await response.text();
		if (body.length > MAX_BODY_BYTES) return null;

		const lowerBody = body.toLowerCase();
		for (const { service, patterns } of matchingEntries) {
			for (const pattern of patterns) {
				if (lowerBody.includes(pattern.toLowerCase())) {
					return SERVICE_DISPLAY_NAMES[service] ?? service;
				}
			}
		}
	} catch {
		// Timeout or network error — silently skip.
	}

	return null;
}

export async function scanSubdomainForTakeover(
	domain: string,
	subdomain: string,
	queryDNS: DNSQueryFunction,
	fetchFn: FetchFunction,
	timeout?: number,
): Promise<Finding[]> {
	// Allow subdomain to be a full FQDN (caller passes from CT enumeration) OR a
	// short label that we append to the apex (legacy KNOWN_SUBDOMAINS path).
	const fqdn = subdomain.includes('.') ? subdomain.replace(/^\*\./, '') : `${subdomain}.${domain}`;
	const findings: Finding[] = [];

	try {
		const cnameRecords = await queryDNS(fqdn, 'CNAME', { timeout });
		for (const rawCname of cnameRecords) {
			const cname = rawCname
				.replace(/\.$/, '')
				.replace(/[\x00-\x1F\x7F]/g, '')
				.toLowerCase();
			if (!isThirdPartyTakeoverService(cname)) continue;

			try {
				const targetAddresses = await queryDNS(cname, 'A', { timeout });
				if (targetAddresses.length === 0) {
					findings.push(
						createTakeoverFinding(
							`Dangling CNAME: ${fqdn} → ${cname}`,
							'high',
							`Subdomain ${fqdn} points to ${cname}, which does not resolve. This is a potential subdomain takeover vector and should be manually validated with authorized claim testing.`,
							'potential',
							['cname_target_unresolved'],
						),
					);
					continue;
				}

				const vulnerableService = await probeHttpFingerprint(fqdn, cname, fetchFn);
				if (vulnerableService) {
					findings.push(
						createTakeoverFinding(
							`Subdomain vulnerable to takeover (${vulnerableService})`,
							'critical',
							`Subdomain ${fqdn} points to ${cname}, which resolves but returns a ${vulnerableService} deprovisioned fingerprint. This is a verified takeover signal and should be confirmed with authorized proof-of-control testing.`,
							'verified',
							['cname_resolves', 'provider_deprovisioned_fingerprint'],
						),
					);
				}
			} catch {
				findings.push(
					createTakeoverFinding(
						`CNAME resolution failed: ${fqdn} → ${cname}`,
						'high',
						`Could not resolve CNAME target ${cname} for ${fqdn}. This is a potential takeover signal and requires manual verification.`,
						'potential',
						['cname_target_resolution_error'],
					),
				);
			}
		}
	} catch {
		// No CNAME or query failed; not critical.
	}

	return findings;
}

export function getNoTakeoverFinding(domain: string): Finding {
	return createTakeoverFinding(
		'No dangling CNAME records found',
		'info',
		`No subdomain takeover vectors detected for ${domain} among known/active subdomains.`,
		'not_exploitable',
		['no_takeover_signals_detected'],
	);
}
