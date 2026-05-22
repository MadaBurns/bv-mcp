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
	// Azure CDN / Front Door deprovisioned endpoints surface ONE of two body
	// shapes depending on which LB instance answers:
	//   1. XML  — `<?xml ...?><Error><Code>ResourceNotFound</Code>...`
	//   2. HTML — generic 404 page whose body references the internal
	//             `df.onecloud.azure-test.net/Error/UE_404` redirect target and
	//             carries a `<title>Page not found</title>` element.
	// Probes against the same FQDN can hit either variant. Both patterns must
	// be present so the second variant doesn't silently drop the finding.
	{
		service: 'afd.azureedge.net',
		patterns: [
			'df.onecloud.azure-test.net/Error/UE_404',
			'<Code>ResourceNotFound</Code>',
			'<title>Page not found</title>',
			'ResourceNotFound',
		],
	},
	{
		service: 'azureedge.net',
		patterns: [
			'df.onecloud.azure-test.net/Error/UE_404',
			'<Code>ResourceNotFound</Code>',
			'<title>Page not found</title>',
			'ResourceNotFound',
			"Our services aren't available right now",
		],
	},
	{
		service: 'azurefd.net',
		patterns: [
			'df.onecloud.azure-test.net/Error/UE_404',
			'<Code>ResourceNotFound</Code>',
			'<title>Page not found</title>',
			"Our services aren't available right now",
		],
	},
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
 * Pattern → severity-impact classification for the CNAME target hostname.
 *
 * - `random`: the hostname embeds a provider-assigned ID (load-balancer ID,
 *   CloudFront distribution ID, API Gateway ID). The namespace label is not
 *   user-controlled and cannot be deterministically reclaimed by another
 *   tenant; the dangling-CNAME finding represents operational drift, not an
 *   active takeover vector.
 * - `claimable`: the hostname is in a known takeover-prone service AND its
 *   label is user-chosen (S3 buckets, AzureEdge endpoints, GitHub Pages
 *   sites, Heroku apps, etc.). A new tenant CAN claim this namespace label
 *   and serve content at the dangling subdomain.
 * - `unknown`: pattern not in either bucket — caller should treat as the
 *   conservative default (HIGH severity).
 */
export type TargetClaimability = 'random' | 'claimable' | 'unknown';

const RANDOM_TARGET_PATTERNS: RegExp[] = [
	// AWS ELB (classic + ALB + NLB): 32+ hex chars + dash + decimal random
	/^[a-f0-9]{32,}-\d+\.[a-z0-9-]+\.elb\.amazonaws\.com$/i,
	// CloudFront distribution ID: 12-14 lowercase alphanumeric, no dashes
	/^[a-z0-9]{12,14}\.cloudfront\.net$/i,
	// API Gateway ID: exactly 10 alphanumeric chars
	/^[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com$/i,
	// Azure Container Apps environment suffix:
	// <name>.<env-name>-<hex>.<region>.azurecontainerapps.io
	// The hex suffix on the env name is provider-assigned, even though the
	// leading <name> isn't.
	/^[a-z0-9-]+\.[a-z0-9-]+-[a-f0-9]{8}\.[a-z0-9-]+\.azurecontainerapps\.io$/i,
];

export function classifyTargetNamespace(cname: string): TargetClaimability {
	const normalized = cname.replace(/\.$/, '').toLowerCase();
	for (const re of RANDOM_TARGET_PATTERNS) {
		if (re.test(normalized)) return 'random';
	}
	if (isThirdPartyTakeoverService(normalized)) return 'claimable';
	return 'unknown';
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
	} catch (err) {
		// TLS-SNI / cert-altname mismatch IS a deprovision signal: a properly
		// provisioned endpoint serves a certificate whose SAN list includes the
		// hostname it's being addressed by. When fetch throws a cert-altname
		// error, the CNAME target is pointing at a cluster that has no
		// configured certificate for this FQDN — i.e. the upstream tenant has
		// been torn down. The exact error wording varies by runtime (workerd,
		// Node 18/20/22, undici), so we match a permissive union of phrases
		// that all describe the same condition.
		const message = err instanceof Error ? err.message : typeof err === 'string' ? err : '';
		if (isTlsCertAltnameMismatch(message)) {
			return TLS_SNI_MISMATCH_DISPLAY;
		}
		// Other transport errors (timeout, DNS, connect refused) are not
		// deprovision evidence — stay silent.
	}

	return null;
}

/**
 * Sentinel display name returned by {@link probeHttpFingerprint} when the
 * upstream cert doesn't cover the SNI hostname. Callers treat any non-null
 * string as a CRITICAL takeover finding; this label flags the underlying
 * signal type for the operator-visible finding text.
 */
export const TLS_SNI_MISMATCH_DISPLAY = 'TLS-SNI mismatch (deprovision signal)';

/**
 * Detect TLS cert SAN/altname mismatch error strings across runtimes:
 *   - Node/undici:    `Hostname/IP does not match certificate's altnames: ...`
 *   - Node code:      `ERR_TLS_CERT_ALTNAME_INVALID`
 *   - workerd:        `unable to verify ... no alternative certificate subject name matches`
 *   - OpenSSL-direct: `Hostname mismatch` / `certificate subject name does not match`
 *
 * Conservative union: only fire on phrases that uniquely describe a SAN/altname
 * mismatch. We deliberately do NOT match generic `certificate` strings (which
 * also appear in expired-cert / self-signed-cert errors that are not a clean
 * deprovision signal).
 */
export function isTlsCertAltnameMismatch(message: string): boolean {
	if (!message) return false;
	const lower = message.toLowerCase();
	return (
		lower.includes('altname') ||
		lower.includes('err_tls_cert_altname_invalid') ||
		lower.includes('certificate subject name') ||
		lower.includes('subject name matches') ||
		lower.includes('hostname mismatch') ||
		lower.includes("doesn't match the certificate") ||
		lower.includes('does not match the certificate')
	);
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
					const claimability = classifyTargetNamespace(cname);
					const isRandom = claimability === 'random';
					const severity: 'medium' | 'high' = isRandom ? 'medium' : 'high';
					const severityRationale = isRandom ? 'random_target_id' : 'claimable_target_name';
					const detail = isRandom
						? `Subdomain ${fqdn} points to ${cname}, which does not resolve. The target hostname embeds a provider-assigned random ID (load-balancer / distribution / API-gateway ID), so it is unlikely to be reclaimable by another tenant — this is operational drift rather than an active takeover vector. Verify whether the upstream resource should be re-created or the DNS pointer removed.`
						: `Subdomain ${fqdn} points to ${cname}, which does not resolve. This is a potential subdomain takeover vector and should be manually validated with authorized claim testing.`;
					findings.push(
						createFinding(
							'subdomain_takeover',
							isRandom ? `Dangling CNAME (operational drift): ${fqdn} → ${cname}` : `Dangling CNAME: ${fqdn} → ${cname}`,
							severity,
							detail,
							{
								verificationStatus: 'potential',
								evidence: ['cname_target_unresolved'],
								severityRationale,
							},
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
