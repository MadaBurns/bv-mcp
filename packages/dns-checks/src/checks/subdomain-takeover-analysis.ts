// SPDX-License-Identifier: BUSL-1.1

/**
 * Subdomain takeover analysis helpers.
 * Scanning logic for detecting dangling CNAMEs and takeover vectors.
 *
 * Two-layer detection:
 *   1. DNS-NXDOMAIN: CNAME present, target does not resolve.
 *   2. Provider-deprovisioned fingerprint: CNAME resolves but provider returns
 *      a well-known "resource gone" body (NoSuchBucket, BlobNotFound,
 *      ResourceNotFound, etc.). This is strong dangling-service evidence, but
 *      exploitability still requires authorized provider-specific proof of
 *      control before reporting a confirmed takeover.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { DNSQueryFunction, FetchFunction, Finding } from '../types';
import { readResponseTextCapped } from '../response-body';
import { createFinding } from '../check-utils';

/**
 * `verified` is reserved for authorized proof-of-control or equivalent
 * explicit control evidence. Provider 404/body/TLS fingerprints are evidence
 * of a dangling service, not proof that another tenant can claim traffic.
 */
export type TakeoverVerificationStatus = 'potential' | 'verified' | 'not_exploitable';

/** Default HTTPS timeout for fingerprint probing (ms) */
const HTTPS_TIMEOUT_MS = 4_000;

/** Cloudflare edge statuses for an origin TLS failure: 525 handshake failed, 526 invalid certificate. */
const EDGE_TLS_FAILURE_STATUSES = new Set([525, 526]);

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

/**
 * Provider fingerprints for the A/AAAA-only takeover vector (#973): a host with
 * NO CNAME whose A/AAAA record points at shared hosting that has not been
 * claimed for this hostname. Unlike {@link TAKEOVER_FINGERPRINTS}, there is no
 * CNAME target hostname to gate the match on — the response body IS the only
 * signal, so this list is probed for every swept subdomain that resolves via
 * A/AAAA with no CNAME. Keep this list to verbatim-evidenced providers only.
 */
const A_RECORD_UNCLAIMED_FINGERPRINTS: { service: string; patterns: string[] }[] = [
	// Cloudways: verbatim text from the provider's "unmapped domain" block page
	// (issue #973). Shared IP, no CNAME — the domain resolves straight to the
	// platform's edge, which serves this page for any hostname it doesn't have
	// an application mapped to.
	{
		service: 'cloudways',
		patterns: [
			'the requested domain is not authorized on cloudways server',
			'the domain has been successfully pointed to a cloudways server but it is not mapped to an application',
			// Live-miss reopen (#973, 2026-09-15): some Cloudways edges answer the
			// unmapped-domain block page as a bare 403 whose ENTIRE body is an
			// `<iframe>` pointing at this S3-hosted maintenance page — the
			// unmapped-domain wording above lives only inside that iframe
			// document, which this check does not fetch. The iframe `src` marker
			// itself, present verbatim in the origin's own 403 body, is the
			// evidence; do not fetch the iframe URL to look for the text.
			'cloudways-static-content.s3.us-east-1.amazonaws.com/error_page/maintenance-domain-mapping.html',
		],
	},
];

const SERVICE_DISPLAY_NAMES: Record<string, string> = {
	cloudways: 'Cloudways',
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
	metadata: Record<string, unknown> = {},
): Finding {
	return createFinding('subdomain_takeover', title, severity, detail, {
		verificationStatus,
		evidence,
		...metadata,
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
	return matchFingerprintOverHttp(fqdn, matchingEntries, fetchFn);
}

/**
 * Probe an A/AAAA-only host (no CNAME) for the shared-hosting "unclaimed
 * domain" fingerprints in {@link A_RECORD_UNCLAIMED_FINGERPRINTS} (#973).
 * There is no CNAME target to gate the match on, so every entry is checked
 * unconditionally — the list is deliberately small and verbatim-evidenced.
 *
 * Falls back to a plain `http://` attempt when the `https://` leg fails
 * outright (live-miss reopen, #973 2026-09-15): some Cloudways edges refuse
 * the TLS handshake entirely for an unmapped domain but still answer plain
 * HTTP with the unmapped-domain fingerprint page. An HTTPS failure followed
 * by an HTTP match is a finding; both legs failing stays the existing silent
 * abstention. The CNAME vector ({@link probeHttpFingerprint}) does not get
 * this fallback — its targets are known third-party HTTPS-serving platforms,
 * not the bare-A-record case this vector exists for.
 */
export async function probeARecordUnclaimedFingerprint(fqdn: string, fetchFn: FetchFunction): Promise<string | null> {
	return matchFingerprintOverHttp(fqdn, A_RECORD_UNCLAIMED_FINGERPRINTS, fetchFn, { httpFallbackOnFailure: true });
}

/**
 * Shared fetch-and-match core for both {@link probeHttpFingerprint} (CNAME
 * vector) and {@link probeARecordUnclaimedFingerprint} (A/AAAA vector, #973).
 * Returns the matched display-name, or null when nothing matched or the fetch
 * was inconclusive (redirect, transport error other than a TLS-SNI mismatch).
 */
async function matchFingerprintOverHttp(
	fqdn: string,
	matchingEntries: { service: string; patterns: string[] }[],
	fetchFn: FetchFunction,
	options?: { httpFallbackOnFailure?: boolean },
): Promise<string | null> {
	if (matchingEntries.length === 0) return null;

	try {
		return await fetchAndMatchFingerprint(`https://${fqdn}`, matchingEntries, fetchFn);
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
		// Other transport errors (timeout, DNS, connect refused, or a TLS
		// handshake failure that never produced a distinguishable altname
		// message) are not deprovision evidence on their own. Without an HTTP
		// fallback, stay silent exactly as before.
		if (!options?.httpFallbackOnFailure) {
			return null;
		}
	}

	// The https:// leg failed with a non-SNI-mismatch error and the caller opted
	// into the #973 HTTP fallback. Same fetchFn (unchanged SSRF posture), same
	// timeout budget, same fingerprint patterns — only the scheme differs.
	try {
		return await fetchAndMatchFingerprint(`http://${fqdn}`, matchingEntries, fetchFn);
	} catch {
		// Both legs failed — stay silent, the existing abstention.
		return null;
	}
}

/**
 * Fetch one URL and check its body against `matchingEntries`. Returns the
 * matched display-name, or null when the fetch completed but nothing
 * matched (including a skipped redirect). Throws on transport failure —
 * callers decide what a thrown fetch means (TLS-SNI signal, HTTP fallback,
 * or silent abstention).
 */
async function fetchAndMatchFingerprint(
	url: string,
	matchingEntries: { service: string; patterns: string[] }[],
	fetchFn: FetchFunction,
): Promise<string | null> {
	const response = await fetchFn(url, {
		redirect: 'manual',
		signal: AbortSignal.timeout(HTTPS_TIMEOUT_MS),
	});
	// #973 live miss (3.81.1): on the Cloudflare edge an origin TLS failure does NOT reject
	// the fetch the way local workerd/Node do — the edge answers with a synthetic 525 (SSL
	// handshake failed) or 526 (invalid SSL certificate) Response. Read as a completed leg,
	// that page matched nothing and the #973 HTTP fallback never ran. Throw instead, so
	// every caller sees exactly what a rejected https leg already means to it.
	if (url.startsWith('https://') && EDGE_TLS_FAILURE_STATUSES.has(response.status)) {
		void response.body?.cancel().catch(() => undefined);
		throw new Error(`HTTPS origin TLS failure (edge status ${response.status})`);
	}
	// Skip fingerprint matching on redirects — redirecting services are not deprovisioned.
	// Release the unread body so workerd doesn't cancel a stalled response.
	if (response.status >= 300 && response.status < 400) {
		void response.body?.cancel().catch(() => undefined);
		return null;
	}

	const MAX_BODY_BYTES = 65_536; // 64 KB — no legitimate takeover fingerprint exceeds this
	const body = await readResponseTextCapped(response, MAX_BODY_BYTES);
	if (body === null) return null;

	const lowerBody = body.toLowerCase();
	for (const { service, patterns } of matchingEntries) {
		for (const pattern of patterns) {
			if (lowerBody.includes(pattern.toLowerCase())) {
				return SERVICE_DISPLAY_NAMES[service] ?? service;
			}
		}
	}

	return null;
}

/**
 * Sentinel display name returned by {@link probeHttpFingerprint} when the
 * upstream cert doesn't cover the SNI hostname. Callers treat any non-null
 * string as provider deprovision evidence; this label flags the underlying
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

/** One swept subdomain's findings plus whether its CNAME probe actually answered (#948). */
export interface SubdomainScanOutcome {
	findings: Finding[];
	/**
	 * True when the outer `queryDNS(fqdn, 'CNAME')` threw, i.e. this subdomain was never
	 * measured. An empty `findings` array on its own cannot distinguish "measured, nothing
	 * dangling" from "the query failed", and conflating the two let a total resolver
	 * outage produce the clean "No dangling CNAME records found" verdict at score 100.
	 */
	cnameQueryFailed: boolean;
	/**
	 * True when a third-party CNAME target's A query threw, i.e. the takeover question for
	 * this subdomain was never answered (#983). The CNAME leg answered, so
	 * `cnameQueryFailed` is false and the older #948 counter would have called the subdomain
	 * measured — but knowing a subdomain points at a takeover-prone service says nothing
	 * about whether that service still holds the name. The caller folds this into the same
	 * unmeasured set so a sweep where nothing resolved abstains instead of scoring.
	 */
	targetResolutionFailed: boolean;
}

/**
 * The real sweep. Returns measurement provenance alongside the findings.
 *
 * This is the additive shape; `scanSubdomainForTakeover` below stays as a thin `Finding[]`
 * wrapper. See that function's note for the (measured) reason — it is NOT the public-API
 * argument an earlier draft of this comment made.
 *
 * @param checkARecordVector - Whether to run the #973 A/AAAA-only takeover vector for
 * this subdomain (defaults to true — every direct caller keeps the full check). The
 * `scan_domain` orchestration caps how many swept subdomains carry this leg, to stay
 * inside its shared DNS-query ceiling (see `aRecordVectorSampleCap` on the package's
 * `checkSubdomainTakeover`); the CNAME leg above is unaffected either way.
 */
export async function scanSubdomainForTakeoverInternal(
	domain: string,
	subdomain: string,
	queryDNS: DNSQueryFunction,
	fetchFn: FetchFunction,
	timeout?: number,
	checkARecordVector = true,
): Promise<SubdomainScanOutcome> {
	// Allow subdomain to be a full FQDN (caller passes from CT enumeration) OR a
	// short label that we append to the apex (legacy KNOWN_SUBDOMAINS path).
	const fqdn = subdomain.includes('.') ? subdomain.replace(/^\*\./, '') : `${subdomain}.${domain}`;
	const findings: Finding[] = [];
	let targetResolutionFailed = false;

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
							`Subdomain possible takeover signal (${vulnerableService})`,
							'high',
							`Subdomain ${fqdn} points to ${cname}, which resolves but returns a ${vulnerableService} deprovisioned fingerprint. This is strong provider evidence of a dangling service, but it is not proof of exploitability. Confirm with authorized proof-of-control testing before reporting a confirmed takeover.`,
							'potential',
							['cname_resolves', 'provider_deprovisioned_fingerprint'],
							{
								evidenceStrength: 'provider_deprovisioned_fingerprint',
								proofRequired: 'authorized_proof_of_control',
								severityRationale: 'provider_deprovisioned_signal',
							},
						),
					);
				}
			} catch {
				// #983 — the TARGET query threw, so this subdomain was not assessed.
				//
				// This used to emit a scored `high` reading "a potential takeover signal".
				// It is not: a thrown query is the transport-failure class #948 already
				// abstains for, and `subdomain_takeover` is in PROFILE_CRITICAL_CATEGORIES
				// for all six profiles, so a resolver blip on one A query took a critical
				// category down on evidence that was never collected. Knowing the CNAME
				// points at a takeover-prone service is not knowing whether the service
				// still holds the name — the only thing that distinguishes a dangling
				// record from a healthy one is the target's own resolution, which is
				// exactly what failed.
				//
				// The finding is kept as a visible `info` disclosure (an operator still
				// wants to see which target could not be checked) carrying `inconclusive`
				// + `errorKind`, and deliberately NOT `missingControl` — nothing was
				// measured, so nothing can be claimed absent (#638 law). The TITLE is
				// unchanged on purpose: `parseTakeoverTarget` in
				// `src/lib/brand-audit-registrar-deepscan.ts` recovers the FQDN from it.
				// That consumer skips `info` findings, which is the correct new behaviour —
				// an unresolvable probe does not belong in a dangling-DNS inventory.
				targetResolutionFailed = true;
				findings.push(
					createTakeoverFinding(
						`CNAME resolution failed: ${fqdn} → ${cname}`,
						'info',
						`Could not resolve CNAME target ${cname} for ${fqdn}: the lookup failed rather than returning an answer. This subdomain was NOT assessed for takeover — it is neither confirmed dangling nor confirmed healthy, and it is excluded from the verdict rather than penalized. Re-run the check once name resolution is working.`,
						'potential',
						['cname_target_resolution_error'],
						{ inconclusive: true, errorKind: 'dns_error' },
					),
				);
			}
		}

		// #973 — A/AAAA-only vector: no CNAME at all, so `isThirdPartyTakeoverService`
		// (which matches CNAME target hostnames) cannot gate this the way it gates the
		// loop above. A host wired straight to shared PaaS by A/AAAA record is invisible
		// to the CNAME model even when the platform openly reports the domain as
		// unclaimed (Cloudways' "not mapped to an application" page). Probe the body
		// directly whenever the subdomain resolves via A/AAAA with no CNAME present —
		// this reuses the same already-enumerated subdomain list and the same per-check
		// fetch budget, it does not add a new enumeration source.
		//
		// `checkARecordVector` gates the whole leg (both queries below): `scan_domain`
		// only sets it false past its sample cap, to stay inside the shared DNS-query
		// ceiling (test/hot-path-concurrency.perf.spec.ts). A skipped host is neither
		// measured nor unmeasured for this vector — it was simply not sampled, which the
		// caller discloses in the all-clear finding rather than reporting as a failure.
		if (cnameRecords.length === 0 && checkARecordVector) {
			try {
				// AAAA is queried only when A comes back empty: an A answer alone already
				// proves the host resolves via this vector, so a second query would just
				// spend DNS-query budget confirming what is already known. This halves the
				// common-case cost of the leg without changing what it can detect.
				const aRecords = await queryDNS(fqdn, 'A', { timeout });
				const aaaaRecords = aRecords.length > 0 ? [] : await queryDNS(fqdn, 'AAAA', { timeout });
				if (aRecords.length > 0 || aaaaRecords.length > 0) {
					const vulnerableService = await probeARecordUnclaimedFingerprint(fqdn, fetchFn);
					if (vulnerableService) {
						findings.push(
							createTakeoverFinding(
								`Subdomain possible takeover signal (${vulnerableService})`,
								'high',
								`Subdomain ${fqdn} has no CNAME but resolves via A/AAAA record to shared hosting that returns a ${vulnerableService} unclaimed-domain fingerprint. This is strong provider evidence that the hostname is not mapped to any application on that platform, but it is not proof of exploitability. Confirm with authorized proof-of-control testing before reporting a confirmed takeover.`,
								'potential',
								['a_record_resolves', 'provider_unclaimed_domain_fingerprint'],
								{
									evidenceStrength: 'provider_deprovisioned_fingerprint',
									proofRequired: 'authorized_proof_of_control',
									severityRationale: 'provider_deprovisioned_signal',
									vector: 'a_record',
								},
							),
						);
					}
				}
			} catch {
				// The A/AAAA query itself threw — this subdomain's A-record vector was not
				// assessed. Mirrors the CNAME-target-failed handling above: disclose as an
				// `info` abstention carrying `inconclusive` + `errorKind`, never a scored
				// finding and never `missingControl` (#638 law) — nothing was measured.
				targetResolutionFailed = true;
				findings.push(
					createTakeoverFinding(
						`A/AAAA resolution failed: ${fqdn}`,
						'info',
						`Could not resolve A/AAAA records for ${fqdn}: the lookup failed rather than returning an answer. This subdomain was NOT assessed for the A-record takeover vector — it is neither confirmed dangling nor confirmed healthy, and it is excluded from the verdict rather than penalized. Re-run the check once name resolution is working.`,
						'potential',
						['a_record_resolution_error'],
						{ inconclusive: true, errorKind: 'dns_error' },
					),
				);
			}
		}
	} catch {
		// The CNAME query itself failed — this subdomain was NOT measured. Nothing is
		// pushed (a failed lookup is not evidence of a dangling record), but the caller
		// is told, so it can abstain rather than issue a clean verdict for a sweep that
		// never happened (#948).
		return { findings, cnameQueryFailed: true, targetResolutionFailed };
	}

	return { findings, cnameQueryFailed: false, targetResolutionFailed };
}

/**
 * Wrapper preserving the pre-#948 `Finding[]` signature.
 *
 * ⚠️ CORRECTION (#948 review): an earlier version of this comment claimed the name is
 * barrel-exported and part of the published surface that bv-web-prod compiles against.
 * That is FALSE, and it was checked: `scanSubdomainForTakeover` is NOT re-exported from
 * `packages/dns-checks/src/index.ts`, and the manifest's `exports` map offers only `.`,
 * `./scoring`, `./whois` and `./cert` — no subpath reaches this module. Changing its
 * signature could not break a downstream tarball consumer, because none can import it.
 * (The fleet rule this violated: verify a vendored package's `exports`, never assume from
 * the filename.)
 *
 * The wrapper is kept anyway, for a smaller and honest reason: eight call sites in
 * `test/subdomain-takeover-analysis.spec.ts` use this signature, and churning them to
 * destructure `.findings` would add diff noise to a scoring fix without buying anything.
 * In-package callers that need the measurement provenance use
 * `scanSubdomainForTakeoverInternal`.
 *
 * If a future change wants this name gone, deleting it is safe — just update those tests.
 */
export async function scanSubdomainForTakeover(
	domain: string,
	subdomain: string,
	queryDNS: DNSQueryFunction,
	fetchFn: FetchFunction,
	timeout?: number,
): Promise<Finding[]> {
	const { findings } = await scanSubdomainForTakeoverInternal(domain, subdomain, queryDNS, fetchFn, timeout);
	return findings;
}

/**
 * @param options.aRecordVectorSampled - True when the #973 A/AAAA vector was only
 * checked on a capped subset of the swept subdomains (the `scan_domain` orchestration,
 * to stay inside its shared DNS-query ceiling), not on all of them. Changes the detail
 * text from a coverage claim to a sampling disclosure — the CNAME vector is always
 * swept in full regardless.
 */
export function getNoTakeoverFinding(domain: string, options?: { aRecordVectorSampled?: boolean }): Finding {
	const aRecordCoverage = options?.aRecordVectorSampled
		? 'checked on a sampled subset of them'
		: 'checked on every one of them';
	return createTakeoverFinding(
		'No dangling CNAME records found',
		'info',
		// #973: this must not read as "no takeover exposure" — it is a claim about the
		// specific vectors this check models, not every way a subdomain can be hijacked.
		// State the coverage rather than the absence: dangling CNAMEs against a known
		// third-party service list, plus the Cloudways unmapped-domain HTTP fingerprint
		// on A/AAAA-only hosts (or a disclosed sample of them, see `aRecordVectorSampled`).
		`No dangling CNAME records or unclaimed shared-hosting A/AAAA records were found for ${domain} among the known/active subdomains swept by this check. Coverage is limited to CNAME targets on a known third-party service list, checked on every swept subdomain, and the Cloudways unmapped-domain HTTP fingerprint on A/AAAA-only hosts, ${aRecordCoverage}; other takeover vectors are not modelled.`,
		'not_exploitable',
		['no_takeover_signals_detected'],
	);
}
