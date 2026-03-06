/**
 * Subdomain Takeover / Dangling CNAME Detection Tool
 * Scans known/active subdomains for orphaned CNAME records pointing to deleted/unresolved third-party services.
 */

import { queryDnsRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding } from '../lib/scoring';

type TakeoverVerificationStatus = 'potential' | 'verified' | 'not_exploitable';

// List of known/active subdomains to check (can be expanded or made configurable)
const KNOWN_SUBDOMAINS = [
	'staging',
	'www',
	'app',
	'api',
	'portal',
	'admin',
	'login',
	'auth',
	'dev',
	'test',
	'beta',
	'demo',
	'preview',
	'status',
	'docs',
	'blog',
	'shop',
	'store',
	'support',
	'cdn',
	'static',
	'assets',
	'media',
	'mail',
	'webmail',
	'vpn',
	'ci',
	'git',
];

// List of third-party services commonly targeted for takeover
const TAKEOVER_SERVICES = [
	'cloudfront.net',
	'herokuapp.com',
	'azurewebsites.net',
	'amazonaws.com',
	'github.io',
	'pages.dev',
	'fastly.net',
	'netlify.app',
	'fly.dev',
	'zeit.co',
	'webflow.io',
	'firebaseapp.com',
	'vercel.app',
	'vercel-dns.com',
	'now.sh',
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

/** HTTP response body fingerprints indicating a service has been deprovisioned (takeover possible) */
const TAKEOVER_FINGERPRINTS: Record<string, string> = {
	'github.io': "There isn't a GitHub Pages site here",
	'herokuapp.com': 'no-such-app',
	'amazonaws.com': 'NoSuchBucket',
	'cloudfront.net': 'NoSuchBucket',
	'fastly.net': 'Fastly error: unknown domain',
	'netlify.app': 'Not Found - Request ID',
	'pantheonsite.io': 'The gods are displeased',
	'tumblr.com': "There's nothing here",
	'ghost.io': 'The thing you were looking for is no longer here',
};

/**
 * Probe an HTTP endpoint for known takeover fingerprints.
 * Returns the matched service name or null if no fingerprint matched.
 */
async function probeHttpFingerprint(fqdn: string, cname: string): Promise<string | null> {
	// Determine which service fingerprint(s) to check
	const matchingEntries = Object.entries(TAKEOVER_FINGERPRINTS).filter(([svc]) => cname.includes(svc));
	if (matchingEntries.length === 0) return null;

	try {
		const resp = await fetch(`https://${fqdn}`, {
			redirect: 'follow',
			signal: AbortSignal.timeout(5000),
		});
		const body = await resp.text();

		for (const [service, fingerprint] of matchingEntries) {
			// Heroku has two variants
			if (service === 'herokuapp.com') {
				if (body.includes('no-such-app') || body.includes('No such app')) {
					return 'Heroku';
				}
			} else if (body.includes(fingerprint)) {
				// Map service domain to display name
				const serviceNames: Record<string, string> = {
					'github.io': 'GitHub Pages',
					'amazonaws.com': 'AWS S3',
					'cloudfront.net': 'AWS S3',
					'fastly.net': 'Fastly',
					'netlify.app': 'Netlify',
					'pantheonsite.io': 'Pantheon',
					'tumblr.com': 'Tumblr',
					'ghost.io': 'Ghost',
				};
				return serviceNames[service] ?? service;
			}
		}
	} catch {
		// Timeout or network error — silently skip
	}

	return null;
}

/**
 * Check for dangling CNAME records on known/active subdomains.
 * Flags orphaned records and potential takeover vectors.
 */
export async function checkSubdomainTakeover(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	const createTakeoverFinding = (
		title: string,
		severity: 'critical' | 'high' | 'info',
		detail: string,
		verificationStatus: TakeoverVerificationStatus,
		evidence: string[],
	): Finding =>
		createFinding('subdomain_takeover', title, severity, detail, {
			verificationStatus,
			evidence,
		});

	const findingsPerSubdomain = await Promise.all(
		KNOWN_SUBDOMAINS.map(async (sub): Promise<Finding[]> => {
			const fqdn = `${sub}.${domain}`;
			const subdomainFindings: Finding[] = [];

			try {
				const cnameRecords = await queryDnsRecords(fqdn, 'CNAME');
				for (const rawCname of cnameRecords) {
					const cname = rawCname.replace(/\.$/, '').toLowerCase();
					const isThirdParty = TAKEOVER_SERVICES.some((svc) => cname.includes(svc));
					if (!isThirdParty) continue;

					// Resolve candidate targets in parallel with other subdomains to avoid serial latency buildup.
					try {
						const targetA = await queryDnsRecords(cname, 'A');
						if (targetA.length === 0) {
							subdomainFindings.push(
								createTakeoverFinding(
									`Dangling CNAME: ${fqdn} → ${cname}`,
									'critical',
									`Subdomain ${fqdn} points to ${cname}, which does not resolve. This is a potential subdomain takeover vector and should be manually validated with authorized claim testing.`,
									'potential',
									['cname_target_unresolved'],
								),
							);
						} else {
							// CNAME resolves, but check HTTP fingerprints for deprovisioned services
							const vulnerableService = await probeHttpFingerprint(fqdn, cname);
							if (vulnerableService) {
								subdomainFindings.push(
									createTakeoverFinding(
										`Subdomain vulnerable to takeover (${vulnerableService})`,
										'critical',
										`Subdomain ${fqdn} points to ${cname}, which resolves but returns a ${vulnerableService} deprovisioned fingerprint. This is a verified takeover signal and should be confirmed with authorized proof-of-control testing.`,
										'verified',
										['cname_resolves', 'provider_deprovisioned_fingerprint'],
									),
								);
							}
						}
					} catch {
						subdomainFindings.push(
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

			return subdomainFindings;
		}),
	);

	for (const subdomainFindings of findingsPerSubdomain) {
		findings.push(...subdomainFindings);
	}

	if (findings.length === 0) {
		findings.push(
			createTakeoverFinding(
				'No dangling CNAME records found',
				'info',
				`No subdomain takeover vectors detected for ${domain} among known/active subdomains.`,
				'not_exploitable',
				['no_takeover_signals_detected'],
			),
		);
	}

	return buildCheckResult('subdomain_takeover', findings);
}
