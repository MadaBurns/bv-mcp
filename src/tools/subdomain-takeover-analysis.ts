// SPDX-License-Identifier: MIT

import { queryDnsRecords } from '../lib/dns';
import type { QueryDnsOptions } from '../lib/dns-types';
import { type Finding, createFinding } from '../lib/scoring';

export type TakeoverVerificationStatus = 'potential' | 'verified' | 'not_exploitable';

export const KNOWN_SUBDOMAINS = [
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

const SERVICE_DISPLAY_NAMES: Record<string, string> = {
	'github.io': 'GitHub Pages',
	'amazonaws.com': 'AWS S3',
	'cloudfront.net': 'AWS S3',
	'fastly.net': 'Fastly',
	'netlify.app': 'Netlify',
	'pantheonsite.io': 'Pantheon',
	'tumblr.com': 'Tumblr',
	'ghost.io': 'Ghost',
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
 * Returns the matched service name or null if no fingerprint matched.
 */
export async function probeHttpFingerprint(fqdn: string, cname: string): Promise<string | null> {
	const matchingEntries = Object.entries(TAKEOVER_FINGERPRINTS).filter(([service]) => cname.includes(service));
	if (matchingEntries.length === 0) return null;

	try {
		const response = await fetch(`https://${fqdn}`, {
			redirect: 'follow',
			signal: AbortSignal.timeout(5000),
		});
		const body = await response.text();

		for (const [service, fingerprint] of matchingEntries) {
			if (service === 'herokuapp.com') {
				if (body.includes('no-such-app') || body.includes('No such app')) {
					return 'Heroku';
				}
			} else if (body.includes(fingerprint)) {
				return SERVICE_DISPLAY_NAMES[service] ?? service;
			}
		}
	} catch {
		// Timeout or network error — silently skip.
	}

	return null;
}

export async function scanSubdomainForTakeover(domain: string, subdomain: string, dnsOptions?: QueryDnsOptions): Promise<Finding[]> {
	const fqdn = `${subdomain}.${domain}`;
	const findings: Finding[] = [];

	try {
		const cnameRecords = await queryDnsRecords(fqdn, 'CNAME', dnsOptions);
		for (const rawCname of cnameRecords) {
			const cname = rawCname.replace(/\.$/, '').toLowerCase();
			if (!isThirdPartyTakeoverService(cname)) continue;

			try {
				const targetAddresses = await queryDnsRecords(cname, 'A', dnsOptions);
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

				const vulnerableService = await probeHttpFingerprint(fqdn, cname);
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