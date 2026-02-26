/**
 * Subdomain Takeover / Dangling CNAME Detection Tool
 * Scans known/active subdomains for orphaned CNAME records pointing to deleted/unresolved third-party services.
 */

import { queryDnsRecords } from '../lib/dns';
import { type CheckResult, type Finding, buildCheckResult, createFinding, type CheckCategory } from '../lib/scoring';

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
];

/**
 * Check for dangling CNAME records on known/active subdomains.
 * Flags orphaned records and potential takeover vectors.
 */
export async function checkSubdomainTakeover(domain: string): Promise<CheckResult> {
	const findings: Finding[] = [];

	   for (const sub of KNOWN_SUBDOMAINS) {
		   const fqdn = `${sub}.${domain}`;
		   try {
			   const cnameRecords = await queryDnsRecords(fqdn, 'CNAME');
			   for (const cname of cnameRecords) {
				   const lowerCname = cname.toLowerCase();
				   const isThirdParty = TAKEOVER_SERVICES.some((svc) => lowerCname.includes(svc));
				   if (isThirdParty) {
					   // Check if the CNAME target resolves
					   try {
						   const targetA = await queryDnsRecords(cname, 'A');
						   if (targetA.length === 0) {
							   findings.push(
								   createFinding(
									   'subdomain_takeover' as CheckCategory,
									   `Dangling CNAME: ${fqdn} → ${cname}`,
									   'critical',
									   `Subdomain ${fqdn} points to ${cname}, which does not resolve. This is a potential subdomain takeover vector.`,
								   ),
							   );
						   }
					   } catch {
						   findings.push(
							   createFinding(
								   'subdomain_takeover' as CheckCategory,
								   `CNAME resolution failed: ${fqdn} → ${cname}`,
								   'high',
								   `Could not resolve CNAME target ${cname} for ${fqdn}. Manual review recommended.`,
							   ),
						   );
					   }
				   }
			   }
		   } catch {
			   // No CNAME or query failed; not critical
		   }
	   }

	   if (findings.length === 0) {
		   findings.push(
			   createFinding(
				   'subdomain_takeover' as CheckCategory,
				   'No dangling CNAME records found',
				   'info',
				   `No subdomain takeover vectors detected for ${domain} among known/active subdomains.`,
			   ),
		   );
	   }

	   return buildCheckResult('subdomain_takeover' as CheckCategory, findings);
}
