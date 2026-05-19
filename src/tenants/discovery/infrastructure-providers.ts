// SPDX-License-Identifier: BUSL-1.1

import { getRegistrableDomain } from '../../lib/public-suffix';

/**
 * Shared infrastructure-provider allowlist for the brand-discovery subsystem.
 *
 * Multi-tenant endpoints (DMARC aggregators, cloud mail platforms, transactional
 * mail egress, CDNs, marketing/CRM SaaS) where a signal overlap is expected but
 * does not indicate organization ownership. Consumed by both:
 *   - `src/tools/discover-brand-domains.ts` (orchestrator drops these candidates)
 *   - `src/tenants/discovery/dmarc-rua-miner.ts` (classifies as `processor`)
 *
 * Single source of truth — adding a vendor here closes the loophole at both
 * layers simultaneously. Enforced by
 * `test/audits/dmarc-rua-processor-consistency.audit.test.ts`.
 */

/** Apex-form hostnames (2-label) of infrastructure providers. */
export const INFRASTRUCTURE_PROVIDERS: ReadonlySet<string> = new Set([
	// DMARC aggregators / report processors
	'agari.com',
	'proofpoint.com',
	'valimail.com',
	'valimail.net',
	'ondmarc.com',
	'mimecast.com',
	'dmarcian.com',
	'easydmarc.com',
	'postmarkapp.com',
	'mxtoolbox.com',
	'dmarcanalyzer.com',
	'urivault.com',
	// Cloud mail platforms
	'outlook.com',
	'office.com',
	'microsoft.com',
	'google.com',
	'googlemail.com',
	'googlegroups.com',
	'gmail.com',
	// Transactional / bulk mail egress
	'amazonses.com',
	'amazonaws.com',
	'mailgun.com',
	'mailgun.org',
	'mailgun.net',
	'sendgrid.net',
	'sendgrid.com',
	'sparkpost.com',
	'mandrillapp.com',
	'mailchimp.com',
	'mcsv.net',
	'mcdlv.net',
	'mailerlite.com',
	'klaviyo.com',
	// CDN / edge / cloud
	'cloudflare.com',
	'cloudflare.net',
	'cloudflare.io',
	'cloudflare.dev',
	'cloudfront.net',
	'fastly.net',
	'akamai.net',
	'akamaitechnologies.com',
	// Marketing / CRM / support SaaS
	'marketo.com',
	'salesforce.com',
	'salesforce.io',
	'force.com',
	'pardot.com',
	'hubspot.com',
	'hubapi.com',
	'hubspotemail.net',
	'hsforms.com',
	'zendesk.com',
	'intercom.io',
	'intercom.com',
	'helpscout.net',
	'freshdesk.com',
	'zoho.com',
	'zoho.eu',
]);

/** Extract the PSL-aware registered apex from a hostname. */
export function registeredApex(host: string): string {
	const normalizedHost = host.trim().toLowerCase().replace(/\.$/, '');
	return getRegistrableDomain(host) ?? normalizedHost;
}

/**
 * True if `host` is in INFRASTRUCTURE_PROVIDERS exactly, or is a subdomain
 * of any listed provider at any depth.
 *
 * LR-3 (TLD-variant evasion) is closed by enumerating every variant in
 * INFRASTRUCTURE_PROVIDERS, not by changing the match algorithm.
 */
export function isInfrastructureProvider(host: string): boolean {
	const lower = host.trim().toLowerCase().replace(/\.$/, '');
	for (const provider of INFRASTRUCTURE_PROVIDERS) {
		if (lower === provider || lower.endsWith('.' + provider)) return true;
	}
	return false;
}
