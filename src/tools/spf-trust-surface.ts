// SPDX-License-Identifier: MIT

/**
 * SPF Trust Surface Analysis.
 * Identifies when SPF include: or redirect= directives delegate sending
 * authority to multi-tenant SaaS platforms, expanding the domain's trust surface.
 */

import type { Finding } from '../lib/scoring';
import { createFinding } from '../lib/scoring';

interface PlatformInfo {
	name: string;
	risk: string;
}

export interface TrustSurfaceContext {
	corroboratedByWeakDmarc?: boolean;
	dmarcPolicy?: string;
	dmarcAlignmentMode?: string;
}

/** Known multi-tenant SaaS platforms whose shared SPF includes widen the trust surface. */
const MULTI_TENANT_PLATFORMS: ReadonlyMap<string, PlatformInfo> = new Map([
	['_spf.salesforce.com', { name: 'Salesforce', risk: 'Any Salesforce customer can send as your domain' }],
	[
		'spf.protection.outlook.com',
		{ name: 'Microsoft 365', risk: 'Any M365 tenant can send as your domain without DKIM/DMARC enforcement' },
	],
	['_spf.google.com', { name: 'Google Workspace', risk: 'Any Google Workspace customer can send as your domain' }],
	['sendgrid.net', { name: 'SendGrid', risk: 'Any SendGrid customer can send as your domain' }],
	['spf.mandrillapp.com', { name: 'Mailchimp/Mandrill', risk: 'Any Mailchimp customer can send as your domain' }],
	['mail.zendesk.com', { name: 'Zendesk', risk: 'Any Zendesk customer can send as your domain' }],
	['stspg-customer.com', { name: 'Postmark', risk: 'Any Postmark customer can send as your domain' }],
	['spf.brevo.com', { name: 'Brevo (Sendinblue)', risk: 'Any Brevo customer can send as your domain' }],
	['amazonses.com', { name: 'Amazon SES', risk: 'Any SES customer can send as your domain' }],
	['servers.mcsv.net', { name: 'Mailchimp', risk: 'Any Mailchimp customer can send as your domain' }],
	['hubspotemail.net', { name: 'HubSpot', risk: 'Any HubSpot customer can send as your domain' }],
	['mktomail.com', { name: 'Marketo', risk: 'Any Marketo customer can send as your domain' }],
	['pphosted.com', { name: 'Proofpoint', risk: 'Any Proofpoint customer can send as your domain' }],
	['firebasemail.com', { name: 'Firebase', risk: 'Any Firebase project can send as your domain' }],
	['freshdesk.com', { name: 'Freshdesk', risk: 'Any Freshdesk customer can send as your domain' }],
	['spf.messagelabs.com', { name: 'Symantec/Broadcom', risk: 'Shared sending infrastructure' }],
	['_spf.atlassian.net', { name: 'Atlassian', risk: 'Any Atlassian customer can send as your domain' }],
	['xero.com', { name: 'Xero', risk: 'Any Xero customer can send as your domain' }],
]);

/**
 * Check whether a domain matches or is a subdomain of a known multi-tenant platform.
 */
function matchPlatform(domain: string): { key: string; info: PlatformInfo } | undefined {
	const lower = domain.toLowerCase();
	for (const [key, info] of MULTI_TENANT_PLATFORMS) {
		if (lower === key || lower.endsWith(`.${key}`)) {
			return { key, info };
		}
	}
	return undefined;
}

/**
 * Extract include: and redirect= domains from an SPF record string.
 */
function extractIncludeAndRedirectDomains(spfRecord: string): string[] {
	const domains: string[] = [];
	const includeRegex = /\binclude:([^\s]+)/gi;
	const redirectRegex = /\bredirect=([^\s]+)/gi;

	let match: RegExpExecArray | null;
	while ((match = includeRegex.exec(spfRecord)) !== null) {
		domains.push(match[1]);
	}
	while ((match = redirectRegex.exec(spfRecord)) !== null) {
		domains.push(match[1]);
	}
	return domains;
}

/**
 * Analyze an SPF record for trust surface exposure from multi-tenant SaaS platform includes.
 * Returns findings for each shared platform detected, plus a summary finding when multiple are found.
 */
export function analyzeTrustSurface(spfRecord: string, context: TrustSurfaceContext = {}): Finding[] {
	const findings: Finding[] = [];
	const domains = extractIncludeAndRedirectDomains(spfRecord);
	const matchedPlatforms: { name: string; includeDomain: string }[] = [];
	const corroboratedByWeakDmarc = context.corroboratedByWeakDmarc === true;
	const findingSeverity = corroboratedByWeakDmarc ? 'medium' : 'info';
	const summarySeverity = corroboratedByWeakDmarc ? 'high' : 'info';
	const detailSuffix = corroboratedByWeakDmarc
		? 'Weak DMARC enforcement and relaxed alignment corroborate this exposure, so a provider misconfiguration or abuse case would be more likely to pass policy checks.'
		: 'This is common and not inherently a misconfiguration, but it expands the sending infrastructure you rely on. The risk becomes more material when DMARC enforcement and alignment are weak.';

	for (const domain of domains) {
		const result = matchPlatform(domain);
		if (result) {
			matchedPlatforms.push({ name: result.info.name, includeDomain: domain });
			findings.push(
				createFinding(
					'spf',
					`SPF delegates to shared platform: ${result.info.name}`,
					findingSeverity,
					`SPF include:${domain} authorizes ${result.info.name}. ${result.info.risk}. ${detailSuffix}`,
					{
						trustSurface: true,
						platform: result.info.name,
						includeDomain: domain,
						dmarcCorroborated: corroboratedByWeakDmarc,
						...(context.dmarcPolicy ? { dmarcPolicy: context.dmarcPolicy } : {}),
						...(context.dmarcAlignmentMode ? { dmarcAlignmentMode: context.dmarcAlignmentMode } : {}),
					},
				),
			);
		}
	}

	if (matchedPlatforms.length > 1) {
		const platformNames = matchedPlatforms.map((p) => p.name).join(', ');
		findings.push(
			createFinding(
				'spf',
				`SPF trust surface: ${matchedPlatforms.length} shared platforms`,
				summarySeverity,
				`SPF record delegates sending authority to ${matchedPlatforms.length} multi-tenant platforms (${platformNames}). Audit each include to confirm it is still needed, configure provider-specific DKIM, and keep DMARC enforcement and alignment strong across every authorized sender.`,
				{
					trustSurface: true,
					platformCount: matchedPlatforms.length,
					platforms: platformNames,
					dmarcCorroborated: corroboratedByWeakDmarc,
					...(context.dmarcPolicy ? { dmarcPolicy: context.dmarcPolicy } : {}),
					...(context.dmarcAlignmentMode ? { dmarcAlignmentMode: context.dmarcAlignmentMode } : {}),
				},
			),
		);
	}

	return findings;
}
