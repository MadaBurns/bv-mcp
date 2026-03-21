// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS record generators for remediation workflows.
 *
 * Each generator runs the relevant check_* function (cached), inspects the
 * CheckResult findings and metadata, then produces a corrected record value
 * with warnings for any edge cases.
 *
 * These are pure computation over existing check data — no additional DNS queries.
 */

import type { CheckResult, Finding } from '../lib/scoring-model';
import type { QueryDnsOptions } from '../lib/dns-types';
import { checkSpf } from './check-spf';
import { checkDmarc } from './check-dmarc';
import { checkMtaSts } from './check-mta-sts';

/** Result from a record generator. */
export interface GeneratedRecord {
	recordType: 'TXT' | 'CNAME' | 'MTA-STS';
	name: string;
	value: string;
	warnings: string[];
	instructions: string[];
}

// ─── SPF Record Generator ─────────────────────────────────────────────

/** Well-known include domains for major email providers. */
const KNOWN_SPF_INCLUDES: Record<string, string> = {
	'google': '_spf.google.com',
	'google workspace': '_spf.google.com',
	'microsoft': 'spf.protection.outlook.com',
	'microsoft 365': 'spf.protection.outlook.com',
	'outlook': 'spf.protection.outlook.com',
	'sendgrid': 'sendgrid.net',
	'mailchimp': 'servers.mcsv.net',
	'amazon ses': 'amazonses.com',
	'zoho': '_spf.zoho.com',
	'postmark': 'spf.mtasv.net',
	'mailgun': 'mailgun.org',
	'freshdesk': 'email.freshdesk.com',
	'zendesk': 'mail.zendesk.com',
	'salesforce': '_spf.salesforce.com',
	'hubspot': '_spf.hubspot.com',
};

/**
 * Generate a corrected SPF record for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param includeProviders - Optional explicit provider include domains
 * @param dnsOptions - DNS query options for the underlying check
 */
export async function generateSpfRecord(
	domain: string,
	includeProviders?: string[],
	dnsOptions?: QueryDnsOptions,
): Promise<GeneratedRecord> {
	const checkResult = await checkSpf(domain, dnsOptions);
	const warnings: string[] = [];
	const instructions: string[] = [];

	// Extract existing include domains from findings metadata
	const existingIncludes = extractSpfIncludes(checkResult);

	// Start with explicitly requested providers
	const includes = new Set<string>(existingIncludes);

	if (includeProviders) {
		for (const provider of includeProviders) {
			const normalized = provider.toLowerCase().trim();
			const known = KNOWN_SPF_INCLUDES[normalized];
			if (known) {
				includes.add(known);
			} else if (normalized.includes('.')) {
				// Treat as raw include domain
				includes.add(normalized);
			} else {
				warnings.push(`Unknown provider "${provider}" — skipped. Use a full include domain instead.`);
			}
		}
	}

	// Build the SPF record
	const mechanisms: string[] = [];
	for (const inc of includes) {
		mechanisms.push(`include:${inc}`);
	}

	// Check DNS lookup count (10 maximum per RFC 7208)
	if (mechanisms.length > 10) {
		warnings.push(`SPF record has ${mechanisms.length} include mechanisms — exceeds the 10-lookup limit. Consider consolidating.`);
	}

	const spfValue = `v=spf1 ${mechanisms.join(' ')} -all`;

	instructions.push(`Publish the following TXT record at ${domain}:`);
	instructions.push(`  Type: TXT`);
	instructions.push(`  Name: ${domain}`);
	instructions.push(`  Value: ${spfValue}`);
	instructions.push('');
	instructions.push('The "-all" suffix means emails from servers not listed will be rejected (hard fail).');

	if (!checkResult.passed) {
		instructions.push('');
		instructions.push('Note: Your current SPF record has issues that this generated record addresses.');
	}

	return {
		recordType: 'TXT',
		name: domain,
		value: spfValue,
		warnings,
		instructions,
	};
}

/** Extract existing include domains from SPF check findings. */
function extractSpfIncludes(result: CheckResult): string[] {
	const includes: string[] = [];
	for (const finding of result.findings) {
		// Look for include domains in metadata or detail text
		if (finding.metadata?.includeDomains && Array.isArray(finding.metadata.includeDomains)) {
			includes.push(...(finding.metadata.includeDomains as string[]));
		}
		// Parse from detail text as fallback
		const includeMatches = finding.detail.match(/include:([^\s]+)/g);
		if (includeMatches) {
			for (const match of includeMatches) {
				includes.push(match.replace('include:', ''));
			}
		}
	}
	return [...new Set(includes)];
}

// ─── DMARC Record Generator ──────────────────────────────────────────

/**
 * Generate a DMARC record for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param policy - DMARC policy (default: 'reject')
 * @param ruaEmail - Aggregate report email (default: `dmarc-reports@{domain}`)
 * @param dnsOptions - DNS query options
 */
export async function generateDmarcRecord(
	domain: string,
	policy?: 'none' | 'quarantine' | 'reject',
	ruaEmail?: string,
	dnsOptions?: QueryDnsOptions,
): Promise<GeneratedRecord> {
	const checkResult = await checkDmarc(domain, dnsOptions);
	const warnings: string[] = [];
	const instructions: string[] = [];

	const effectivePolicy = policy ?? 'reject';
	const reportEmail = ruaEmail ?? `dmarc-reports@${domain}`;

	// Build DMARC record
	const tags: string[] = [
		`v=DMARC1`,
		`p=${effectivePolicy}`,
		`rua=mailto:${reportEmail}`,
		`adkim=s`,
		`aspf=s`,
		`pct=100`,
	];

	// Add subdomain policy
	tags.push(`sp=${effectivePolicy}`);

	const dmarcValue = tags.join('; ');

	if (effectivePolicy === 'none') {
		warnings.push('Policy "none" provides monitoring only — emails will not be rejected or quarantined.');
		warnings.push('Start with "none" for monitoring, then move to "quarantine" and finally "reject".');
	}

	if (effectivePolicy === 'quarantine') {
		warnings.push('Policy "quarantine" sends suspicious emails to spam. Consider "reject" for full enforcement.');
	}

	// Check if existing DMARC has reporting
	const hasExistingReporting = checkResult.findings.some(
		(f: Finding) => f.detail.toLowerCase().includes('rua') || f.detail.toLowerCase().includes('aggregate'),
	);

	instructions.push(`Publish the following TXT record at _dmarc.${domain}:`);
	instructions.push(`  Type: TXT`);
	instructions.push(`  Name: _dmarc.${domain}`);
	instructions.push(`  Value: ${dmarcValue}`);
	instructions.push('');
	instructions.push(`Ensure "${reportEmail}" can receive reports. Many providers offer free DMARC report processing.`);

	if (!hasExistingReporting) {
		instructions.push('');
		instructions.push('Tip: Set up a DMARC report processor (e.g., Report URI, Valimail, EasyDMARC) to analyze aggregate reports.');
	}

	return {
		recordType: 'TXT',
		name: `_dmarc.${domain}`,
		value: dmarcValue,
		warnings,
		instructions,
	};
}

// ─── DKIM Config Generator ──────────────────────────────────────────

/** Provider-specific DKIM setup instructions. */
const DKIM_PROVIDER_INSTRUCTIONS: Record<string, string[]> = {
	'google': [
		'1. Go to Google Admin Console → Apps → Google Workspace → Gmail → Authenticate email',
		'2. Select your domain and click "Generate new record"',
		'3. Choose 2048-bit key length',
		'4. Copy the TXT record name and value',
		'5. Add the TXT record to your DNS provider',
		'6. Return to Google Admin and click "Start authentication"',
	],
	'microsoft': [
		'1. Go to Microsoft 365 Defender → Email & collaboration → Policies → DKIM',
		'2. Select your domain',
		'3. Toggle "Sign messages for this domain with DKIM signatures" to Enabled',
		'4. Microsoft creates two CNAME records: selector1._domainkey and selector2._domainkey',
		'5. Add both CNAME records to your DNS provider',
		'6. Return to Microsoft 365 and confirm DKIM is enabled',
	],
	'default': [
		'1. Generate a 2048-bit RSA key pair for DKIM signing',
		'2. Publish the public key as a TXT record at {selector}._domainkey.{domain}',
		'3. Configure your mail server to sign outgoing emails with the private key',
		'4. Verify with: dig TXT {selector}._domainkey.{domain}',
	],
};

/**
 * Generate DKIM configuration instructions for a domain.
 *
 * @param domain - Validated, sanitized domain
 * @param provider - Optional email provider name (e.g., "google", "microsoft")
 */
export async function generateDkimConfig(
	domain: string,
	provider?: string,
): Promise<GeneratedRecord> {
	const warnings: string[] = [];
	const normalizedProvider = provider?.toLowerCase().trim() ?? 'default';

	const providerInstructions = DKIM_PROVIDER_INSTRUCTIONS[normalizedProvider]
		?? DKIM_PROVIDER_INSTRUCTIONS['default'];

	const instructions = providerInstructions.map((step) =>
		step.replace('{domain}', domain).replace('{selector}', 'default'),
	);

	if (normalizedProvider === 'default' && !provider) {
		warnings.push('No email provider specified. Showing generic DKIM setup. Specify your provider for tailored instructions.');
	}

	// Generate a placeholder record for reference
	const selectorName = normalizedProvider === 'google' ? 'google' :
		normalizedProvider === 'microsoft' ? 'selector1' : 'default';

	return {
		recordType: 'TXT',
		name: `${selectorName}._domainkey.${domain}`,
		value: 'v=DKIM1; k=rsa; p=<YOUR_PUBLIC_KEY>',
		warnings,
		instructions,
	};
}

// ─── MTA-STS Policy Generator ────────────────────────────────────────

/**
 * Generate MTA-STS TXT record and policy file content.
 *
 * @param domain - Validated, sanitized domain
 * @param mxHosts - Optional explicit MX hostnames. If omitted, attempts to extract from check.
 * @param dnsOptions - DNS query options
 */
export async function generateMtaStsPolicy(
	domain: string,
	mxHosts?: string[],
	dnsOptions?: QueryDnsOptions,
): Promise<GeneratedRecord> {
	const checkResult = await checkMtaSts(domain, dnsOptions);
	const warnings: string[] = [];
	const instructions: string[] = [];

	// Extract MX hosts from findings if not provided
	const effectiveMxHosts = mxHosts ?? extractMxHostsFromFindings(checkResult);

	if (effectiveMxHosts.length === 0) {
		warnings.push('No MX hosts found or provided. You must specify mx_hosts for the policy file.');
		effectiveMxHosts.push('mail.example.com');
	}

	// Generate policy ID (timestamp-based)
	const policyId = new Date().toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);

	// TXT record value
	const txtValue = `v=STSv1; id=${policyId}`;

	// Policy file content
	const policyLines = [
		'version: STSv1',
		'mode: enforce',
		`max_age: 86400`,
	];
	for (const mx of effectiveMxHosts) {
		policyLines.push(`mx: ${mx}`);
	}
	const policyContent = policyLines.join('\n');

	instructions.push(`Step 1: Publish TXT record at _mta-sts.${domain}:`);
	instructions.push(`  Type: TXT`);
	instructions.push(`  Name: _mta-sts.${domain}`);
	instructions.push(`  Value: ${txtValue}`);
	instructions.push('');
	instructions.push(`Step 2: Host the policy file at https://mta-sts.${domain}/.well-known/mta-sts.txt`);
	instructions.push('  Content:');
	for (const line of policyLines) {
		instructions.push(`    ${line}`);
	}
	instructions.push('');
	instructions.push('Step 3: Ensure mta-sts.{domain} has a valid HTTPS certificate.');
	instructions.push('');
	instructions.push('Note: Start with mode "testing" before switching to "enforce" to avoid delivery issues.');
	instructions.push(`Update the "id" value in the TXT record whenever the policy changes.`);

	if (!checkResult.passed) {
		warnings.push('Your current MTA-STS configuration has issues. Review the instructions carefully.');
	}

	return {
		recordType: 'MTA-STS',
		name: `_mta-sts.${domain}`,
		value: txtValue,
		warnings,
		instructions: [
			...instructions,
			'',
			'--- Policy file content (mta-sts.txt) ---',
			policyContent,
		],
	};
}

/** Extract MX hostnames from MTA-STS check findings. */
function extractMxHostsFromFindings(result: CheckResult): string[] {
	const hosts: string[] = [];
	for (const finding of result.findings) {
		if (finding.metadata?.mxHosts && Array.isArray(finding.metadata.mxHosts)) {
			hosts.push(...(finding.metadata.mxHosts as string[]));
		}
		// Try to parse MX hosts from detail text
		const mxMatches = finding.detail.match(/mx:\s*([^\s,]+)/gi);
		if (mxMatches) {
			for (const match of mxMatches) {
				const host = match.replace(/^mx:\s*/i, '').trim();
				if (host && host !== 'example.com') {
					hosts.push(host);
				}
			}
		}
	}
	return [...new Set(hosts)];
}

// ─── Format helpers ──────────────────────────────────────────────────

/** Format a generated record as a human-readable text block. */
export function formatGeneratedRecord(record: GeneratedRecord): string {
	const lines: string[] = [];

	lines.push(`# Generated ${record.recordType} Record`);
	lines.push(`Name: ${record.name}`);
	lines.push(`Value: ${record.value}`);
	lines.push('');

	if (record.warnings.length > 0) {
		lines.push('## Warnings');
		for (const w of record.warnings) {
			lines.push(`- ${w}`);
		}
		lines.push('');
	}

	if (record.instructions.length > 0) {
		lines.push('## Instructions');
		for (const inst of record.instructions) {
			lines.push(inst);
		}
	}

	return lines.join('\n');
}
