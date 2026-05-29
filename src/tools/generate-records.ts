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

import type { OutputFormat } from '../handlers/tool-args';
import type { CheckResult, Finding } from '@blackveil/dns-checks/scoring';
import type { QueryDnsOptions } from '../lib/dns-types';
import { queryMxRecords, queryTxtRecords } from '../lib/dns';
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
	const warnings: string[] = [];
	const instructions: string[] = [];

	// Detect the domain's existing authorizing mechanisms directly from live DNS.
	// We must preserve ALL authorizing mechanisms (ip4, ip6, a, mx, include, exists,
	// redirect) — not just include: — or a generated record would silently drop a
	// domain's legitimate senders and hard-fail their mail.
	const existing = await detectExistingSpfMechanisms(domain, dnsOptions);

	// Build the authorizing-mechanism list, preserving existing mechanisms verbatim.
	// Use insertion-ordered de-dup so the live record's structure is retained.
	const mechanisms: string[] = [];
	const seen = new Set<string>();
	const addMechanism = (mech: string): void => {
		const trimmed = mech.trim();
		if (trimmed.length === 0 || seen.has(trimmed.toLowerCase())) return;
		seen.add(trimmed.toLowerCase());
		mechanisms.push(trimmed);
	};

	for (const mech of existing.mechanisms) {
		addMechanism(mech);
	}

	// Layer in explicitly requested providers (in addition to detected senders).
	if (includeProviders) {
		for (const provider of includeProviders) {
			const normalized = provider.toLowerCase().trim();
			const known = KNOWN_SPF_INCLUDES[normalized];
			if (known) {
				addMechanism(`include:${known}`);
			} else if (normalized.includes('.')) {
				// Treat as raw include domain
				addMechanism(`include:${normalized}`);
			} else {
				warnings.push(`Unknown provider "${provider}" — skipped. Use a full include domain instead.`);
			}
		}
	}

	// A redirect= modifier replaces the entire record (RFC 7208 §6.1), so 'all'
	// is irrelevant and must not be appended.
	const hasRedirect = mechanisms.some((m) => /^redirect=/i.test(m));

	// HARD GUARD: never emit a bare "v=spf1 -all". Publishing an SPF record with no
	// authorizing mechanisms and a hard fail (-all) rejects ALL of the domain's mail.
	// This is the safety net the detection step backstops — detection can fail
	// (timeout / DoH error) and we must refuse rather than break delivery silently.
	if (mechanisms.length === 0 && !hasRedirect) {
		warnings.push(
			'No email senders detected for this domain and no include_providers were supplied. ' +
				'Refusing to emit a bare "v=spf1 -all" because publishing it would REJECT ALL mail for the domain. ' +
				'Pass include_providers (e.g. your email provider) or run a scan first so existing senders can be preserved.',
		);
		const safeValue = 'v=spf1 ?all';
		instructions.push(
			`No SPF record could be generated safely for ${domain}.`,
			existing.detectionFailed
				? 'The existing SPF record could not be read from DNS (lookup failed or timed out).'
				: 'No existing SPF record was found and no senders were provided.',
			'Provide include_providers for every legitimate sending source, then regenerate.',
			'A neutral "v=spf1 ?all" is shown only as a non-breaking placeholder — it does NOT protect against spoofing.',
		);
		return {
			recordType: 'TXT',
			name: domain,
			value: safeValue,
			warnings,
			instructions,
		};
	}

	// Build the SPF record. Join with single spaces to avoid the double-space defect.
	const parts = ['v=spf1', ...mechanisms];
	if (!hasRedirect) {
		parts.push('-all');
	}
	const spfValue = parts.join(' ');

	// Count DNS-lookup-incurring mechanisms (10 maximum per RFC 7208 §4.6.4):
	// include, a, mx, ptr, exists, redirect. ip4/ip6 do NOT incur lookups.
	const lookupMechanisms = mechanisms.filter((m) => /^(include:|a[:/\s]?|a$|mx[:/\s]?|mx$|ptr|exists:|redirect=)/i.test(m));
	if (lookupMechanisms.length > 10) {
		warnings.push(`SPF record has ${lookupMechanisms.length} lookup-incurring mechanisms — exceeds the 10-lookup limit (RFC 7208). Consider consolidating.`);
	}

	if (existing.detectionFailed && (includeProviders?.length ?? 0) > 0) {
		warnings.push(
			'Could not read the existing SPF record from DNS, so only the explicitly supplied include_providers are included. ' +
				'Verify no other legitimate senders are missing before publishing.',
		);
	}

	instructions.push(`Publish the following TXT record at ${domain}:`);
	instructions.push(`  Type: TXT`);
	instructions.push(`  Name: ${domain}`);
	instructions.push(`  Value: ${spfValue}`);
	instructions.push('');
	if (hasRedirect) {
		instructions.push('This record uses a "redirect=" modifier, which delegates the policy to another domain. No "all" mechanism is added.');
	} else {
		instructions.push('The "-all" suffix means emails from servers not listed will be rejected (hard fail).');
	}

	return {
		recordType: 'TXT',
		name: domain,
		value: spfValue,
		warnings,
		instructions,
	};
}

/** Result of detecting a domain's existing SPF authorizing mechanisms. */
interface ExistingSpfMechanisms {
	/** Authorizing/policy mechanisms in record order (ip4, ip6, a, mx, include, exists, redirect=). */
	mechanisms: string[];
	/** True if the live SPF record could not be read (lookup failed/timed out). */
	detectionFailed: boolean;
}

/**
 * Read the domain's live SPF record and extract every authorizing mechanism
 * verbatim. This preserves ip4/ip6/a/mx/include/exists/redirect so a regenerated
 * record does not silently drop legitimate senders.
 */
async function detectExistingSpfMechanisms(
	domain: string,
	dnsOptions?: QueryDnsOptions,
): Promise<ExistingSpfMechanisms> {
	let txtRecords: string[];
	try {
		txtRecords = await queryTxtRecords(domain, dnsOptions);
	} catch {
		return { mechanisms: [], detectionFailed: true };
	}

	const concatenated = txtRecords.join('');
	const spfMatch = concatenated.match(/v=spf1[^]*/i);
	if (!spfMatch) {
		// No SPF record present — not a failure, just nothing to preserve.
		return { mechanisms: [], detectionFailed: false };
	}

	const tokens = spfMatch[0].trim().split(/\s+/);
	const mechanisms: string[] = [];
	for (const token of tokens) {
		if (/^v=spf1$/i.test(token)) continue;
		// Skip the terminating 'all' mechanism (any qualifier) — we re-add our own.
		if (/^[+?~-]?all$/i.test(token)) continue;
		// Keep authorizing/policy mechanisms only.
		if (/^([+?~-]?)(ip4:|ip6:|a([:/]|$)|mx([:/]|$)|include:|exists:|ptr|redirect=)/i.test(token)) {
			mechanisms.push(token);
		}
	}

	return { mechanisms, detectionFailed: false };
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

	// Resolve MX hosts. When mx_hosts is omitted, auto-detect from live DNS (the
	// schema documents "Omit to detect from DNS"). Fall back to parsing the
	// MTA-STS check findings only if a direct MX query yields nothing.
	let effectiveMxHosts = mxHosts ?? [];
	if (effectiveMxHosts.length === 0) {
		effectiveMxHosts = await detectMxHosts(domain, dnsOptions);
	}
	if (effectiveMxHosts.length === 0) {
		effectiveMxHosts = extractMxHostsFromFindings(checkResult);
	}

	if (effectiveMxHosts.length === 0) {
		warnings.push('No MX hosts found in DNS or provided. The domain appears to have no MX records — specify mx_hosts to generate a usable policy file.');
		effectiveMxHosts = ['mail.example.com'];
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

/**
 * Auto-detect a domain's MX hostnames directly from live DNS.
 * Returns lowercased, trailing-dot-stripped exchange hostnames sorted by priority.
 */
async function detectMxHosts(domain: string, dnsOptions?: QueryDnsOptions): Promise<string[]> {
	try {
		const records = await queryMxRecords(domain, dnsOptions);
		const seen = new Set<string>();
		const hosts: string[] = [];
		for (const { exchange } of [...records].sort((a, b) => a.priority - b.priority)) {
			const host = exchange.trim().replace(/\.$/, '').toLowerCase();
			// A single "." exchange is RFC 7505 "null MX" — the domain does not receive mail.
			if (host.length === 0 || host === '.' || seen.has(host)) continue;
			seen.add(host);
			hosts.push(host);
		}
		return hosts;
	} catch {
		return [];
	}
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
export function formatGeneratedRecord(record: GeneratedRecord, format: OutputFormat = 'full'): string {
	const lines: string[] = [];

	if (format === 'compact') {
		lines.push(`${record.recordType}: ${record.name}`);
		lines.push(record.value);
		for (const w of record.warnings) {
			lines.push(`⚠ ${w}`);
		}
		return lines.join('\n');
	}

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
