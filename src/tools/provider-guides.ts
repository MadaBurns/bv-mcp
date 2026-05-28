// SPDX-License-Identifier: BUSL-1.1

/**
 * Provider knowledge base for provider-aware fix plans.
 * Detects email, DNS, and sending infrastructure providers from DNS signals,
 * and returns actionable remediation steps tailored to each provider's UI.
 */

/** A detected infrastructure provider with role and detection signal. */
export interface DetectedProvider {
	name: string;
	role: 'mail' | 'dns' | 'sending';
	signal: string;
}

/** Input signals for provider detection. */
export interface ProviderDetectionInput {
	mxHosts: string[];
	spfIncludes: string[];
	nsHosts: string[];
}

/** Actions that fix guides can provide steps for. */
export type FixAction = 'add_txt' | 'enable_dkim' | 'add_mta_sts' | 'enable_dnssec';

/** Parameters passed to fix guide step generators. */
export interface FixStepParams {
	name?: string;
	value?: string;
}

interface DetectionRule {
	name: string;
	role: 'mail' | 'dns' | 'sending';
	patterns: {
		mx?: RegExp;
		spf?: RegExp;
		ns?: RegExp;
	};
	signal: string;
}

/** Static detection rules with regex patterns for MX, SPF, and NS matching. */
const DETECTION_RULES: DetectionRule[] = [
	{
		name: 'Google Workspace',
		role: 'mail',
		patterns: {
			mx: /\.google\.com$/i,
			spf: /_spf\.google\.com$/i,
		},
		signal: 'mx:google.com',
	},
	{
		name: 'Microsoft 365',
		role: 'mail',
		patterns: {
			mx: /\.mail\.protection\.outlook\.com$/i,
			spf: /spf\.protection\.outlook\.com$/i,
		},
		signal: 'mx:mail.protection.outlook.com',
	},
	{
		name: 'Fastmail',
		role: 'mail',
		patterns: {
			mx: /\.messagingengine\.com$/i,
		},
		signal: 'mx:messagingengine.com',
	},
	{
		name: 'Mimecast',
		role: 'mail',
		patterns: {
			mx: /\.mimecast\.com$/i,
		},
		signal: 'mx:mimecast.com',
	},
	{
		name: 'Proofpoint',
		role: 'mail',
		patterns: {
			mx: /\.pphosted\.com$/i,
		},
		signal: 'mx:pphosted.com',
	},
	{
		name: 'Cloudflare',
		role: 'dns',
		patterns: {
			ns: /\.cloudflare\.com$/i,
		},
		signal: 'ns:cloudflare.com',
	},
	{
		name: 'AWS Route 53',
		role: 'dns',
		patterns: {
			ns: /awsdns-\d+\./i,
		},
		signal: 'ns:awsdns',
	},
	{
		name: 'Namecheap',
		role: 'dns',
		patterns: {
			ns: /\.registrar-servers\.com$/i,
		},
		signal: 'ns:registrar-servers.com',
	},
	{
		name: 'GoDaddy',
		role: 'dns',
		patterns: {
			ns: /\.domaincontrol\.com$/i,
		},
		signal: 'ns:domaincontrol.com',
	},
	{
		// UltraDNS (Neustar/Vercara). Multi-TLD vendor — same authoritative DNS
		// service is served from `*.ultradns.com`, `*.ultradns.net`, `*.ultradns.info`,
		// `*.ultradns.biz`. Without this collapse, a single zone using two sibling
		// TLDs (eg. `pdns100.ultradns.com` + `pdns100.ultradns.net`) lists as two
		// separate dns-hosting rows. Mirrors the AWS Route 53 multi-TLD pattern.
		// Defect surfaced 2026-05-28.
		name: 'UltraDNS (Neustar)',
		role: 'dns',
		patterns: {
			ns: /\.ultradns\.(com|net|info|biz)$/i,
		},
		signal: 'ns:ultradns',
	},
	{
		// NS1 (IBM, since 2024). Multi-TLD vendor — authoritative DNS is served
		// from both `*.ns1.com` and `*.nsone.net`. Many large customers carry NS
		// hosts on both sibling TLDs for redundancy; without this collapse the
		// supply-chain map double-counts. Single-TLD deployments (eg. nsone.net
		// only) must still resolve to the same canonical provider name.
		// Catalog gap surfaced 2026-05-28 (post-v3.3.14 fact-check round).
		name: 'NS1 (IBM)',
		role: 'dns',
		patterns: {
			ns: /\.(nsone\.net|ns1\.com)$/i,
		},
		signal: 'ns:ns1',
	},
	{
		// Dyn (Oracle Dyn). Multi-TLD vendor — authoritative DNS is served from
		// both `*.dyn.com` and `*.dynect.net`. Many pre-Oracle-acquisition
		// enterprise customers still carry NS hosts on both sibling TLDs.
		// Catalog gap surfaced 2026-05-28 (post-v3.3.14 fact-check round).
		name: 'Dyn (Oracle)',
		role: 'dns',
		patterns: {
			ns: /\.(dyn\.com|dynect\.net)$/i,
		},
		signal: 'ns:dyn',
	},
	{
		name: 'AWS SES',
		role: 'sending',
		patterns: {
			spf: /amazonses\.com$/i,
		},
		signal: 'spf:amazonses.com',
	},
	{
		name: 'SendGrid',
		role: 'sending',
		patterns: {
			spf: /sendgrid\.net$/i,
		},
		signal: 'spf:sendgrid.net',
	},
	{
		name: 'Mailgun',
		role: 'sending',
		patterns: {
			spf: /mailgun\.org$/i,
		},
		signal: 'spf:mailgun.org',
	},
	{
		name: 'Postmark',
		role: 'sending',
		patterns: {
			spf: /mtasv\.net$/i,
		},
		signal: 'spf:mtasv.net',
	},
	{
		// AutoSPF. SPF-flattening service — customers replace their nested SPF
		// includes with a single per-tenant include under `*.autospf.email`
		// (eg. `_s00430413.autospf.email`). Without this rule the raw per-tenant
		// selector hostname surfaces as a third-party row instead of the canonical
		// provider name. SPF-only (no fixed MX hostnames); the SPF-rule dedup path
		// (matchProviderForSpfInclude) handles it.
		// Catalog gap surfaced 2026-05-28 (post-v3.3.19 fact-check round).
		name: 'AutoSPF',
		role: 'sending',
		patterns: {
			spf: /\.autospf\.email$/i,
		},
		signal: 'spf:autospf',
	},
	{
		// Trellix Email Security (formerly FireEye Email Security; rebranded after
		// Trellix was formed in 2022). Enterprise email security gateway that sits
		// between sender and recipient; SPF includes resolve to AWS-edge senders.
		// Detected via SPF only (no fixed MX hostnames — customers point their MX
		// at customer-specific Trellix tenants); intentionally no `signal: 'mx:…'`
		// so the SPF-rule dedup path (see matchProviderForSpfInclude) handles it.
		name: 'Trellix Email Security',
		role: 'sending',
		patterns: {
			spf: /(^|\.)fireeyecloud\.com$/i,
		},
		signal: 'spf:fireeyecloud.com',
	},
	{
		// Oracle Cloud Email (formerly Oracle Cloud Infrastructure Email Delivery).
		// Detected via SPF selector subdomains under `oraclecloud.com`: the customer
		// SPF includes `spf_c.oraclecloud.com`, which cascades through
		// `spf_s1.oraclecloud.com` and `spf_s2.oraclecloud.com`. Without this rule
		// the raw selector hostname surfaces as a third-party row instead of the
		// canonical provider name. SPF-only (no fixed MX hostnames); the SPF-rule
		// dedup path (matchProviderForSpfInclude) handles it.
		// Catalog gap surfaced 2026-05-28 (post-v3.3.14 fact-check round).
		name: 'Oracle Cloud Email',
		role: 'sending',
		patterns: {
			spf: /(_c|_s\d+)\.oraclecloud\.com$/i,
		},
		signal: 'spf:oraclecloud.com',
	},
	{
		// Foundation DNS. Multi-TLD vendor — the same authoritative DNS service is
		// served from `*.foundationdns.com`, `*.foundationdns.net`, and
		// `*.foundationdns.org`. Without this collapse a single zone using all three
		// sibling TLDs (eg. `gold.foundationdns.{com,net,org}`) lists as three
		// separate dns-hosting rows. Same drift class as UltraDNS / NS1 / Dyn /
		// Google Cloud DNS — catalog gap surfaced 2026-05-28.
		name: 'Foundation DNS',
		role: 'dns',
		patterns: {
			ns: /\.foundationdns\.(com|net|org)$/i,
		},
		signal: 'ns:foundationdns',
	},
	{
		// Google Cloud DNS. Authoritative DNS for projects on GCP — NS hosts are
		// `ns-cloud-{a,b,c,d}{1,2,3,4}.googledomains.com`. Without this rule the
		// raw `googledomains.com` (trailing-label heuristic) surfaces instead of
		// the canonical provider name. Distinct from Google Workspace (mail) and
		// Google Domains registrar (now sunset, transferred to Squarespace).
		// Catalog gap surfaced 2026-05-28 (post-v3.3.15 fact-check round).
		name: 'Google Cloud DNS',
		role: 'dns',
		patterns: {
			ns: /\.googledomains\.com$/i,
		},
		signal: 'ns:googledomains',
	},
	{
		// HubSpot transactional/marketing email. Customer SPF includes a per-tenant
		// selector under `*.hubspotemail.net` (eg. `21894833.spf06.hubspotemail.net`).
		// Without this rule the raw selector hostname surfaces as a third-party row.
		// SPF-only (no fixed MX hostnames); the SPF-rule dedup path
		// (matchProviderForSpfInclude) handles it. Distinct from the older
		// self-wrapper pattern `hubspot.spf-records.<customer>.com` which v3.3.13
		// self-SPF dedup already collapses.
		// Catalog gap surfaced 2026-05-28 (post-v3.3.15 fact-check round).
		name: 'HubSpot',
		role: 'sending',
		patterns: {
			spf: /\.hubspotemail\.net$/i,
		},
		signal: 'spf:hubspot',
	},
	{
		// Mailchimp Transactional (formerly Mandrill). Customer SPF includes
		// `servers.mcsv.net` — the `mcsv.net` domain hosts Mailchimp's transactional
		// email infrastructure. Distinct from Mailchimp marketing (which uses
		// `mailchimp.com` / `mail.mailchimp.com` and has no rule here yet). Labelled
		// "Mailchimp Transactional" to disambiguate from the marketing product.
		// Catalog gap surfaced 2026-05-28 (post-v3.3.15 fact-check round).
		name: 'Mailchimp Transactional',
		role: 'sending',
		patterns: {
			spf: /\.mcsv\.net$/i,
		},
		signal: 'spf:mailchimp-transactional',
	},
	{
		// Salesforce (Sales Cloud / Service Cloud / Marketing Cloud). Customer SPF
		// includes `_spf.salesforce.com`. Pattern is anchored to a leading `.` or
		// start-of-string so it cannot accidentally collapse Pardot endpoints
		// (`et._spf.pardot.com`) — those continue to surface separately. Distinct
		// from Pardot (no Pardot rule today; raw `et._spf.pardot.com` surfaces).
		// Catalog gap surfaced 2026-05-28 (post-v3.3.15 fact-check round).
		name: 'Salesforce',
		role: 'sending',
		patterns: {
			spf: /(^|\.)salesforce\.com$/i,
		},
		signal: 'spf:salesforce',
	},
];

/**
 * Resolve a single SPF include hostname to a known provider name, if any.
 * Uses the same DETECTION_RULES as detectProviders so the two paths can't drift.
 * Returns null when no rule's spf pattern matches.
 */
export function matchProviderForSpfInclude(spfInclude: string): string | null {
	for (const rule of DETECTION_RULES) {
		if (rule.patterns.spf && rule.patterns.spf.test(spfInclude)) {
			return rule.name;
		}
	}
	return null;
}

/**
 * Resolve a single NS host to a known provider name, if any.
 * Uses the same DETECTION_RULES as detectProviders so the two paths can't drift.
 * Returns null when no rule's ns pattern matches.
 *
 * Replaces the previous substring-via-signal heuristic in map-supply-chain,
 * which silently broke for multi-TLD vendors whose two TLDs share no common
 * substring (eg. NS1: `*.ns1.com` + `*.nsone.net`).
 */
export function matchProviderForNsHost(nsHost: string): string | null {
	for (const rule of DETECTION_RULES) {
		if (rule.patterns.ns && rule.patterns.ns.test(nsHost)) {
			return rule.name;
		}
	}
	return null;
}

/**
 * Resolve a single MX exchange host to a known provider name, if any.
 * Uses the same DETECTION_RULES as detectProviders so the two paths can't drift.
 * Returns null when no rule's mx pattern matches.
 *
 * Mirrors matchProviderForSpfInclude / matchProviderForNsHost so map-supply-chain
 * can attribute an email-RECEIVING provider from MX independently of the SPF
 * (email-sending) signal — the two are distinct dependencies (a domain can
 * receive via Mimecast/Proofpoint while sending via M365, or vice versa).
 */
export function matchProviderForMxHost(mxHost: string): string | null {
	for (const rule of DETECTION_RULES) {
		if (rule.patterns.mx && rule.patterns.mx.test(mxHost)) {
			return rule.name;
		}
	}
	return null;
}

/**
 * Detect infrastructure providers from DNS signals.
 * Returns deduplicated list of DetectedProvider (one entry per provider name).
 */
export function detectProviders(input: ProviderDetectionInput): DetectedProvider[] {
	const seen = new Set<string>();
	const results: DetectedProvider[] = [];

	for (const rule of DETECTION_RULES) {
		if (seen.has(rule.name)) continue;

		let matched = false;

		if (rule.patterns.mx) {
			const pattern = rule.patterns.mx;
			if (input.mxHosts.some((h) => pattern.test(h))) {
				matched = true;
			}
		}

		if (!matched && rule.patterns.spf) {
			const pattern = rule.patterns.spf;
			if (input.spfIncludes.some((s) => pattern.test(s))) {
				matched = true;
			}
		}

		if (!matched && rule.patterns.ns) {
			const pattern = rule.patterns.ns;
			if (input.nsHosts.some((n) => pattern.test(n))) {
				matched = true;
			}
		}

		if (matched) {
			seen.add(rule.name);
			results.push({ name: rule.name, role: rule.role, signal: rule.signal });
		}
	}

	return results;
}

type FixGuideMap = Record<string, Partial<Record<FixAction, (params: FixStepParams) => string[]>>>;

/** Provider-specific fix guides mapping provider name → action → step generator. */
const FIX_GUIDES: FixGuideMap = {
	'Google Workspace': {
		add_txt: (params) => [
			'Sign in to your domain registrar or DNS provider.',
			`Add a new TXT record with name "${params.name ?? '@'}" and value: ${params.value ?? '(see recommendation)'}`,
			'Save the record and allow up to 48 hours for DNS propagation.',
			'Verify in Google Admin console (Apps → Google Workspace → Gmail → Authenticate email) if applicable.',
		],
		enable_dkim: () => [
			'Sign in to Google Admin console (admin.google.com).',
			'Navigate to Apps → Google Workspace → Gmail → Authenticate email.',
			'Select your domain and click "Generate new record".',
			'Copy the DKIM TXT record and add it to your DNS at the selector subdomain shown.',
			'Return to Google Admin and click "Start authentication".',
			'Allow up to 48 hours for DNS propagation before DKIM signing activates.',
		],
		add_mta_sts: () => [
			'Create a file at https://mta-sts.<yourdomain>/.well-known/mta-sts.txt with the MTA-STS policy.',
			'Add a TXT record: name "_mta-sts", value "v=STSv1; id=<timestamp>".',
			'Ensure the mta-sts subdomain is served over HTTPS with a valid certificate.',
			'Google Workspace enforces MTA-STS for inbound mail automatically when the policy is present.',
		],
	},
	'Microsoft 365': {
		add_txt: (params) => [
			'Sign in to your domain registrar or DNS provider (not Microsoft 365 admin).',
			`Add a new TXT record with name "${params.name ?? '@'}" and value: ${params.value ?? '(see recommendation)'}`,
			'Save the record and allow up to 48 hours for DNS propagation.',
			'In Microsoft 365 admin center, verify the domain is still configured correctly under Settings → Domains.',
		],
		enable_dkim: () => [
			'Sign in to Microsoft 365 Defender (security.microsoft.com).',
			'Navigate to Email & Collaboration → Policies & Rules → Threat Policies → Email Authentication Settings.',
			'Select your domain under the DKIM tab.',
			'Click "Enable" — Microsoft 365 will instruct you to add two CNAME records to your DNS.',
			'Add the CNAME records at your DNS provider: selector1._domainkey and selector2._domainkey.',
			'Return to the DKIM tab and click "Enable" again after DNS propagates (up to 48 hours).',
		],
		add_mta_sts: () => [
			'Create a file at https://mta-sts.<yourdomain>/.well-known/mta-sts.txt with the MTA-STS policy.',
			'Add a TXT record: name "_mta-sts", value "v=STSv1; id=<timestamp>".',
			'Ensure the mta-sts subdomain resolves and is served over HTTPS.',
			'Microsoft 365 supports MTA-STS enforcement; inbound connections will use TLS when policy is present.',
		],
	},
	Cloudflare: {
		add_txt: (params) => [
			'Sign in to the Cloudflare dashboard (dash.cloudflare.com).',
			'Select your account and the relevant domain.',
			'Navigate to DNS → Records.',
			'Click "Add record", select type TXT.',
			`Set the Name field to "${params.name ?? '@'}" and the Content to: ${params.value ?? '(see recommendation)'}`,
			'Set TTL to Auto and click Save.',
			'Changes propagate within seconds on Cloudflare\'s network.',
		],
		enable_dnssec: () => [
			'Sign in to the Cloudflare dashboard (dash.cloudflare.com).',
			'Select your account and the relevant domain.',
			'Navigate to DNS → Settings.',
			'Under DNSSEC, click "Enable DNSSEC".',
			'Copy the DS record details shown (Key Tag, Algorithm, Digest Type, Digest).',
			'Add the DS record at your domain registrar to complete the chain of trust.',
			'Cloudflare will automatically sign all DNS records once DNSSEC is enabled.',
		],
	},
	'AWS Route 53': {
		add_txt: (params) => [
			'Sign in to the AWS Management Console.',
			'Navigate to Route 53 → Hosted Zones and select your domain.',
			'Click "Create record".',
			'Select record type TXT, set the record name to "${params.name ?? \'@\'}".',
			`Set the value to: "${params.value ?? '(see recommendation)'}"`,
			'Set TTL (e.g. 300 seconds) and click "Create records".',
			'Propagation typically completes within 60 seconds within AWS.',
		],
		enable_dnssec: () => [
			'Sign in to the AWS Management Console.',
			'Navigate to Route 53 → Hosted Zones and select your domain.',
			'Click the "DNSSEC signing" tab.',
			'Click "Enable DNSSEC signing" and follow the prompts to create a KSK (Key Signing Key).',
			'After signing is enabled, establish the chain of trust: copy the DS record shown.',
			'Add the DS record at your domain registrar.',
			'AWS Route 53 will automatically sign all records once DNSSEC is enabled.',
		],
	},
	Namecheap: {
		add_txt: (params) => [
			'Sign in to your Namecheap account.',
			'Navigate to Domain List and click "Manage" next to your domain.',
			'Go to the Advanced DNS tab.',
			'Click "Add New Record" and select type TXT Record.',
			`Set Host to "${params.name ?? '@'}" and Value to: ${params.value ?? '(see recommendation)'}`,
			'Set TTL to Automatic and click the green checkmark to save.',
		],
	},
	GoDaddy: {
		add_txt: (params) => [
			'Sign in to your GoDaddy account.',
			'Navigate to My Products → DNS (next to your domain).',
			'Click "Add" under the DNS Records section.',
			'Select type TXT.',
			`Set Name to "${params.name ?? '@'}" and Value to: ${params.value ?? '(see recommendation)'}`,
			'Set TTL to 1 Hour (or default) and click Save.',
		],
	},
	Fastmail: {
		add_txt: (params) => [
			'Sign in to the Fastmail control panel.',
			'Navigate to Settings → Domains and select your domain.',
			'Go to the DNS records section.',
			`Add a TXT record with name "${params.name ?? '@'}" and value: ${params.value ?? '(see recommendation)'}`,
			'Save and allow up to 48 hours for propagation.',
		],
		enable_dkim: () => [
			'Sign in to the Fastmail control panel.',
			'Navigate to Settings → Domains and select your domain.',
			'Fastmail automatically configures DKIM for hosted domains.',
			'Verify DKIM is enabled under the domain\'s email settings.',
			'If using an external DNS provider, copy the DKIM CNAME or TXT records shown and add them at your DNS host.',
		],
	},
	Mimecast: {
		add_txt: (params) => [
			'Log in to the Mimecast Administration Console.',
			'Navigate to Administration → Domain Management → Domains.',
			'Select your domain and go to the DNS Authentication tab.',
			`Add a TXT record with name "${params.name ?? '@'}" and value: ${params.value ?? '(see recommendation)'} at your external DNS provider.`,
			'Mimecast does not host DNS — you must add the record at your registrar or DNS provider.',
		],
		enable_dkim: () => [
			'Log in to the Mimecast Administration Console.',
			'Navigate to Administration → Gateway → Policies → DNS Authentication - Outbound.',
			'Create or edit a DKIM policy for your domain.',
			'Mimecast will generate a DKIM selector and public key.',
			'Add the provided DKIM TXT record to your external DNS provider.',
			'Activate the policy in Mimecast once DNS has propagated.',
		],
	},
	Proofpoint: {
		enable_dkim: () => [
			'Log in to the Proofpoint Essentials or Protection Server console.',
			'Navigate to Email Authentication → DKIM.',
			'Add your domain and generate a DKIM key pair.',
			'Copy the provided DKIM TXT record and add it to your external DNS provider.',
			'Enable signing in the Proofpoint console after DNS propagates.',
		],
	},
	'AWS SES': {
		enable_dkim: () => [
			'Sign in to the AWS Management Console.',
			'Navigate to Amazon SES → Verified Identities.',
			'Select your domain identity.',
			'Under the Authentication tab, find the DKIM section.',
			'SES uses Easy DKIM (3 CNAME records) — copy the provided CNAME values.',
			'Add the three CNAME records to your DNS provider.',
			'Return to SES; DKIM status will show "Verified" after propagation (up to 72 hours).',
		],
	},
	SendGrid: {
		enable_dkim: () => [
			'Sign in to your SendGrid account.',
			'Navigate to Settings → Sender Authentication.',
			'Click "Authenticate Your Domain" and follow the wizard.',
			'SendGrid provides CNAME records for domain authentication (which includes DKIM).',
			'Add the provided CNAME records to your DNS provider.',
			'Return to SendGrid and click "Verify" once DNS has propagated.',
		],
	},
	Mailgun: {
		enable_dkim: () => [
			'Log in to your Mailgun account.',
			'Navigate to Sending → Domains and select your domain.',
			'Click "DNS Records" to view the required TXT and CNAME records.',
			'Add the DKIM TXT record (starting with "v=DKIM1") to your DNS provider.',
			'Also add the SPF TXT record if not already present.',
			'Click "Verify DNS Settings" in Mailgun after DNS propagates.',
		],
	},
	Postmark: {
		enable_dkim: () => [
			'Log in to your Postmark account.',
			'Navigate to Sender Signatures or your sending domain.',
			'Click "DKIM Settings" to view the required TXT record.',
			'Add the DKIM TXT record to your DNS provider at the provided selector subdomain.',
			'Postmark will automatically detect the record once DNS propagates.',
		],
	},
};

/**
 * Returns provider-specific fix steps for a given action, or null if the provider is unknown.
 *
 * @param providerName - The provider name (e.g. 'Cloudflare', 'Google Workspace')
 * @param action - The fix action to perform
 * @param params - Optional parameters such as record name/value
 * @returns Array of step strings, or null if provider or action has no guide
 */
export function getProviderFixSteps(providerName: string, action: FixAction, params: FixStepParams): string[] | null {
	const guide = FIX_GUIDES[providerName];
	if (!guide) return null;

	const stepsFn = guide[action];
	if (!stepsFn) return null;

	return stepsFn(params);
}
