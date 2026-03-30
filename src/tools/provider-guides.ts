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
];

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
