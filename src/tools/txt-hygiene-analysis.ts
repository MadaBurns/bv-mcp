// SPDX-License-Identifier: BUSL-1.1

/**
 * Shared TXT hygiene analysis constants and types.
 *
 * Exported for use by check-txt-hygiene.ts and map-supply-chain.ts.
 */

// ─── Verification pattern definitions ────────────────────────────────────────

export type VerificationCategory = 'search_engine' | 'identity_auth' | 'collaboration' | 'security' | 'marketing' | 'infrastructure' | 'email_auth';

export interface VerificationPattern {
	prefix: string;
	service: string;
	category: VerificationCategory;
	jurisdiction?: string;
}

export const VERIFICATION_PATTERNS: VerificationPattern[] = [
	// Search engines
	{ prefix: 'google-site-verification=', service: 'Google Search Console', category: 'search_engine' },
	{ prefix: 'yandex-verification:', service: 'Yandex', category: 'search_engine', jurisdiction: 'RU' },
	{ prefix: 'msvalidate.01=', service: 'Bing', category: 'search_engine' },
	{ prefix: 'baidu-site-verification=', service: 'Baidu', category: 'search_engine', jurisdiction: 'CN' },
	{ prefix: 'naver-site-verification=', service: 'Naver', category: 'search_engine' },

	// Identity & auth
	{ prefix: 'MS=', service: 'Microsoft 365', category: 'identity_auth' },
	{ prefix: 'apple-domain-verification=', service: 'Apple', category: 'identity_auth' },
	{ prefix: 'facebook-domain-verification=', service: 'Facebook', category: 'identity_auth' },
	{ prefix: 'atlassian-domain-verification=', service: 'Atlassian', category: 'identity_auth' },
	{ prefix: 'adobe-idp-site-verification=', service: 'Adobe', category: 'identity_auth' },
	{ prefix: 'docusign=', service: 'DocuSign', category: 'identity_auth' },
	{ prefix: 'cisco-ci-domain-verification=', service: 'Cisco', category: 'identity_auth' },
	{ prefix: 'teamviewer-sso-verification=', service: 'TeamViewer', category: 'identity_auth' },
	{ prefix: 'zoom-domain-verification=', service: 'Zoom', category: 'identity_auth' },

	// Collaboration
	{ prefix: 'miro-verification=', service: 'Miro', category: 'collaboration' },
	{ prefix: 'figma-domain-verification=', service: 'Figma', category: 'collaboration' },
	{ prefix: 'slack-domain-verification=', service: 'Slack', category: 'collaboration' },
	{ prefix: 'asana-domain-verification=', service: 'Asana', category: 'collaboration' },
	{ prefix: 'notion-domain-verification=', service: 'Notion', category: 'collaboration' },
	{ prefix: 'canva-domain-verification=', service: 'Canva', category: 'collaboration' },
	{ prefix: 'monday-domain-verification=', service: 'Monday.com', category: 'collaboration' },

	// Security
	{ prefix: 'onetrust-domain-verification=', service: 'OneTrust', category: 'security' },
	{ prefix: 'knowbe4-site-verification=', service: 'KnowBe4', category: 'security' },
	{ prefix: 'sophos-domain-verification=', service: 'Sophos', category: 'security' },
	{ prefix: 'crowdstrike-domain-verification=', service: 'CrowdStrike', category: 'security' },

	// Marketing
	{ prefix: 'google-gws-recovery-domain-verification=', service: 'Google Workspace Recovery', category: 'marketing' },
	{ prefix: 'hubspot-developer-verification=', service: 'HubSpot', category: 'marketing' },
	{ prefix: 'pardot_', service: 'Salesforce Pardot', category: 'marketing' },
	{ prefix: 'mailchimp-domain-verification=', service: 'Mailchimp', category: 'marketing' },
	{ prefix: 'sendgrid-verification=', service: 'SendGrid', category: 'marketing' },

	// Infrastructure
	{ prefix: 'barco-verification=', service: 'Barco', category: 'infrastructure' },
	{ prefix: 'TrustedForDomainSharing=', service: 'TrustedForDomainSharing', category: 'infrastructure' },
	{ prefix: 'have-i-been-pwned-verification=', service: 'Have I Been Pwned', category: 'infrastructure' },
	{ prefix: 'stripe-verification=', service: 'Stripe', category: 'infrastructure' },
	{ prefix: 'globalsign-domain-verification=', service: 'GlobalSign', category: 'infrastructure' },
	{ prefix: '_github-pages-challenge-', service: 'GitHub Pages', category: 'infrastructure' },
	{ prefix: '_gitlab-pages-verification-code', service: 'GitLab Pages', category: 'infrastructure' },
	{ prefix: 'loaderio-', service: 'Loader.io', category: 'infrastructure' },

	// Email auth (v=spf1 is expected and not flagged as verification)
	{ prefix: 'v=DMARC1', service: 'DMARC', category: 'email_auth' },
];

// ─── SPF cross-reference for staleness detection ─────────────────────────────

export const SERVICE_SPF_DOMAINS: Record<string, string[]> = {
	'Google Search Console': ['_spf.google.com', 'google.com'],
	'Microsoft 365': ['spf.protection.outlook.com', 'outlook.com'],
	'SendGrid': ['sendgrid.net'],
	'Mailchimp': ['mandrillapp.com', 'mailchimp.com'],
	'HubSpot': ['hubspotemail.net'],
	'Salesforce Pardot': ['salesforce.com'],
	'Zoho': ['zoho.com', 'zoho.eu'],
	'Freshdesk': ['freshdesk.com'],
	'Zendesk': ['zendesk.com'],
};
