// SPDX-License-Identifier: BUSL-1.1

/**
 * Common DKIM selectors used by major email providers.
 *
 * Extracted from check-dkim.ts so the probe list can grow without churning
 * the check implementation. Entries are roughly ordered by population:
 * generic defaults → big-4 providers → ESPs → niche.
 *
 * Empirical sourcing notes (recheck if regressions appear):
 * - proton.me / proton.ch use `protonmail`, `protonmail2`, `protonmail3`.
 *   `dig +short TXT protonmail._domainkey.proton.me` returns a CNAME chain
 *   into *.domains.proton.ch; the final TXT is v=DKIM1; k=rsa; p=...
 * - Stripe (and many other SendGrid tenants) use `s1`, `s2` delegated via
 *   CNAME to *.domainkey.*.sendgrid.net (records lack v=DKIM1 — see
 *   dkim-saas-attribution.ts).
 * - Mandrill uses `mandrill`; MailerSend uses `mte1`/`mte2`; SparkPost
 *   ships `scph<yyyymm>` rotated keys; Klaviyo/HubSpot default to
 *   `dkim1`/`dkim2`.
 */
export const COMMON_DKIM_SELECTORS: readonly string[] = [
	// Generic defaults
	'default',
	'mail',
	'dkim',
	'dkim1',
	'dkim2',
	'k1',
	's1',
	's2',
	// Google Workspace
	'google',
	'20230601',
	// Microsoft 365
	'selector1',
	'selector2',
	// Amazon SES
	'amazonses',
	// Zoho Mail
	'zoho',
	// Cloudflare Email Routing
	'cf2024-1',
	// Proton Mail
	'protonmail',
	'protonmail2',
	'protonmail3',
	// Mandrill (Mailchimp Transactional)
	'mandrill',
	// MailerSend
	'mte1',
	'mte2',
	// SparkPost (rotating monthly; common recent vintages)
	'scph1220',
	'scph0322',
	// Postmark
	'pm',
];
