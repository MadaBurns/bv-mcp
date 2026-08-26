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
 *   ships `scph<yyyymm>` rotated keys.
 * - Klaviyo uses `kl`/`kl2` and HubSpot uses `hs1`/`hs2` — NOT `dkim1`/`dkim2`
 *   as this comment previously claimed. Corrected 2026-08-06 from live DoH
 *   probes (glossier.com, hubspot.com); the mistaken claim is why the HubSpot
 *   entry in dkim-saas-attribution.ts had been unreachable.
 *
 * Every entry below is backed by an observed key on a real domain. Do NOT add
 * speculative selectors: the check fans out with Promise.all over the WHOLE
 * list on every scan of every domain, under an 8s per-check timeout, and a
 * check that times out is excluded from the score entirely — an over-long list
 * degrades into no DKIM signal at all, which is worse than the false negative
 * it was meant to fix. Provider-specific tails belong behind a second stage
 * conditioned on MX/SPF, not in this list.
 *
 * Selectors that CANNOT be enumerated, and must not be attempted here:
 * - Amazon SES Easy DKIM — three random 32-char tokens per domain.
 * - Microsoft 365 `selector1-<domain>` — that is the CNAME *target* under
 *   <tenant>.onmicrosoft.com, not a selector on the customer domain.
 * - Date-stamped selectors (20161025, 20120113, …) — per-key-generation names
 *   on the provider's own domain; unbounded search space.
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
	// Resend (provider-published direct TXT, no v= tag)
	'resend',
	// --- Added 2026-08-06, each confirmed by a live DoH probe (evidence domain
	// in parentheses). Regression-guarded by dkim-selector-coverage.test.ts. ---
	// Fastmail (fastmail.com published NOTHING at any pre-existing selector —
	// a total false negative for every Fastmail-hosted domain)
	'fm1',
	'fm2',
	'fm3',
	// Mailchimp rotation beyond k1 (mailchimp.com → dkim2/dkim3.mcsv.net)
	'k2',
	'k3',
	// HubSpot (hubspot.com, mailgun.com → <domain>.hs01a.dkim.hubspotemail.net)
	'hs1',
	'hs2',
	// Klaviyo (glossier.com → kl.domainkey.*.sendgrid.net — SendGrid holds the key)
	'kl',
	'kl2',
	// Mailgun (mailgun.com → dkim.mailgun.net; `pic` observed on hubspot.com)
	'mg',
	'pic',
	// SendGrid legacy selectors, still live (klaviyo.com, hubspot.com)
	'smtpapi',
	'm1',
	// Zendesk (mailchimp.com, klaviyo.com → zendesk[12]._domainkey.zendesk.com)
	'zendesk1',
	'zendesk2',
	// Mailjet (mailgun.com)
	'mailjet',
];
