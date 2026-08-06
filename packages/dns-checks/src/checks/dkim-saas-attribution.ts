// SPDX-License-Identifier: BUSL-1.1

/**
 * DKIM CNAME → SaaS provider attribution.
 *
 * When a domain's `<selector>._domainkey.<domain>` is a CNAME chain that
 * lands at a known transactional/email-SaaS hostname, the customer cannot
 * fix issues in the destination record (e.g. SendGrid omits v=DKIM1 by
 * design — RFC 6376 §3.6.1 tolerates this). Findings rooted in those
 * records should credit the SaaS provider and be reframed accordingly:
 *
 *   - "Missing DKIM version tag" → severity downgraded to `info`.
 *   - "Legacy 1024-bit RSA key"  → severity downgraded high → medium
 *     (customer can pressure the provider, but cannot rotate the key).
 *
 * Each pattern matches against the *terminal* CNAME target (or any link
 * in the CNAME chain, since some SaaS providers nest sub-CNAMEs).
 */

export interface DkimSaasAttribution {
	/** Human-readable provider name surfaced in finding metadata. */
	provider: string;
	/** Regex that matches the CNAME target hostname. */
	pattern: RegExp;
}

/**
 * Known SaaS CNAME patterns.
 * Order is not significant; the first regex to match wins.
 */
export const DKIM_SAAS_PATTERNS: readonly DkimSaasAttribution[] = [
	{ provider: 'SendGrid', pattern: /\.sendgrid\.net\.?$/i },
	// Mailgun delegates DKIM to dkim.mailgun.NET (measured on mailgun.com,
	// 2026-08-06). The pattern was `.org` only — mailgun.org is the sending
	// SUBDOMAIN customers are told to create, never the DKIM CNAME target — so
	// this never matched a real chain. Both are kept: .org costs nothing and
	// guards against a future change of target.
	//
	// `(^|\.)` is load-bearing. Attribution DOWNGRADES finding severity (a weak
	// 1024-bit key drops high → medium because only the provider can rotate it),
	// so an unanchored suffix would let an attacker-registered `evil-mailgun.net`
	// claim provider status and soften findings about a key it fully controls.
	{ provider: 'Mailgun', pattern: /(^|\.)mailgun\.(net|org)\.?$/i },
	{ provider: 'Postmark', pattern: /\.mtasv\.net\.?$/i },
	{ provider: 'Mailchimp', pattern: /\.(mcsv|mailchimpapp)\.net\.?$/i },
	{ provider: 'Amazon SES', pattern: /\.dkim\.amazonses\.com\.?$/i },
	{ provider: 'HubSpot', pattern: /\.hubspotemail\.net\.?$/i },
	{ provider: 'Klaviyo', pattern: /\.dkim\.klclick(\d+)?\.com\.?$/i },
	{ provider: 'Zoho', pattern: /\.zoho\.com\.?$/i },
	{ provider: 'Proton', pattern: /\.domains\.proton\.ch\.?$/i },
];

/**
 * Resolve a CNAME chain to its terminal SaaS provider, if recognised.
 * Accepts the entire chain (or a single hop) and returns the first
 * provider whose pattern matches any hop. Returns `undefined` when no
 * pattern matches — the caller should then treat the record as
 * customer-owned (no severity downgrade, no `delegatedTo` metadata).
 */
export function attributeCnameChain(chain: readonly string[]): string | undefined {
	for (const hop of chain) {
		for (const entry of DKIM_SAAS_PATTERNS) {
			if (entry.pattern.test(hop)) return entry.provider;
		}
	}
	return undefined;
}
