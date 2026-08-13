// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF Trust Surface Analysis.
 * Identifies when SPF include: or redirect= directives delegate sending
 * authority to multi-tenant SaaS platforms, expanding the domain's trust surface.
 *
 * WORKER-LAYER AUGMENTATION (issue #566): this module is intentionally NOT dead code.
 * The `check_spf` tool delegates scoring/findings to the parity-locked core package
 * `@blackveil/dns-checks`; `check-spf.ts` runs this copy as a post-processor that
 * REPLACES the core-produced trust-surface findings while leaving the score untouched.
 *
 * ⚠️ AS OF #572 PART 2 THE TWO COPIES ARE BEHAVIOURALLY IDENTICAL — the worker no
 * longer leads the core. Its catalog lead was closed in 3.42.0 (Mailjet, #572 part 1)
 * and the generic "unrecognized shared sender" heuristic below was adopted core-side in
 * part 2, so the core now COUNTS unrecognized senders toward the trust-surface total
 * exactly as this file does. There is therefore no worker-only recognition left to
 * augment: this copy survives only until the seam is deleted outright. Any edit here
 * MUST be mirrored byte-for-byte into
 * `packages/dns-checks/src/checks/spf-trust-surface.ts` (and vice versa) — divergence
 * silently splits direct package consumers (bv-web-prod) from the worker, which is the
 * #572 failure mode. Parity is audited by
 * `test/audits/spf-trust-surface-catalog-parity.audit.test.ts`.
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
	['spf.protection.outlook.com', { name: 'Microsoft 365', risk: 'Any M365 tenant can send as your domain without DKIM/DMARC enforcement' }],
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
	// #566: Mailjet — multi-tenant ESP. Registrable key so `spf.mailjet.com` and any
	// Mailjet sub-host match via the endsWith('.'+key) rule. Also in the CORE catalog
	// since 3.42.0 (#572 part 1) — the two are parity-audited.
	['mailjet.com', { name: 'Mailjet', risk: 'Any Mailjet customer can send as your domain' }],
]);

/**
 * Heuristic for an UNRECOGNIZED but broad multi-tenant sending host (issue #566):
 * a hostname carrying an `spf` / `_spf` / `spfNN` label is an SPF-delegation endpoint
 * for a shared platform, even when the specific provider is not in the catalog above.
 * First-party includes like `mail.mycompany.com` deliberately do NOT match, so they
 * are never flagged as shared senders.
 */
const GENERIC_SHARED_SENDER_RE = /(^|\.)_?spf\d*\./i;

function isGenericSharedSender(domain: string): boolean {
	return GENERIC_SHARED_SENDER_RE.test(domain.toLowerCase());
}

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
 * Describe WHAT actually corroborated the exposure, derived from the DMARC context the
 * caller supplied, so the prose matches the `dmarcPolicy` / `dmarcAlignmentMode` metadata
 * carried on the same finding.
 *
 * An ENFORCING policy (`p=quarantine` or `p=reject` at `pct=100`) must NEVER be described
 * as "weak DMARC enforcement": the same scan reports that domain as "DMARC enforcing" in
 * its scoring signals, and `p=quarantine` is this product's own BIMI eligibility bar, so
 * enforcement-based wording made one report contradict itself. When the policy enforces,
 * the corroborating signal is the RELAXED ALIGNMENT (or a partial `pct=`) — say that.
 * Enforcement wording is reserved for `p=none` and for an absent DMARC record.
 *
 * ⚠️ DUPLICATED FILE: this module exists twice — core
 * `packages/dns-checks/src/checks/spf-trust-surface.ts` and worker
 * `src/tools/spf-trust-surface.ts`. Keep this function byte-identical in both copies;
 * a change to one alone diverges direct package consumers (bv-web-prod) from the worker.
 */
function describeCorroboration(context: TrustSurfaceContext): string {
	const rawPolicy = (context.dmarcPolicy ?? '').toLowerCase().trim();
	const basePolicy = rawPolicy.split(';')[0].trim();
	const pct = /pct=(\d+)/.exec(rawPolicy)?.[1];
	const enforcingPolicy = basePolicy === 'quarantine' || basePolicy === 'reject';
	const alignmentRelaxed = context.dmarcAlignmentMode === 'relaxed';

	const signals: string[] = [];
	if (basePolicy === '' || basePolicy === 'missing') {
		signals.push('No DMARC record is published');
	} else if (!enforcingPolicy) {
		signals.push(`DMARC is monitor-only (p=${basePolicy}) and is not enforcing`);
	} else if (pct !== undefined && pct !== '100') {
		signals.push(`DMARC enforces (p=${basePolicy}) on only ${pct}% of mail`);
	}
	if (alignmentRelaxed) {
		signals.push(
			enforcingPolicy
				? `DMARC alignment is relaxed, which lets mail from any subdomain of your organizational domain align under p=${basePolicy}`
				: 'DMARC alignment is relaxed',
		);
	}
	if (signals.length === 0) {
		signals.push('The current DMARC posture does not fully constrain this delegation');
	}

	return `${signals.join('; ')} — a provider misconfiguration or abuse case would therefore be more likely to pass policy checks.`;
}

/**
 * Analyze an SPF record for trust surface exposure from multi-tenant SaaS platform includes.
 * Returns findings for each shared platform detected, plus a summary finding when multiple are found.
 */
export function analyzeTrustSurface(spfRecord: string, context: TrustSurfaceContext = {}): Finding[] {
	const findings: Finding[] = [];
	const domains = extractIncludeAndRedirectDomains(spfRecord);
	const delegated: { name: string; includeDomain: string; recognized: boolean }[] = [];
	const corroboratedByWeakDmarc = context.corroboratedByWeakDmarc === true;
	/**
	 * The per-platform findings are DELIBERATELY informational — ALWAYS, corroborated or not.
	 *
	 * ⚠️ DOUBLE-COUNT REGRESSION GUARD (issue #637). This previously graded each matched
	 * platform `medium` (−15) whenever weak DMARC corroborated, AND ALSO emitted the aggregate
	 * "SPF trust surface: N shared platforms" finding at `high` (−25) below. Both describe the
	 * SAME condition — sending authority delegated to multi-tenant platforms — so the penalty
	 * was charged once per platform PLUS once for the set. github.com paid 6 × −15 = −90 on top
	 * of the −25 aggregate; the per-platform stack alone floors the category, so a valid,
	 * working SPF record scored 0, indistinguishable from publishing no SPF at all. SPF is one
	 * of only four categories the 1,000-domain corpus found to actually discriminate, so a
	 * check that cannot separate "complex sender profile" from "no SPF" is broken.
	 *
	 * The fix keeps exactly ONE scored signal for this condition: the aggregate below, whose
	 * severity still escalates with corroboration and whose title / `platformCount` scale with
	 * the size of the trust surface — the real, proportionate signal. This mirrors what DKIM
	 * already does for duplicate selector-probe key-strength findings ("Consolidated N
	 * duplicate selector-probe key-strength finding(s) to reduce repeated penalty for identical
	 * key profiles across selectors").
	 *
	 * The per-platform findings REMAIN PRESENT and fully detailed — same titles, same
	 * `describeCorroboration()` prose, same `dmarcCorroborated` / `dmarcPolicy` /
	 * `dmarcAlignmentMode` metadata — so a customer can still see exactly which platforms are
	 * authorized and why each one matters. Only the repeated penalty is gone. Nothing about the
	 * elevation/corroboration rule, any severity threshold, weight, tier, grade band or profile
	 * changed, and `SEVERITY_PENALTIES` is untouched.
	 *
	 * ⚠️ DUPLICATED FILE: mirror any change here in the other copy — core
	 * `packages/dns-checks/src/checks/spf-trust-surface.ts` and worker
	 * `src/tools/spf-trust-surface.ts`. Direct package consumers (bv-web-prod) see only the
	 * core copy; parity is audited by
	 * `test/audits/spf-trust-surface-catalog-parity.audit.test.ts`.
	 */
	const findingSeverity = 'info' as const;
	const summarySeverity = corroboratedByWeakDmarc ? 'high' : 'info';
	const detailSuffix = corroboratedByWeakDmarc
		? describeCorroboration(context)
		: 'This is common and not inherently a misconfiguration, but it expands the sending infrastructure you rely on. The risk becomes more material when DMARC enforcement and alignment are weak.';

	for (const domain of domains) {
		const result = matchPlatform(domain);
		if (result) {
			delegated.push({ name: result.info.name, includeDomain: domain, recognized: true });
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
		} else if (isGenericSharedSender(domain)) {
			// #566: broaden the trust surface to unrecognized-but-broad shared senders so
			// an ESP the catalog misses still counts. Named as the include host, not a brand.
			delegated.push({ name: 'unrecognized shared sender', includeDomain: domain, recognized: false });
			findings.push(
				createFinding(
					'spf',
					`SPF delegates to shared sending platform (unrecognized): ${domain}`,
					findingSeverity,
					`SPF include:${domain} delegates sending to an external multi-tenant-style platform that is not in the recognized ESP catalog. It still widens your trust surface even though the specific provider is not named. ${detailSuffix}`,
					{
						trustSurface: true,
						platform: 'unrecognized shared sender',
						includeDomain: domain,
						recognized: false,
						dmarcCorroborated: corroboratedByWeakDmarc,
						...(context.dmarcPolicy ? { dmarcPolicy: context.dmarcPolicy } : {}),
						...(context.dmarcAlignmentMode ? { dmarcAlignmentMode: context.dmarcAlignmentMode } : {}),
					},
				),
			);
		}
	}

	if (delegated.length > 1) {
		const platformNames = delegated.map((p) => (p.recognized ? p.name : `${p.includeDomain} (unrecognized)`)).join(', ');
		findings.push(
			createFinding(
				'spf',
				`SPF trust surface: ${delegated.length} shared platforms`,
				summarySeverity,
				`SPF record delegates sending authority to ${delegated.length} multi-tenant platforms (${platformNames}). Audit each include to confirm it is still needed, configure provider-specific DKIM, and keep DMARC enforcement and alignment strong across every authorized sender.`,
				{
					trustSurface: true,
					platformCount: delegated.length,
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
