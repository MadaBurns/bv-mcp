// SPDX-License-Identifier: BUSL-1.1
/**
 * Brand-audit classification module.
 *
 * Extracted from `scripts/brand-audit-brand-audit.spec.ts` so the bucketing logic
 * can be unit-tested independently from the live discovery/registrar I/O.
 *
 * Rule order (first match wins):
 *   1. Subdomain of target → consolidated, 'Organizational Subdomain'
 *   2. Strong deterministic ownership signal (DKIM, redirect, SPF, CNAME, recursive SAN, app/bounty declarations) → consolidated
 *   3. High-confidence dmarc_rua alone → consolidated
 *   4. Same normalized registrar family + ≥2 non-generated corroborating signals → consolidated
 *   5. Registrar source is redacted/notfound + no strong signals → indeterminate
 *   6. High confidence + mail-policy delegation on different registrar → shadowIt
 *   7. Medium confidence + no strong signals → indeterminate
 *   8. Low confidence + no strong signals → impersonation
 */

import { sameRegistrarFamily } from './registrar-identity';
import { clearsOwnershipGate, type BrandEvidenceObservation } from './brand-evidence';
import type { BrandDiscoveryTier } from './brand-discovery-tiers';

/**
 * Buckets emitted by the classifier.
 *
 * - `consolidated`, `shadowIt`, `indeterminate`, `impersonation` — legacy
 *   Tier-3 classifier outputs, unchanged.
 * - `impersonationSurface` — Task 8 (brand-discovery first-principles). Emitted
 *   ONLY when all observations on a candidate carry `tier === 4` (and no
 *   higher-provenance tier). Mutually exclusive with the Owned buckets:
 *   a domain with any tier 0/1/2 obs routes to `consolidated`, never to
 *   `impersonationSurface`. The invariant is pinned by an audit test.
 */
export type Bucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation' | 'impersonationSurface';
export type ConfidenceTier = 'high' | 'medium' | 'low';
export type RegistrarSource = 'rdap' | 'whois' | 'redacted' | 'notfound' | 'lookup_failed' | 'unknown';

export interface CandidateInput {
	domain: string;
	confidence: number;
	signals: string[];
	registrar: string;
	registrarIanaId?: string | null;
	registrarSource?: RegistrarSource;
	/** Registrant organization (from RDAP entities). null when redacted/unavailable. */
	registrant?: string | null;
	/**
	 * TXT verification tokens (e.g. `google-site-verification=...`, `MS=ms12345`)
	 * present on BOTH the candidate and the target. Sharing such a token is
	 * deterministic evidence that the same operator controls both zones — even
	 * when DNS / certs / DKIM are hosted disjointly (shopify, marketing SaaS).
	 * Empty/undefined → no shared TXT signal. Driver of the shadowIt branch.
	 */
	sharedTxtVerifications?: string[];
	/**
	 * Identifier for a mail platform when the candidate's MX RR set points at
	 * the same provider as the target (e.g. `google_workspace`, `m365`, `proofpoint`).
	 * null/undefined → no shared MX platform. Driver of the shadowIt branch.
	 */
	sharedMxPlatform?: string | null;
	/**
	 * Visual / string-similarity score against the target's effective domain
	 * label, in [0, 1]. Typosquat candidates have ≥0.85. Together with a
	 * registrar-family mismatch (and no shared infrastructure) this signals
	 * impersonation. Defaults to 0 (i.e. not a lookalike) when omitted.
	 */
	lookalikeScore?: number;
	/** True when the caller explicitly supplied this candidate for corroboration. */
	callerAsserted?: boolean;
	/** Optional normalized evidence observations used to apply shared ownership-gate policy. */
	evidenceObservations?: BrandEvidenceObservation[];
}

export interface TargetContext {
	domain: string;
	registrar: string;
	registrarFamily: string;
	registrarIanaId?: string | null;
	/** Target's registrant organization (for cross-reference matching). */
	registrant?: string | null;
}

export interface Classification {
	bucket: Bucket;
	confidenceTier: ConfidenceTier;
	note?: string;
	reasons: string[];
	/**
	 * Brand-discovery tier (Task 8). Set only when the candidate routed via the
	 * tier-aware short-circuit (i.e. at least one observation carried a `tier`
	 * field). Unset for legacy Tier-3 / classic-mode classification — the
	 * field's absence is the byte-identical signal that the legacy path ran.
	 */
	tier?: BrandDiscoveryTier;
}

/** Minimum specificityScore for a tier-1 observation to qualify as consolidated evidence. */
const TIER1_SPECIFICITY_THRESHOLD = 0.5;

/** Strong ownership signals — sharing any of these is near-deterministic operational control evidence. */
const STRONG_INFRA_SIGNALS = new Set([
	'san_recursive',
	'dkim_key_reuse',
	'http_redirect',
	'spf_include',
	'cname_alignment',
	'app_links',
	'bounty_scope',
]);

/** Confidence threshold above which dmarc_rua alone is consolidation evidence. */
const DMARC_CONSOLIDATION_THRESHOLD = 0.85;

/** Confidence threshold above which a candidate without strong signals counts as shadowIt rather than indeterminate. */
const SHADOW_IT_CONFIDENCE_THRESHOLD = 0.7;

/** Confidence threshold above which a candidate without strong signals is indeterminate rather than impersonation. */
const INDETERMINATE_CONFIDENCE_THRESHOLD = 0.5;

/**
 * Lookalike-similarity threshold at which a candidate is plausibly a typosquat.
 * Combined with a registrar-family mismatch and no shared-infra evidence, this
 * tips a candidate into the impersonation bucket. Calibrated against the
 * empirical BrandAudit brand-audit set (`reports/brand-audit-audit-results.json`).
 */
const IMPERSONATION_LOOKALIKE_THRESHOLD = 0.85;

/**
 * Normalize a registrant organization string for cross-domain comparison.
 * Strips common corporate suffixes (`Inc.`, `Ltd`, `LLC`, `Corp.`, etc.),
 * punctuation, and lowercases. Returns null for empty/null input.
 */
export function normalizeRegistrant(raw: string | null | undefined): string | null {
	if (!raw) return null;
	const cleaned = raw
		.toLowerCase()
		.trim()
		.replace(/\b(inc|incorporated|llc|l\.l\.c\.|ltd|limited|corp|corporation|co|company|gmbh|s\.?a\.?|s\.?l\.?|sas|sarl|plc|ag|bv|nv|kk|ab|oy|as)\.?$/g, '')
		.replace(/[.,'"‘’“”]/g, '')
		.replace(/\s+/g, ' ')
		.trim();
	return cleaned || null;
}

export function normalizeRegistrar(raw: string): string {
	if (!raw || raw === 'Unknown') return 'Unknown';
	const lower = raw.toLowerCase();
	if (/markmonitor/.test(lower)) return 'MarkMonitor';
	if (/com\s*laude|nom[ -]?iq/.test(lower)) return 'Com Laude';
	if (/safenames/.test(lower)) return 'SafeNames';
	// CSC Corporate Domains operates dozens of regional entities (CSC US, CSC
	// Canada, CSC UK, etc.) all sharing infra. Match the family, not each
	// regional variant. Legacy regex used 'BrandAudit' as a placeholder name —
	// see test for the production incident that surfaced this.
	if (/corporate\s*domains/.test(lower)) return 'CSC';
	if (/cloudflare/.test(lower)) return 'Cloudflare';
	if (/tucows/.test(lower)) return 'Tucows';
	if (/godaddy/.test(lower)) return 'GoDaddy';
	if (/namecheap/.test(lower)) return 'Namecheap';
	if (/network solutions|networksolutions/.test(lower)) return 'Network Solutions';
	if (/gandi/.test(lower)) return 'Gandi';
	return raw.trim();
}

export function confidenceTier(c: number): ConfidenceTier {
	if (c >= 0.85) return 'high';
	if (c >= 0.5) return 'medium';
	return 'low';
}

export function isSubdomainOf(candidate: string, target: string): boolean {
	if (candidate === target) return true;
	return candidate.endsWith('.' + target);
}

function hasStrongInfraSignal(signals: string[]): string[] {
	return signals.filter((s) => STRONG_INFRA_SIGNALS.has(s));
}

function isGeneratedSeedSignal(signal: string): boolean {
	return signal === 'markov_gen' || signal === 'active_lookalike';
}

function nonGeneratedSignals(signals: string[]): string[] {
	return signals.filter((signal) => !isGeneratedSeedSignal(signal));
}

/**
 * Pure shadowIt predicate: candidate is plausibly operated by the brand but
 * sits on disjoint DNS/cert infrastructure, with cross-channel evidence
 * (shared TXT verification token, shared mail platform) pointing back at
 * the target. Deterministic ownership signals are handled by the earlier
 * consolidated rules — this branch fires only when those are absent.
 *
 * Returns the reason strings that drove the match (empty when no match).
 */
export function isShadowIt(c: CandidateInput): string[] {
	const reasons: string[] = [];
	const sharedTxt = c.sharedTxtVerifications ?? [];
	if (sharedTxt.length > 0) {
		reasons.push(`shared TXT verification token(s): ${sharedTxt.join(', ')}`);
	}
	if (c.sharedMxPlatform) {
		const corroboratedBySignal = c.signals.some((signal) =>
			signal === 'dmarc_rua' ||
			signal === 'txt_verification' ||
			signal === 'ns' ||
			signal === 'san' ||
			signal === 'san_recursive' ||
			signal === 'dkim_key_reuse' ||
			signal === 'spf_include' ||
			signal === 'spf_include_seed' ||
			signal === 'cname_alignment' ||
			signal === 'http_redirect',
		);
		const corroboratedBySimilarity = (c.lookalikeScore ?? 0) >= IMPERSONATION_LOOKALIKE_THRESHOLD && c.signals.length >= 2;
		const corroboratedByCaller = c.callerAsserted === true;
		if (corroboratedBySignal || corroboratedBySimilarity || corroboratedByCaller) {
			reasons.push(`shared MX platform (${c.sharedMxPlatform})`);
			if (corroboratedByCaller) reasons.push('caller asserted candidate domain');
			if (corroboratedBySimilarity) reasons.push(`lookalike score ${(c.lookalikeScore ?? 0).toFixed(2)} corroborates shared MX platform`);
		}
	}
	return reasons;
}

/**
 * Pure impersonation predicate: candidate looks like a typosquat (string
 * similarity ≥ IMPERSONATION_LOOKALIKE_THRESHOLD), the registrar family does
 * NOT match the target's (rules out defensive registration), and there is no
 * shared-infrastructure evidence whatsoever. Caller must have already
 * eliminated consolidated and shadowIt branches.
 */
export function isImpersonation(c: CandidateInput, t: TargetContext): string[] {
	const score = c.lookalikeScore ?? 0;
	if (score < IMPERSONATION_LOOKALIKE_THRESHOLD) return [];

	// Registrar-family mismatch — same family signals defensive registration, not impersonation.
	const candFamily = normalizeRegistrar(c.registrar);
	const sameFamily = sameRegistrarFamily(
		{ name: c.registrar, ianaId: c.registrarIanaId },
		{ name: t.registrar, ianaId: t.registrarIanaId },
	);
	if (sameFamily) return [];

	// No shared cross-channel signal — those should have already routed to shadowIt;
	// belt-and-braces here so the predicate is callable in isolation.
	const sharedTxt = (c.sharedTxtVerifications ?? []).length > 0;
	const sharedMx = !!c.sharedMxPlatform;
	if (sharedTxt || sharedMx) return [];

	return [
		`lookalike score ${score.toFixed(2)} ≥ ${IMPERSONATION_LOOKALIKE_THRESHOLD}`,
		`registrar mismatch (candidate=${candFamily || 'Unknown'}, target=${t.registrarFamily || 'Unknown'})`,
		'no shared infrastructure signal',
	];
}

function signalLabel(s: string): string {
	switch (s) {
		case 'san':
			return 'SAN co-cert';
		case 'ns':
			return 'NS overlap';
		case 'dkim_key_reuse':
			return 'shared DKIM key';
		case 'http_redirect':
			return 'HTTP redirect to target';
		case 'spf_include':
			return 'SPF includes target policy';
		case 'spf_include_seed':
			return 'seed SPF delegates to candidate';
		case 'cname_alignment':
			return 'CNAME alignment';
		case 'san_recursive':
			return 'recursive SAN confirmation';
		case 'app_links':
			return 'brand app-link declaration';
		case 'bounty_scope':
			return 'brand-declared bug bounty scope';
		case 'dmarc_rua':
			return 'DMARC RUA reports to target';
		default:
			return s.toUpperCase().replace(/_/g, ' ');
	}
}

export function classifyCandidate(c: CandidateInput, t: TargetContext): Classification {
	const tier = confidenceTier(c.confidence);
	const reasons: string[] = [];

	// Task 8 — brand-discovery tier routing.
	//
	// When ANY observation carries a `tier` field, route by tier provenance
	// BEFORE the legacy classifier rules. Mutual-exclusion rule: Owned tiers
	// (0/1/2) beat the impersonation surface (4), so a candidate with both a
	// tier-2 dmarc_rua AND a tier-4 active_lookalike obs routes to
	// `consolidated`, never to `impersonationSurface`.
	//
	// If no observation carries a tier, this block is bypassed entirely and the
	// legacy Tier-3 rules below execute byte-identically — that's the invariant
	// the "no tier field" regression test pins.
	const observations = c.evidenceObservations ?? [];
	const anyTierTagged = observations.some((o) => o.tier !== undefined);
	if (anyTierTagged) {
		const tier0 = observations.find((o) => o.tier === 0);
		if (tier0) {
			reasons.push(`tier 0 (tenant-declared) via ${tier0.signal}`);
			return { bucket: 'consolidated', confidenceTier: tier, reasons, tier: 0 };
		}
		const tier1 = observations.find(
			(o) => o.tier === 1 && (o.specificityScore ?? 0) >= TIER1_SPECIFICITY_THRESHOLD,
		);
		if (tier1) {
			reasons.push(
				`tier 1 (graph-surfaced) via ${tier1.signal}, specificity=${(tier1.specificityScore ?? 0).toFixed(2)}`,
			);
			return { bucket: 'consolidated', confidenceTier: tier, reasons, tier: 1 };
		}
		const tier2 = observations.find((o) => o.tier === 2);
		if (tier2) {
			reasons.push(`tier 2 (declared/witnessed) via ${tier2.signal}`);
			return { bucket: 'consolidated', confidenceTier: tier, reasons, tier: 2 };
		}
		const onlyTier4 = observations.every((o) => o.tier === 4);
		if (onlyTier4) {
			const sample = observations[0];
			reasons.push(`tier 4 (impersonation surface) via ${sample?.signal ?? 'unknown'}`);
			return { bucket: 'impersonationSurface', confidenceTier: tier, reasons, tier: 4 };
		}
		// Mixed tier 3-only or tier-3-with-tier-4: fall through to legacy rules.
	}

	// Rule 1: Subdomain of target — DNS managed by parent zone, always organizational.
	if (isSubdomainOf(c.domain, t.domain)) {
		reasons.push('subdomain of target');
		return { bucket: 'consolidated', confidenceTier: tier, note: 'Organizational Subdomain', reasons };
	}

	// Rule 1.5: Registrant organization match — when both sides expose registrant via
	// RDAP entities and they normalize to the same string, treat as consolidated.
	// More authoritative than registrar family because MarkMonitor manages many brands
	// but Apple's registrant is always 'Apple Inc.'.
	const candRegistrant = normalizeRegistrant(c.registrant);
	const targetRegistrant = normalizeRegistrant(t.registrant);
	if (candRegistrant && targetRegistrant && candRegistrant === targetRegistrant) {
		reasons.push(`registrant match: ${c.registrant}`);
		return { bucket: 'consolidated', confidenceTier: tier, reasons };
	}

	// Rule 2: Strong deterministic ownership signal.
	const strongSignals = hasStrongInfraSignal(c.signals);
	if (strongSignals.length > 0) {
		reasons.push(...strongSignals.map(signalLabel));
		return { bucket: 'consolidated', confidenceTier: tier, reasons };
	}

	// Rule 3: High-confidence DMARC RUA alone — seed receives DMARC reports for this domain.
	if (c.signals.includes('dmarc_rua') && c.confidence >= DMARC_CONSOLIDATION_THRESHOLD) {
		reasons.push(signalLabel('dmarc_rua'));
		return { bucket: 'consolidated', confidenceTier: tier, reasons };
	}

	const candFamily = normalizeRegistrar(c.registrar);

	if (c.evidenceObservations && !clearsOwnershipGate(c.evidenceObservations, { callerAsserted: c.callerAsserted })) {
		reasons.push('weak evidence did not clear ownership gate');
		return { bucket: 'indeterminate', confidenceTier: tier, reasons };
	}

	// Rule 4: Same normalized registrar family + ≥2 non-generated corroborating signals.
	if (
		sameRegistrarFamily(
			{ name: c.registrar, ianaId: c.registrarIanaId },
			{ name: t.registrar, ianaId: t.registrarIanaId },
		) &&
		nonGeneratedSignals(c.signals).length >= 2
	) {
		reasons.push(`shared registrar family (${candFamily}) + ${nonGeneratedSignals(c.signals).length} corroborating signals`);
		return { bucket: 'consolidated', confidenceTier: tier, reasons };
	}

	// Rule 4.5: Cross-channel shadowIt — disjoint provider but shared TXT verification
	// token or shared MX platform pointing back at the target. Must beat Rule 5
	// (redacted → indeterminate) and Rule 4.6 (impersonation), per the task spec:
	// a typosquat with shared evidence is more interesting as shadowIt.
	const shadowReasons = isShadowIt(c);
	if (c.confidence >= SHADOW_IT_CONFIDENCE_THRESHOLD && c.signals.includes('spf_include_seed')) {
		reasons.push(signalLabel('spf_include_seed'));
		return { bucket: 'shadowIt', confidenceTier: tier, reasons };
	}
	if (shadowReasons.length > 0) {
		reasons.push(...shadowReasons);
		return { bucket: 'shadowIt', confidenceTier: tier, reasons };
	}

	// Rule 4.6: Impersonation — lookalike score ≥ threshold + registrar family
	// mismatch + no shared-infrastructure signal. Fires before Rules 5/7 so a
	// clearly typosquatted domain doesn't disappear into indeterminate when the
	// candidate's RDAP is redacted.
	const impersonationReasons = isImpersonation(c, t);
	if (impersonationReasons.length > 0) {
		reasons.push(...impersonationReasons);
		return { bucket: 'impersonation', confidenceTier: tier, reasons };
	}

	// Rule 5: Registrar source is redacted / notfound / lookup_failed → can't
	// determine ownership from this dimension. Bucket is `indeterminate` for all
	// three (downstream API stays a 4-value enum), but `note` differentiates so
	// the retry hook (Phase 2b) and human reviewers can act:
	//   - lookup_failed → transient; should retry before re-classifying
	//   - redacted     → registry policy hides registrar; ownership unverifiable
	//   - notfound     → registry has no record; usually expired / never registered
	const src = c.registrarSource ?? 'unknown';
	if (src === 'lookup_failed' && strongSignals.length === 0) {
		reasons.push('registrar lookup failed transiently — retry pending');
		return { bucket: 'indeterminate', confidenceTier: tier, note: 'needs_retry', reasons };
	}
	if ((src === 'redacted' || src === 'notfound') && strongSignals.length === 0) {
		reasons.push(`registrar source: ${src}`);
		return { bucket: 'indeterminate', confidenceTier: tier, note: src, reasons };
	}

	// Rule 6: High confidence + dmarc_rua-only on different registrar → genuine sprawl candidate.
	// (Third-party operating on behalf of the brand, or weak coincidence — flag for review.)
	if (c.confidence >= SHADOW_IT_CONFIDENCE_THRESHOLD && c.signals.includes('dmarc_rua')) {
		reasons.push(`DMARC RUA on non-aligned registrar (${candFamily})`);
		return { bucket: 'shadowIt', confidenceTier: tier, reasons };
	}

	// Rule 7: Medium confidence + no strong signals → indeterminate (not enough evidence either way).
	if (c.confidence >= INDETERMINATE_CONFIDENCE_THRESHOLD) {
		reasons.push('medium confidence, no strong infra signal');
		return { bucket: 'indeterminate', confidenceTier: tier, reasons };
	}

	// Rule 8: Low confidence + no strong signals → likely parked / unrelated / impersonation.
	reasons.push('low confidence, no strong infra signal');
	return { bucket: 'impersonation', confidenceTier: tier, reasons };
}
