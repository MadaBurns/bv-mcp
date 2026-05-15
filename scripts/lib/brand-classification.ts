// SPDX-License-Identifier: BUSL-1.1
/**
 * Brand-audit classification module.
 *
 * Extracted from `scripts/brand-audit-brand-audit.spec.ts` so the bucketing logic
 * can be unit-tested independently from the live discovery/registrar I/O.
 *
 * Rule order (first match wins):
 *   1. Subdomain of target → consolidated, 'Organizational Subdomain'
 *   2. Strong infra signal (san | ns | dkim_key_reuse) → consolidated
 *   3. High-confidence dmarc_rua alone → consolidated
 *   4. Same normalized registrar family + ≥2 corroborating signals → consolidated
 *   5. Registrar source is redacted/notfound + no strong signals → indeterminate
 *   6. High confidence + dmarc_rua-only on different registrar → shadowIt
 *   7. Medium confidence + no strong signals → indeterminate
 *   8. Low confidence + no strong signals → impersonation
 */

export type Bucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation';
export type ConfidenceTier = 'high' | 'medium' | 'low';
export type RegistrarSource = 'rdap' | 'whois' | 'redacted' | 'notfound' | 'unknown';

export interface CandidateInput {
	domain: string;
	confidence: number;
	signals: string[];
	registrar: string;
	registrarSource?: RegistrarSource;
	/** Registrant organization (from RDAP entities). null when redacted/unavailable. */
	registrant?: string | null;
}

export interface TargetContext {
	domain: string;
	registrar: string;
	registrarFamily: string;
	/** Target's registrant organization (for cross-reference matching). */
	registrant?: string | null;
}

export interface Classification {
	bucket: Bucket;
	confidenceTier: ConfidenceTier;
	note?: string;
	reasons: string[];
}

/** Strong infrastructure signals — sharing any of these is near-deterministic ownership evidence. */
const STRONG_INFRA_SIGNALS = new Set(['san', 'ns', 'dkim_key_reuse']);

/** Confidence threshold above which dmarc_rua alone is consolidation evidence. */
const DMARC_CONSOLIDATION_THRESHOLD = 0.85;

/** Confidence threshold above which a candidate without strong signals counts as shadowIt rather than indeterminate. */
const SHADOW_IT_CONFIDENCE_THRESHOLD = 0.7;

/** Confidence threshold above which a candidate without strong signals is indeterminate rather than impersonation. */
const INDETERMINATE_CONFIDENCE_THRESHOLD = 0.5;

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
	if (/brand-audit\s*corporate|brand-audit\s*global|corporate domains/.test(lower)) return 'BrandAudit';
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

function signalLabel(s: string): string {
	switch (s) {
		case 'san':
			return 'SAN co-cert';
		case 'ns':
			return 'NS overlap';
		case 'dkim_key_reuse':
			return 'shared DKIM key';
		case 'dmarc_rua':
			return 'DMARC RUA reports to target';
		default:
			return s.toUpperCase().replace(/_/g, ' ');
	}
}

export function classifyCandidate(c: CandidateInput, t: TargetContext): Classification {
	const tier = confidenceTier(c.confidence);
	const reasons: string[] = [];

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

	// Rule 2: Strong infrastructure signal — SAN co-cert, shared NS, or DKIM key reuse.
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

	// Rule 4: Same normalized registrar family + ≥2 corroborating signals.
	const candFamily = normalizeRegistrar(c.registrar);
	if (
		candFamily !== 'Unknown' &&
		t.registrarFamily !== 'Unknown' &&
		candFamily === t.registrarFamily &&
		c.signals.length >= 2
	) {
		reasons.push(`shared registrar family (${candFamily}) + ${c.signals.length} corroborating signals`);
		return { bucket: 'consolidated', confidenceTier: tier, reasons };
	}

	// Rule 5: Registrar source is redacted or notfound → can't determine ownership.
	const src = c.registrarSource ?? 'unknown';
	if ((src === 'redacted' || src === 'notfound') && strongSignals.length === 0) {
		reasons.push(`registrar source: ${src}`);
		return { bucket: 'indeterminate', confidenceTier: tier, reasons };
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
