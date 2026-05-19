// SPDX-License-Identifier: BUSL-1.1

export type BrandEvidenceSignal =
	| 'san'
	| 'san_recursive'
	| 'ns'
	| 'dmarc_rua'
	| 'dkim_key_reuse'
	| 'http_redirect'
	| 'mx_overlap'
	| 'txt_verification'
	| 'mx_platform'
	| 'spf_include'
	| 'spf_include_seed'
	| 'cname_alignment'
	| 'markov_gen'
	| 'active_lookalike'
	// Ground-truth Phase-5 signals — brand-authored declarations that bypass
	// the downstream signal sweep but still need a tier classification.
	| 'app_links'
	| 'bounty_scope';

export type BrandEvidenceTier = 'strong' | 'medium' | 'weak';

export interface BrandEvidenceObservation {
	signal: BrandEvidenceSignal;
	confidence?: number;
	metadata?: Record<string, unknown>;
	/**
	 * First-principles discovery tier (T1.4):
	 *   0 = tenant-declared (bv-enterprise)
	 *   1 = infrastructure graph (bv-infrastructure-graph)
	 *   2 = declared / witnessed evidence (bv-intel-gateway)
	 *   3 = fingerprint sweep fallback (this worker)
	 *   4 = becoming-critical candidate
	 * Absent on legacy fingerprint observations; T6 keys ownership-gate bypass off it.
	 */
	tier?: 0 | 1 | 2 | 3 | 4;
	/**
	 * Per-signal specificity (Tier 1, infrastructure-graph). Higher → rarer signal
	 * across the corpus, so a co-occurrence is more meaningful (e.g. unique cert
	 * fingerprint ~ 0.9; shared `mx.gmail.com` ~ 0.05). Used by T6 to decide
	 * whether a single Tier-1 observation is strong enough to clear ownership alone.
	 */
	specificityScore?: number;
}

export interface OwnershipGateOptions {
	callerAsserted?: boolean;
}

const STRONG_SIGNALS: ReadonlySet<BrandEvidenceSignal> = new Set([
	'dkim_key_reuse',
	'http_redirect',
	'txt_verification',
	'spf_include',
	'spf_include_seed',
	'cname_alignment',
	'san_recursive',
	'app_links',
	'bounty_scope',
]);

const MEDIUM_SIGNALS: ReadonlySet<BrandEvidenceSignal> = new Set([
	'ns',
	'dmarc_rua',
	'mx_overlap',
	'san',
]);

const WEAK_SIGNALS: ReadonlySet<BrandEvidenceSignal> = new Set([
	'markov_gen',
	'active_lookalike',
]);

const BROAD_MX_PLATFORMS = new Set([
	'm365',
	'microsoft_365',
	'office365',
	'office_365',
	'exchange_online',
	'google_workspace',
	'google',
	'gmail',
]);

function normalizedMetadataValue(metadata: Record<string, unknown> | undefined, key: string): string | null {
	const value = metadata?.[key];
	return typeof value === 'string' ? value.trim().toLowerCase() : null;
}

export function evidenceTier(signal: BrandEvidenceSignal, metadata?: Record<string, unknown>): BrandEvidenceTier {
	if (signal === 'mx_platform') {
		const sharedMxPlatform = normalizedMetadataValue(metadata, 'sharedMxPlatform');
		return sharedMxPlatform && BROAD_MX_PLATFORMS.has(sharedMxPlatform) ? 'weak' : 'medium';
	}
	if (STRONG_SIGNALS.has(signal)) return 'strong';
	if (MEDIUM_SIGNALS.has(signal)) return 'medium';
	if (WEAK_SIGNALS.has(signal)) return 'weak';
	return 'weak';
}

function isSeedObservation(observation: BrandEvidenceObservation): boolean {
	return observation.signal === 'markov_gen' || observation.signal === 'active_lookalike';
}

export function clearsOwnershipGate(
	observations: BrandEvidenceObservation[],
	options: OwnershipGateOptions = {},
): boolean {
	const unique = new Map<BrandEvidenceSignal, BrandEvidenceObservation>();
	for (const observation of observations) {
		if (!unique.has(observation.signal)) unique.set(observation.signal, observation);
	}
	const distinct = Array.from(unique.values());
	if (distinct.length === 0) return false;

	// T6: tier-based bypass of the legacy N-of-M corroboration gate.
	// Tier 0 (tenant-declared) and Tier 2 (declared/witnessed evidence) are gold-
	// standard and auto-clear. Tier 1 (infrastructure-graph) auto-clears only when
	// the underlying signal is specific enough (>= 0.5) — broad signals like a
	// shared `mx.gmail.com` carry tier=1 but specificityScore ~ 0.05 and must
	// still corroborate. Tier 3/4 and untiered observations fall through to the
	// existing strong-or-N-of-M-medium logic.
	for (const observation of distinct) {
		if (observation.tier === 0) return true;
		if (observation.tier === 2) return true;
		if (observation.tier === 1 && typeof observation.specificityScore === 'number' && observation.specificityScore >= 0.5) {
			return true;
		}
	}

	if (options.callerAsserted === true) {
		return distinct.some((observation) => !isSeedObservation(observation));
	}

	const tiers = distinct.map((observation) => evidenceTier(observation.signal, observation.metadata));
	if (tiers.includes('strong')) return true;
	const nonSeed = distinct.filter((observation) => !isSeedObservation(observation));
	const nonSeedTiers = nonSeed.map((observation) => evidenceTier(observation.signal, observation.metadata));
	if (nonSeedTiers.filter((tier) => tier === 'medium').length >= 2) return true;
	return false;
}
