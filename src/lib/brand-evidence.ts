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
