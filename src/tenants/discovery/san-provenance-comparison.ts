// SPDX-License-Identifier: BUSL-1.1
import {
	MAX_SAN_PROVENANCE_OBSERVATIONS,
	MAX_PROVENANCE_CANDIDATES,
	MAX_PROVENANCE_DNS_NAMES,
	type SanCertificateProvenance,
} from './san-provenance';

export interface SanCandidateProvenanceSummary {
	coverage: 'complete' | 'unknown';
	observedIssuanceCount: number | null;
	registrableDomainCountRange: { min: number; max: number } | null;
}

export interface SanProvenanceComparison {
	/** A relation between observed certificates, never independence or ownership evidence. */
	issuanceRelation: 'distinct_issuances_observed' | 'same_issuance_observed' | 'unknown';
	firstOrder: SanCandidateProvenanceSummary;
	reciprocal: SanCandidateProvenanceSummary;
}

const unknownSummary = (): SanCandidateProvenanceSummary => ({
	coverage: 'unknown',
	observedIssuanceCount: null,
	registrableDomainCountRange: null,
});

function candidateObservations(
	candidate: string,
	observations: readonly SanCertificateProvenance[] | undefined,
	truncated: boolean,
): SanCertificateProvenance[] | null {
	if (!observations || observations.length === 0 || observations.length > MAX_SAN_PROVENANCE_OBSERVATIONS || truncated) return null;
	// Missing mappings could conceal a matching observation. Never infer absence from a capped sample.
	if (
		observations.some(
			(observation) =>
				!observation.candidateMappingComplete ||
				observation.candidateDomains.length > MAX_PROVENANCE_CANDIDATES ||
				observation.coverage !== 'complete' ||
				observation.source !== 'certspotter' ||
				!observation.issuanceSha256 ||
				!/^[a-f0-9]{64}$/.test(observation.issuanceSha256) ||
				!Number.isInteger(observation.registrableDomainCount) ||
				(observation.registrableDomainCount ?? 0) < 1 ||
				(observation.registrableDomainCount ?? 0) > MAX_PROVENANCE_DNS_NAMES,
		)
	)
		return null;
	const matches = observations.filter((observation) => observation.candidateDomains.includes(candidate));
	return matches.length > 0 ? matches : null;
}

function summarize(matches: SanCertificateProvenance[] | null): SanCandidateProvenanceSummary {
	if (!matches) return unknownSummary();
	const counts = matches.map((observation) => observation.registrableDomainCount!);
	return {
		coverage: 'complete',
		observedIssuanceCount: new Set(matches.map((observation) => observation.issuanceSha256)).size,
		registrableDomainCountRange: { min: Math.min(...counts), max: Math.max(...counts) },
	};
}

/** Compact candidate-specific reporting; no threshold, filter, score, or verdict. */
export function summarizeSanCandidateProvenance(
	candidate: string,
	observations: readonly SanCertificateProvenance[] | undefined,
	truncated = false,
): SanCandidateProvenanceSummary {
	return summarize(candidateObservations(candidate, observations, truncated));
}

/** Compare only retained full-name issuance observations. Different issuances can still share a vendor. */
export function compareSanCertificateProvenance(input: {
	seed: string;
	candidate: string;
	firstOrder?: readonly SanCertificateProvenance[];
	firstOrderTruncated?: boolean;
	reciprocal?: readonly SanCertificateProvenance[];
	reciprocalTruncated?: boolean;
}): SanProvenanceComparison {
	const first = candidateObservations(input.candidate, input.firstOrder, input.firstOrderTruncated ?? false);
	const reciprocal = candidateObservations(input.seed, input.reciprocal, input.reciprocalTruncated ?? false);
	let issuanceRelation: SanProvenanceComparison['issuanceRelation'] = 'unknown';
	if (first && reciprocal) {
		// "distinct" means at least one observed pair differs, not that none are shared.
		issuanceRelation = first.some((a) => reciprocal.some((b) => a.issuanceSha256 !== b.issuanceSha256))
			? 'distinct_issuances_observed'
			: 'same_issuance_observed';
	}
	return { issuanceRelation, firstOrder: summarize(first), reciprocal: summarize(reciprocal) };
}
