// SPDX-License-Identifier: BUSL-1.1

import { PARITY_CORPUS_VERSION } from '../parity-fixtures';
import { NIST_GRADE_THRESHOLDS } from './engine';
import {
	PROFILE_CRITICAL_CATEGORIES,
	PROFILE_EMAIL_BONUS_ELIGIBLE,
	PROFILE_WEIGHTS,
	type DomainProfile,
} from './profiles';

export const SCORING_CONTRACT_SCHEMA_VERSION = 1;

export type ProfileComparisonClass = 'ordinary-domain' | 'limited-footprint' | 'specialist-dns';

export interface ScoringProfileSemantics {
	comparisonClass: ProfileComparisonClass;
	emailPostureIncluded: boolean;
	autoSelectable: boolean;
	selectionReason: string;
}

export const PROFILE_SEMANTICS: Readonly<Record<DomainProfile, ScoringProfileSemantics>> = Object.freeze({
	mail_enabled: {
		comparisonClass: 'ordinary-domain',
		emailPostureIncluded: true,
		autoSelectable: true,
		selectionReason: 'mail-routing-detected',
	},
	enterprise_mail: {
		comparisonClass: 'ordinary-domain',
		emailPostureIncluded: true,
		autoSelectable: true,
		selectionReason: 'enterprise-mail-and-enforcing-dmarc-detected',
	},
	non_mail: {
		comparisonClass: 'ordinary-domain',
		emailPostureIncluded: true,
		autoSelectable: true,
		selectionReason: 'no-receiving-mail-or-web-presence-detected',
	},
	web_only: {
		comparisonClass: 'ordinary-domain',
		emailPostureIncluded: false,
		autoSelectable: true,
		selectionReason: 'web-presence-without-receiving-mail-detected',
	},
	minimal: {
		comparisonClass: 'limited-footprint',
		emailPostureIncluded: true,
		autoSelectable: true,
		selectionReason: 'more-than-half-of-measured-checks-failed',
	},
	authoritative_dns_infra: {
		comparisonClass: 'specialist-dns',
		emailPostureIncluded: false,
		autoSelectable: false,
		selectionReason: 'explicit-specialist-profile-only',
	},
});

/**
 * Machine-readable scoring behavior contract. Object keys are normalized by
 * `canonicalScoringContractJson`; release tooling hashes those canonical bytes.
 */
export const SCORING_CONTRACT = Object.freeze({
	schemaVersion: SCORING_CONTRACT_SCHEMA_VERSION,
	packageVersion: PARITY_CORPUS_VERSION,
	gradeThresholds: NIST_GRADE_THRESHOLDS,
	profiles: Object.fromEntries(
		(Object.keys(PROFILE_WEIGHTS) as DomainProfile[]).map((profile) => [
			profile,
			{
				weights: PROFILE_WEIGHTS[profile],
				criticalCategories: PROFILE_CRITICAL_CATEGORIES[profile],
				emailBonusEligible: PROFILE_EMAIL_BONUS_ELIGIBLE[profile],
				semantics: PROFILE_SEMANTICS[profile],
				},
			]),
		),
});

function normalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(normalize);
	if (value !== null && typeof value === 'object') {
		return Object.fromEntries(
			Object.entries(value as Record<string, unknown>)
				.sort(([left], [right]) => left.localeCompare(right))
				.map(([key, child]) => [key, normalize(child)]),
		);
	}
	return value;
}

/** Stable bytes used for hashing, attestation and cross-repository comparison. */
export function canonicalScoringContractJson(): string {
	return `${JSON.stringify(normalize(SCORING_CONTRACT), null, 2)}\n`;
}
