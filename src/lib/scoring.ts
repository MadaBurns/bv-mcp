// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS Security Scoring Library
 *
 * Public scoring surface re-exporting from @blackveil/dns-checks/scoring (single source of truth).
 */

export {
	CATEGORY_DISPLAY_WEIGHTS,
	CATEGORY_TIERS,
	SEVERITY_PENALTIES,
	buildCheckResult,
	computeCategoryScore,
	createFinding,
	inferFindingConfidence,
	computeScanScore,
	scoreToGrade,
	IMPORTANCE_WEIGHTS,
	CORE_WEIGHTS,
	PROTECTIVE_WEIGHTS,
	scoreIndicatesMissingControl,
	detectDomainContext,
	getProfileWeights,
	PROFILE_WEIGHTS,
	PROFILE_CRITICAL_CATEGORIES,
	PROFILE_EMAIL_BONUS_ELIGIBLE,
	DEFAULT_SCORING_CONFIG,
	toImportanceRecord,
	parseScoringConfig,
} from '@blackveil/dns-checks/scoring';

export type {
	CategoryTier,
	CheckCategory,
	CheckResult,
	CheckStatus,
	Finding,
	FindingConfidence,
	ScanScore,
	Severity,
	DomainContext,
	DomainProfile,
	ScoringConfig,
} from '@blackveil/dns-checks/scoring';

export {
	adaptiveWeightsToContext,
	generateScoringNote,
	computeAdaptiveWeight,
	blendWeights,
} from './adaptive-weights';

export type {
	AdaptiveWeightsResponse,
	ScanTelemetry,
	WeightBound,
} from './adaptive-weights';
