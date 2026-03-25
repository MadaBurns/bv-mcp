// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring engine for @blackveil/dns-checks
 *
 * Exports the three-tier scoring model, engine, runtime config, and domain context profiles.
 */

export {
	// Re-exports from model (types and helpers)
	CATEGORY_DISPLAY_WEIGHTS,
	CATEGORY_TIERS,
	SEVERITY_PENALTIES,
	inferFindingConfidence,
	computeCategoryScore,
	buildCheckResult,
	createFinding,
} from './model';
export type {
	CheckCategory,
	CategoryTier,
	Finding,
	FindingConfidence,
	CheckResult,
	ScanScore,
	Severity,
} from './model';

export {
	IMPORTANCE_WEIGHTS,
	CORE_WEIGHTS,
	PROTECTIVE_WEIGHTS,
	scoreIndicatesMissingControl,
	scoreToGrade,
	computeScanScore,
} from './engine';

export {
	DEFAULT_SCORING_CONFIG,
	toImportanceRecord,
	parseScoringConfig,
} from './config';
export type { ScoringConfig } from './config';

export {
	PROFILE_WEIGHTS,
	PROFILE_CRITICAL_CATEGORIES,
	PROFILE_EMAIL_BONUS_ELIGIBLE,
	detectDomainContext,
	getProfileWeights,
} from './profiles';
export type { DomainProfile, DomainContext } from './profiles';
