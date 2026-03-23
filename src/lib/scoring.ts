// SPDX-License-Identifier: BUSL-1.1

/**
 * DNS Security Scoring Library
 *
 * Public scoring surface re-exporting the scoring model and scan aggregation engine.
 */

export {
	CATEGORY_DISPLAY_WEIGHTS,
	CATEGORY_TIERS,
	SEVERITY_PENALTIES,
	buildCheckResult,
	computeCategoryScore,
	createFinding,
	inferFindingConfidence,
	type CategoryTier,
	type CheckCategory,
	type CheckResult,
	type Finding,
	type FindingConfidence,
	type ScanScore,
	type Severity,
} from './scoring-model';

export { computeScanScore, scoreToGrade, IMPORTANCE_WEIGHTS, CORE_WEIGHTS, PROTECTIVE_WEIGHTS } from './scoring-engine';

export { detectDomainContext, getProfileWeights, type DomainContext, type DomainProfile } from './context-profiles';

export {
	adaptiveWeightsToContext,
	generateScoringNote,
	computeAdaptiveWeight,
	blendWeights,
	type AdaptiveWeightsResponse,
	type ScanTelemetry,
	type WeightBound,
} from './adaptive-weights';

export { parseScoringConfig, DEFAULT_SCORING_CONFIG, toImportanceRecord, type ScoringConfig } from './scoring-config';
