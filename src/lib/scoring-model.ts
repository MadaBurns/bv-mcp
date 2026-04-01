// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring model — re-exported from @blackveil/dns-checks/scoring (single source of truth).
 * @deprecated Import directly from @blackveil/dns-checks/scoring in new code.
 */

export {
	CATEGORY_DISPLAY_WEIGHTS,
	CATEGORY_TIERS,
	SEVERITY_PENALTIES,
	buildCheckResult,
	computeCategoryScore,
	createFinding,
	inferFindingConfidence,
} from '@blackveil/dns-checks/scoring';

export type {
	CategoryTier,
	CheckCategory,
	CheckResult,
	Finding,
	FindingConfidence,
	ScanScore,
	Severity,
} from '@blackveil/dns-checks/scoring';
