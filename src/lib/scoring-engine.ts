// SPDX-License-Identifier: BUSL-1.1

/**
 * Scoring engine — re-exported from @blackveil/dns-checks/scoring (single source of truth).
 * @deprecated Import directly from @blackveil/dns-checks/scoring in new code.
 */

export {
	IMPORTANCE_WEIGHTS,
	CORE_WEIGHTS,
	PROTECTIVE_WEIGHTS,
	scoreIndicatesMissingControl,
	scoreToGrade,
	computeScanScore,
} from '@blackveil/dns-checks/scoring';
