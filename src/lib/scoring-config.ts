// SPDX-License-Identifier: BUSL-1.1

/**
 * Runtime scoring configuration — re-exported from @blackveil/dns-checks/scoring (single source of truth).
 * @deprecated Import directly from @blackveil/dns-checks/scoring in new code.
 */

export {
	DEFAULT_SCORING_CONFIG,
	toImportanceRecord,
	parseScoringConfig,
} from '@blackveil/dns-checks/scoring';

export type { ScoringConfig } from '@blackveil/dns-checks/scoring';
