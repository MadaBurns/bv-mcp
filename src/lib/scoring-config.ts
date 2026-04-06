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

import { parseScoringConfig } from '@blackveil/dns-checks/scoring';
import type { ScoringConfig } from '@blackveil/dns-checks/scoring';

let cachedConfig: { input: string | undefined; result: ScoringConfig } | null = null;

/**
 * Memoized wrapper around parseScoringConfig.
 * The SCORING_CONFIG env var is immutable per isolate lifetime,
 * so we cache the parsed result to avoid re-parsing on every request.
 */
export function parseScoringConfigCached(raw: string | undefined): ScoringConfig {
	if (cachedConfig && cachedConfig.input === raw) return cachedConfig.result;
	const result = parseScoringConfig(raw);
	cachedConfig = { input: raw, result };
	return result;
}

/** @internal Reset cached config (test use only). */
export function resetScoringConfigCache(): void {
	cachedConfig = null;
}
