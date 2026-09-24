// SPDX-License-Identifier: BUSL-1.1

/**
 * Project-local scoring configuration utilities.
 * Memoized wrapper around parseScoringConfig from @blackveil/dns-checks/scoring.
 */

import { parseScoringConfig } from '@blackveil/dns-checks/scoring';
import type { ScoringConfig } from '@blackveil/dns-checks/scoring';
import { logEvent } from './log';

let cachedConfig: { input: string | undefined; result: ScoringConfig } | null = null;

/** Marker dns-checks' warn hook uses for the JSON.parse-failure message (see config.ts). */
const INVALID_JSON_WARN_MARKER = 'could not be parsed as JSON';

/**
 * Route parseScoringConfig's advisory warnings: the JSON.parse-failure case gets a
 * structured `logEvent` (category 'config', result 'scoring_config_invalid_json') so
 * it's queryable like every other operator-facing degradation; every other warn path
 * (schema-invalid keys, unrecognized paths) keeps its prior plain `console.warn`.
 */
function routeScoringConfigWarning(message: string): void {
	if (message.includes(INVALID_JSON_WARN_MARKER)) {
		logEvent({
			timestamp: new Date().toISOString(),
			severity: 'warn',
			category: 'config',
			result: 'scoring_config_invalid_json',
			details: { message },
		});
		return;
	}
	if (typeof console !== 'undefined') console.warn(message);
}

/**
 * Memoized wrapper around parseScoringConfig.
 * The SCORING_CONFIG env var is immutable per isolate lifetime,
 * so we cache the parsed result to avoid re-parsing on every request — which also
 * makes any parse-failure warning fire at most once per isolate, not once per scan.
 */
export function parseScoringConfigCached(raw: string | undefined): ScoringConfig {
	if (cachedConfig && cachedConfig.input === raw) return cachedConfig.result;
	const result = parseScoringConfig(raw, { onWarn: routeScoringConfigWarning });
	cachedConfig = { input: raw, result };
	return result;
}

/** @internal Reset cached config (test use only). */
export function resetScoringConfigCache(): void {
	cachedConfig = null;
}
