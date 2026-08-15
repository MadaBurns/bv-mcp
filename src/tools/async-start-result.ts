// SPDX-License-Identifier: BUSL-1.1

/** Shared error-result builder for asynchronous tool producers. */
import { buildCheckResult, createFinding, type CheckCategory, type CheckResult } from '../lib/scoring';

/**
 * Creates a typed error-result builder while preserving each producer's finding
 * category and human-readable summary prefix.
 */
export function createAsyncStartErrorResultBuilder<Flag extends string>(category: CheckCategory, summaryPrefix: string) {
	return (flag: Flag, message: string, extra: Record<string, unknown> = {}): CheckResult =>
		buildCheckResult(category, [
			createFinding(category, `${summaryPrefix}: ${flag}`, 'high', message, {
				[flag]: true,
				...extra,
			}),
		]);
}
