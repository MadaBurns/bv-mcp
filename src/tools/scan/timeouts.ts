// SPDX-License-Identifier: BUSL-1.1

import { PER_CHECK_TIMEOUT_MS, SCAN_TIMEOUT_MS } from '../../lib/config';
import type { ScanRuntimeOptions } from './post-processing';

export interface ScanTimeoutBudget {
	scanTimeoutMs: number;
	perCheckTimeoutMs: number;
	retryBudgetMs: number;
	maxRetriesPerScan: number;
	retryTimeoutMs: number;
}

const RETRY_BUDGET_MS = 3_000;
const MAX_RETRIES_PER_SCAN = 3;
const RETRY_TIMEOUT_MS = 2_500;

export function resolveScanTimeoutBudget(
	runtimeOptions?: Pick<ScanRuntimeOptions, 'scanTimeoutMs' | 'perCheckTimeoutMs'>,
): ScanTimeoutBudget {
	const scanTimeoutMs = runtimeOptions?.scanTimeoutMs ?? SCAN_TIMEOUT_MS;
	// ⚠️ The two env overrides are parsed by INDEPENDENT clamps — `parsePerCheckTimeout`
	// allows up to 15s while `parseScanTimeout` allows as little as 5s — so they can be
	// configured into direct contradiction: a single check permitted to outlive the whole
	// scan. Three things break silently when that happens, and none of them announce
	// themselves (issue #674):
	//
	//   1. `safeCheck`'s per-check killer becomes dead code — the scan race always wins.
	//   2. `fetchBudgetFor(perCheckTimeoutMs)` is then sized against a timer that CANNOT
	//      fire, so every budgeted check (#641) loses the one guarantee the budget exists
	//      to provide: that our own abort lands BEFORE the killer instead of racing it.
	//      The check is discarded with its findings in hand — the exact failure #641 fixed.
	//   3. The transient-zero retry pass is skipped entirely (`if (!timedOut && …)`).
	//
	// Reconciling here rather than at the nine parse sites: this is the SOLE consumer of
	// `perCheckTimeoutMs` on the scan path, so it is the one place the invariant can be
	// stated once. Leaves the retry budget's room so that pass stays reachable.
	const perCheckCeilingMs = Math.max(1, scanTimeoutMs - RETRY_BUDGET_MS);
	return {
		scanTimeoutMs,
		perCheckTimeoutMs: Math.min(runtimeOptions?.perCheckTimeoutMs ?? PER_CHECK_TIMEOUT_MS, perCheckCeilingMs),
		retryBudgetMs: RETRY_BUDGET_MS,
		maxRetriesPerScan: MAX_RETRIES_PER_SCAN,
		retryTimeoutMs: RETRY_TIMEOUT_MS,
	};
}
