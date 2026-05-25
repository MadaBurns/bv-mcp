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
	return {
		scanTimeoutMs: runtimeOptions?.scanTimeoutMs ?? SCAN_TIMEOUT_MS,
		perCheckTimeoutMs: runtimeOptions?.perCheckTimeoutMs ?? PER_CHECK_TIMEOUT_MS,
		retryBudgetMs: RETRY_BUDGET_MS,
		maxRetriesPerScan: MAX_RETRIES_PER_SCAN,
		retryTimeoutMs: RETRY_TIMEOUT_MS,
	};
}
