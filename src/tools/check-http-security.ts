// SPDX-License-Identifier: BUSL-1.1

/**
 * HTTP security headers check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkHTTPSecurity } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';

/**
 * Check HTTP security headers for a domain.
 * Fetches the HTTPS endpoint and analyzes browser security headers.
 */
export async function checkHttpSecurity(domain: string): Promise<CheckResult> {
	return checkHTTPSecurity(domain, fetch, { timeout: HTTPS_TIMEOUT_MS }) as Promise<CheckResult>;
}
