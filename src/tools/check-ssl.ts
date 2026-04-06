// SPDX-License-Identifier: BUSL-1.1

/**
 * SSL/TLS certificate check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkSSL } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';

/**
 * Check SSL/TLS configuration for a domain.
 * Validates HTTPS connectivity, HSTS headers, and HTTP→HTTPS redirect.
 */
export async function checkSsl(domain: string): Promise<CheckResult> {
	return checkSSL(domain, fetch, { timeout: HTTPS_TIMEOUT_MS }) as Promise<CheckResult>;
}
