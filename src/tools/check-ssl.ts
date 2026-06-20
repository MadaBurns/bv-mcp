// SPDX-License-Identifier: BUSL-1.1

/**
 * SSL/TLS certificate check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 *
 * Operator-only enrichment: when a `tlsProbeBinding` is provided (via the BV_TLS_PROBE
 * service binding), the result is enriched with negotiated-TLS-version data. BSL
 * self-hosts without the binding receive the unmodified base result.
 */

import { checkSSL } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { callTlsProbe, mergeTlsFinding } from '../lib/tls-probe-binding';
import type { TlsProbeBinding, BindingDegradationSink } from '../lib/tls-probe-binding';

/**
 * Check SSL/TLS configuration for a domain.
 * Validates HTTPS connectivity, HSTS headers, and HTTP→HTTPS redirect.
 *
 * @param domain - The domain to check.
 * @param tlsProbeOptions - Optional operator-only TLS-version enrichment options.
 *   `tlsProbeBinding`: the BV_TLS_PROBE service binding (absent on all BSL self-hosts).
 *   `tlsProbeAuthToken`: bearer token forwarded to the probe endpoint.
 *   Omitting the binding (or passing an empty object) returns the result unchanged — fail-soft.
 */
export async function checkSsl(
	domain: string,
	tlsProbeOptions: { tlsProbeBinding?: TlsProbeBinding; tlsProbeAuthToken?: string; onBindingDegradation?: BindingDegradationSink } = {},
): Promise<CheckResult> {
	const result = (await checkSSL(domain, fetch, { timeout: HTTPS_TIMEOUT_MS })) as CheckResult;
	// Operator-only TLS-version enrichment via the BV_TLS_PROBE service binding.
	// Fail-soft: absent binding (every BSL self-host) → result returned unchanged.
	// callTlsProbe returns null on any failure; mergeTlsFinding only ever appends a
	// High finding when the probe actively reports legacy TLS (≤1.1), never penalizes 1.2/1.3.
	if (!tlsProbeOptions.tlsProbeBinding) return result;
	const probe = await callTlsProbe(tlsProbeOptions.tlsProbeBinding, tlsProbeOptions.tlsProbeAuthToken, domain, {
		telemetry: tlsProbeOptions.onBindingDegradation,
	});
	return probe ? mergeTlsFinding(result, probe) : result;
}
