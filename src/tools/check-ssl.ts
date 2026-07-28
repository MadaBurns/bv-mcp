// SPDX-License-Identifier: BUSL-1.1

/**
 * SSL/TLS certificate check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 *
 * Operator-only enrichment: when a `tlsProbeBinding` is provided (via the BV_TLS_PROBE
 * service binding), the result is enriched with negotiated-TLS-version data. BSL
 * self-hosts without the binding receive the unmodified base result.
 */

import { checkSSL, withRobotsGate } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { callTlsProbe, mergeTlsFinding } from '../lib/tls-probe-binding';
import { enrichWithCertificateMetadata } from '../lib/cert-metadata-enrich';
import type { TlsProbeBinding, BindingDegradationSink } from '../lib/tls-probe-binding';
import { withAbortSignal } from '../lib/abort-signal';

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
	tlsProbeOptions: {
		tlsProbeBinding?: TlsProbeBinding;
		tlsProbeAuthToken?: string;
		onBindingDegradation?: BindingDegradationSink;
		/**
		 * Optional caller-supplied abort signal (R7). When provided, it is composed
		 * with the package's own per-fetch `AbortSignal.timeout` so a scan-/per-check
		 * timeout ABORTS the in-flight HTTPS subrequests rather than merely abandoning
		 * them — freeing the Cloudflare Workers subrequest budget. Absent (every direct
		 * `check_ssl` call) → byte-for-byte unchanged behaviour.
		 */
		signal?: AbortSignal;
		/**
		 * Opt IN to certificate metadata (issuer / expiry / SANs) from Certificate
		 * Transparency. DEFAULT OFF, and deliberately so.
		 *
		 * Enrichment costs one extra subrequest to Certspotter's public API, whose
		 * free tier is ~100 requests/hour/egress-IP and is SHARED across everything
		 * this Worker does. `scan_domain` fans out 17 checks per call, so enriching
		 * there would spend that quota at scan volume — and an exhausted quota
		 * degrades to no metadata at all, for every caller.
		 *
		 * So only the DIRECT `check_ssl` tool turns this on: that is the tool whose
		 * description promises issuer and expiry, and it is called one domain at a
		 * time. `scan_domain`, `validate_fix`, and `simulate_attack_paths` leave it
		 * off — none of them surfaces the field, so the request would be pure cost.
		 *
		 * A caching layer in front of Certspotter is what would make this safe to
		 * turn on everywhere; there isn't one on this Worker today.
		 */
		certMetadata?: boolean;
	} = {},
): Promise<CheckResult> {
	const fetchFn = withRobotsGate(withAbortSignal(fetch, tlsProbeOptions.signal));
	const base = (await checkSSL(domain, fetchFn, { timeout: HTTPS_TIMEOUT_MS })) as CheckResult;
	// Certificate metadata (issuer / expiry / SANs) from Certificate Transparency.
	// NON-SCORING: attaches to `metadata`, never appends a Finding — a CT lookup
	// failing must not move a domain's grade.
	//
	// Deliberately NOT robots-gated: the request goes to Certspotter's public API,
	// not to the scanned domain, so the target's robots.txt has no authority over
	// it. It IS abort-composed, so a scan-/per-check timeout cancels the in-flight
	// CT subrequest rather than leaking it from the subrequest budget (R7).
	const result = tlsProbeOptions.certMetadata
		? await enrichWithCertificateMetadata(base, domain, withAbortSignal(fetch, tlsProbeOptions.signal))
		: base;
	// Operator-only TLS-version enrichment via the BV_TLS_PROBE service binding.
	// NOTE this one DOES affect scoring (it appends a High finding), unlike the
	// certificate-metadata enrichment above.
	// Fail-soft: absent binding (every BSL self-host) → result returned unchanged.
	// callTlsProbe returns null on any failure; mergeTlsFinding only ever appends a
	// High finding when the probe actively reports legacy TLS (≤1.1), never penalizes 1.2/1.3.
	if (!tlsProbeOptions.tlsProbeBinding) return result;
	const probe = await callTlsProbe(tlsProbeOptions.tlsProbeBinding, tlsProbeOptions.tlsProbeAuthToken, domain, {
		telemetry: tlsProbeOptions.onBindingDegradation,
	});
	return probe ? mergeTlsFinding(result, probe) : result;
}
