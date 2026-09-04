// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE-HTTPS check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 *
 * Operator-only enrichment (#841): when a `tlsProbeBinding` is provided (the BV_TLS_PROBE
 * service binding), the certificate the host serves on :443 is captured and every TLSA
 * association is VERIFIED against it — a stale pin becomes a `high` mismatch, a matching
 * one a verified `info`. BSL self-hosts without the binding receive the unmodified base
 * result (present, not verified — the 1.18.0 posture).
 */

import { checkDANEHTTPS } from '@blackveil/dns-checks';
import type { TlsaVerificationContext } from '@blackveil/dns-checks';
import { queryDns } from '../lib/dns';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import type { CheckResult } from '../lib/scoring';
import { callTlsProbe, servedCertificateFromProbe } from '../lib/tls-probe-binding';
import type { TlsProbeBinding, BindingDegradationSink } from '../lib/tls-probe-binding';
import { createFetchBudget } from '../lib/fetch-budget';

/** Operator-only certificate-probe options for {@link checkDaneHttps}. Mirrors `checkSsl`'s. */
export interface CheckDaneHttpsProbeOptions {
	/** The BV_TLS_PROBE service binding (absent on all BSL self-hosts). */
	tlsProbeBinding?: TlsProbeBinding;
	/** Bearer token forwarded to the probe endpoint. */
	tlsProbeAuthToken?: string;
	onBindingDegradation?: BindingDegradationSink;
	/** Caller-supplied abort signal (scan per-check / scan-level) — composed into the probe call. */
	signal?: AbortSignal;
	/**
	 * Wall-clock this check may spend on the probe (issue #641 pattern). The probe is a
	 * service binding, not a `fetch`, so a fetch-wrapper budget cannot meter it —
	 * `budget.signal()` is what caps it at the shared deadline (the same lesson
	 * `check_ssl` learned). Absent (every direct call) → the probe's own 8s timeout.
	 */
	budgetMs?: number;
}

/**
 * Check DANE TLSA records for a domain's HTTPS endpoint (_443._tcp.{domain}).
 *
 * The probe is LAZY: the package calls `resolveServedCertificate` only when the TLSA
 * lookup returned records, so the ~100% of domains with no DANE never spend a Browser
 * Rendering session. The probe host is EXACTLY `domain` — the TLSA owner is
 * `_443._tcp.<domain>`, and DANE pins that host's certificate, not whatever an apex →
 * `www` redirect lands on; `servedCertificateFromProbe` asserts the capture's host.
 */
export async function checkDaneHttps(
	domain: string,
	dnsOptions?: QueryDnsOptions,
	probeOptions: CheckDaneHttpsProbeOptions = {},
): Promise<CheckResult> {
	const budget = createFetchBudget(probeOptions.budgetMs);
	const binding = probeOptions.tlsProbeBinding;
	// Fail-soft end to end: `callTlsProbe` returns null on any failure and the `.catch`
	// is belt-and-braces; the package turns a throwing resolver into a `failed` probe
	// (unmeasured), never into a verdict.
	const resolveServedCertificate = binding
		? async (): Promise<TlsaVerificationContext> => {
				const probe = await callTlsProbe(binding, probeOptions.tlsProbeAuthToken, domain, {
					telemetry: probeOptions.onBindingDegradation,
					signal: budget.signal(probeOptions.signal),
				}).catch(() => null);
				return servedCertificateFromProbe(probe, domain);
			}
		: undefined;
	return checkDANEHTTPS(domain, makeQueryDNS(dnsOptions), {
		timeout: dnsOptions?.timeoutMs ?? 5000,
		rawQueryDNS: async (d, type, dnssecFlag) => {
			const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
			return { AD: resp.AD, Answer: resp.Answer };
		},
		resolveServedCertificate,
	}) as Promise<CheckResult>;
}
