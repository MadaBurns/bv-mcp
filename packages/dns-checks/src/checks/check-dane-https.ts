// SPDX-License-Identifier: BUSL-1.1

/**
 * DANE-HTTPS check.
 * Validates TLSA records specifically for the HTTPS endpoint (_443._tcp.{domain}).
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding, RawDNSQueryFunction } from '../types';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';
import { analyzeTlsaRecords, DANE_PIN_NOT_ASSESSED_REASONS, isTransientDanePinReason } from './dane-analysis';
import type { TlsaVerificationContext } from './dane-analysis';

/** Options for {@link checkDANEHTTPS}. */
export interface CheckDaneHttpsOptions extends TlsaVerificationContext {
	timeout?: number;
	rawQueryDNS?: RawDNSQueryFunction;
	/**
	 * Lazy certificate source (#841). Called ONLY when the TLSA lookup returned records —
	 * DANE-for-HTTPS adoption is ~0%, so an eager probe would spend a Browser Rendering
	 * session on every scan to verify nothing. A throwing resolver is a `failed` probe
	 * (`probe_unavailable`, unverified at 95, re-tried), never a verdict. Takes precedence over the static `servedCertificate` /
	 * `certificateProbe` fields when both are supplied.
	 */
	resolveServedCertificate?: () => Promise<TlsaVerificationContext>;
}

/**
 * Check DANE TLSA records for a domain's HTTPS endpoint (_443._tcp.{domain}).
 *
 * With a served certificate (or a `resolveServedCertificate` source) the pinned data is
 * VERIFIED against it — see `analyzeTlsaRecords` for the verdict ladder. Without one
 * (every BSL self-host) the result is the 1.18.0 "present, not verified" posture.
 */
export async function checkDANEHTTPS(domain: string, queryDNS: DNSQueryFunction, options?: CheckDaneHttpsOptions): Promise<CheckResult> {
	const timeout = options?.timeout ?? 5000;
	const rawQueryDNS = options?.rawQueryDNS;
	const findings: Finding[] = [];
	let hasDnssec = false;

	// Step 1: Check DNSSEC status for the domain
	if (rawQueryDNS) {
		try {
			const resp = await rawQueryDNS(domain, 'A', true, { timeout });
			hasDnssec = resp.AD === true;
		} catch {
			// DNSSEC check failed — continue without it
		}
	}

	// Step 2: Query TLSA records at _443._tcp.{domain}
	const tlsaName = `_443._tcp.${domain}`;
	let tlsaRecords: string[];
	try {
		tlsaRecords = await queryDNS(tlsaName, 'TLSA', { timeout });
	} catch {
		// A THROWN TLSA lookup (transport error / timeout) never got a resolver's answer, so
		// nothing was measured: abstain in the not-assessed shape (checkStatus 'error', score 0,
		// partial) so scoring excludes the category. This used to return a COMPLETED `low`
		// finding scored 95 — a cut probe counted as measured evidence (SQ-201). An answered-empty
		// or NXDOMAIN lookup does not throw and still reaches the "No DANE TLSA" branch below.
		// `recordPresent` stays undefined ("not determined"), never false.
		return buildNotAssessedResult(
			'dane_https',
			createFinding(
				'dane_https',
				'DANE HTTPS not assessed — TLSA query failed',
				'info',
				`DNS query for TLSA records at ${tlsaName} failed before any resolver answered. This is not evidence either way about DANE for ${domain} — the category is excluded from scoring rather than passed. Re-run the check once name resolution is working.`,
				{ inconclusive: true, errorKind: 'dns_error' },
			),
			'error',
		);
	}

	const hasHttpsTlsa = tlsaRecords.length > 0;
	if (hasHttpsTlsa) {
		findings.push(...analyzeTlsaRecords(tlsaRecords, tlsaName, hasDnssec, await resolveVerification(options)));
	}

	// Step 3: If no TLSA records found, classify absence
	if (!hasHttpsTlsa) {
		findings.push(
			createFinding(
				'dane_https',
				'No DANE TLSA for HTTPS',
				'low',
				`No TLSA record found at ${tlsaName}. DANE can pin web server certificates to DNS, providing an additional layer of trust beyond the CA system. Implement DANE-EE (usage 3) with DNSSEC enabled for maximum security.`,
			),
		);
	}

	// Step 4: Handle case where all DNS queries failed and findings is empty
	if (findings.length === 0) {
		findings.push(
			createFinding(
				'dane_https',
				'DANE HTTPS check inconclusive',
				'medium',
				`DNS queries for DANE HTTPS TLSA records failed for ${domain}. Unable to determine DANE HTTPS status.`,
			),
		);
	}

	// Remap any finding categories to 'dane_https' (analyzeTlsaRecords produces 'dane' category)
	const remapped = findings.map((f) => ({ ...f, category: 'dane_https' as const }));

	// `recordPresent` = a TLSA record was observed at _443._tcp. The category remap above is
	// cosmetic (finding provenance) and does not bear on publication. A failed lookup returned
	// the not-assessed result above, so every result reaching here answered.
	const result = buildCheckResult('dane_https', remapped, undefined, hasHttpsTlsa);
	// An ATTEMPTED-but-unanswered pin verification with a TRANSIENT reason (cold-cache
	// pending, host unreachable, probe 5xx/throw, capture hiccup) gets `partial: true`,
	// which keeps it out of the scan-TTL cache so the next scan re-tries (mirrors the
	// MTA-STS not-assessed shape, #889). Permanent reasons (off-host redirect, host
	// mismatch, truncated chain) cache normally — no retry-forever. `checkStatus` is
	// deliberately NOT set — the TLSA measurement itself is real, so the category stays
	// completed and scored (at the unverified 95).
	const retryable = remapped.some(
		(f) =>
			(f.metadata?.certificateProbe === 'pending' || f.metadata?.certificateProbe === 'failed') &&
			isTransientDanePinReason(f.metadata?.notAssessedReason),
	);
	return retryable ? { ...result, partial: true } : result;
}

/**
 * Resolve the verification context: the lazy source wins; a throw is a `failed` probe.
 * Absent everything → `{}` → the analyzer's default `unavailable` posture.
 */
async function resolveVerification(options: CheckDaneHttpsOptions | undefined): Promise<TlsaVerificationContext> {
	if (!options) return {};
	if (options.resolveServedCertificate) {
		try {
			return await options.resolveServedCertificate();
		} catch {
			return { certificateProbe: 'failed', certificateProbeReason: DANE_PIN_NOT_ASSESSED_REASONS.probeUnavailable };
		}
	}
	return {
		servedCertificate: options.servedCertificate,
		certificateProbe: options.certificateProbe,
		certificateProbeReason: options.certificateProbeReason,
	};
}
