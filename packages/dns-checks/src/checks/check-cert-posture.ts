// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate posture check (NON-SCORING category `cert_posture`).
 *
 * Judges one certificate the HOST injects — expiry, key strength, validity window — and
 * compares the CA that issued it with the CAs the domain's CAA policy authorises. The
 * certificate is injected rather than fetched so this package stays runtime-agnostic: a
 * Worker has no TLS peer-certificate API, so the caller supplies Certificate Transparency
 * metadata (see `cert/ct-source.ts`) and this check never opens a connection.
 *
 * Non-scoring: `NON_SCORING_CATEGORIES` removes this result from every score, finding
 * count and evidence ratio, so nothing here can move a grade.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction } from '../types';
import type { CertMetadata } from '../cert/cert-metadata';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';
import { effectiveCaaIssuers } from './caa-analysis';
import { buildCertPostureFindings } from './cert-posture-analysis';

export interface CheckCertPostureOptions {
	/** The certificate to judge. Null/absent → the check abstains (a missing certificate is never a pass). */
	certificate: CertMetadata | null;
	/** Issuer DN to use instead of `certificate.issuer` (e.g. a fuller string from a DER decode). */
	issuerDn?: string | null;
	/** Per-lookup DNS timeout in milliseconds (default 5000). */
	timeout?: number;
	/** Injectable clock, epoch SECONDS (default: now). For deterministic expiry bands in tests. */
	nowSeconds?: number;
}

/**
 * Assess one injected certificate's posture.
 *
 * @param domain - The domain the certificate belongs to; its CAA policy is read via `queryDNS`.
 * @param queryDNS - Injected resolver (used for the CAA climb only).
 */
export async function checkCertPosture(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: CheckCertPostureOptions,
): Promise<CheckResult> {
	const cert = options?.certificate ?? null;
	if (cert === null) {
		return buildNotAssessedResult(
			'cert_posture',
			createFinding(
				'cert_posture',
				'Certificate posture not assessed',
				'info',
				`No certificate was supplied for ${domain}, so expiry, key strength and CAA-versus-issuer were not assessed.`,
				{ notAssessed: true, confidence: 'heuristic' },
			),
		);
	}

	const caa = await effectiveCaaIssuers(domain, queryDNS, { timeout: options?.timeout });
	const issuerDn = options?.issuerDn ?? cert.issuer;
	const nowSeconds = options?.nowSeconds ?? Math.floor(Date.now() / 1000);
	const findings = buildCertPostureFindings(cert, issuerDn, caa, nowSeconds);
	return buildCheckResult('cert_posture', findings, undefined, undefined, {
		certSource: cert.source,
		notBefore: cert.notBefore,
		notAfter: cert.notAfter,
	});
}
