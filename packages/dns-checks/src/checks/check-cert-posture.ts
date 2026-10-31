// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate posture check (NON-SCORING category `cert_posture`).
 *
 * Judges one certificate the HOST injects — expiry, key strength, validity window — and
 * compares the CA that issued it with the CAs the domain's CAA policy authorises. It also
 * compares the domain's DANE TLSA pins with CT-derived certificates the host injects. The
 * certificates are injected rather than fetched so this package stays runtime-agnostic: a
 * Worker has no TLS peer-certificate API, so the caller supplies Certificate Transparency
 * data (see `cert/ct-source.ts`) and this check never opens a connection.
 *
 * Non-scoring: `NON_SCORING_CATEGORIES` removes this result from every score, finding
 * count and evidence ratio, so nothing here can move a grade.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 */

import type { CheckResult, DNSQueryFunction, Finding } from '../types';
import type { CertMetadata } from '../cert/cert-metadata';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';
import { isInconclusiveRcode, queryWithRcode } from '../dns-rcode';
import { effectiveCaaIssuers } from './caa-analysis';
import { buildCertPostureFindings, daneVsLoggedCertFindings, type TlsaLookup } from './cert-posture-analysis';
import type { ServedCertificate } from './dane-analysis';

export interface CheckCertPostureOptions {
	/** The certificate to judge. Null/absent → the posture findings abstain (a missing certificate is never a pass). */
	certificate: CertMetadata | null;
	/** Issuer DN to use instead of `certificate.issuer` (e.g. a fuller string from a DER decode). */
	issuerDn?: string | null;
	/**
	 * Certificates the HOST decoded from Certificate Transparency (e.g. CertSpotter DER), shaped as
	 * `ServedCertificate` digests so the DANE comparison can reuse `verifyTlsaAssociations`. This package
	 * never fetches or parses a certificate. Absent or empty → published TLSA records are reported as
	 * not compared. When supplied without `certificate`, only the DANE-vs-logged-certificate findings are produced.
	 */
	ctCertificates?: ServedCertificate[];
	/** Per-lookup DNS timeout in milliseconds (default 5000). */
	timeout?: number;
	/** Injectable clock, epoch SECONDS (default: now). For deterministic expiry bands in tests. */
	nowSeconds?: number;
}

function abstain(domain: string): CheckResult {
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

/** Read the TLSA RRset at one owner name; a throw or SERVFAIL/REFUSED is `unreadable`, never "no TLSA". */
async function lookupTlsa(name: string, queryDNS: DNSQueryFunction, timeout: number): Promise<TlsaLookup> {
	try {
		const outcome = await queryWithRcode(queryDNS, name, 'TLSA', timeout);
		return { name, records: outcome.records, unreadable: outcome.records.length === 0 && isInconclusiveRcode(outcome.rcode) };
	} catch {
		return { name, records: [], unreadable: true };
	}
}

/** TLSA lookups for the HTTPS endpoint of the domain and its `www` host. */
async function daneFindings(domain: string, queryDNS: DNSQueryFunction, certs: ServedCertificate[], timeout: number): Promise<Finding[]> {
	const hosts = domain.startsWith('www.') ? [domain] : [domain, `www.${domain}`];
	const lookups = await Promise.all(hosts.map((host) => lookupTlsa(`_443._tcp.${host}`, queryDNS, timeout)));
	return daneVsLoggedCertFindings(lookups, certs);
}

async function postureFindings(
	domain: string,
	queryDNS: DNSQueryFunction,
	cert: CertMetadata,
	options: CheckCertPostureOptions,
): Promise<Finding[]> {
	const caa = await effectiveCaaIssuers(domain, queryDNS, { timeout: options.timeout });
	const nowSeconds = options.nowSeconds ?? Math.floor(Date.now() / 1000);
	return buildCertPostureFindings(cert, options.issuerDn ?? cert.issuer, caa, nowSeconds);
}

/**
 * Assess one injected certificate's posture, and compare any DANE TLSA pins with injected CT certificates.
 *
 * @param domain - The domain the certificate belongs to; its CAA and TLSA records are read via `queryDNS`.
 * @param queryDNS - Injected resolver (CAA climb and TLSA lookups only).
 */
export async function checkCertPosture(
	domain: string,
	queryDNS: DNSQueryFunction,
	options?: CheckCertPostureOptions,
): Promise<CheckResult> {
	const cert = options?.certificate ?? null;
	if (options === undefined || (cert === null && options.ctCertificates === undefined)) return abstain(domain);

	const findings = [
		...(cert === null ? [] : await postureFindings(domain, queryDNS, cert, options)),
		...(await daneFindings(domain, queryDNS, options.ctCertificates ?? [], options.timeout ?? 5000)),
	];
	const metadata = cert === null ? undefined : { certSource: cert.source, notBefore: cert.notBefore, notAfter: cert.notAfter };
	return buildCheckResult('cert_posture', findings, undefined, undefined, metadata);
}
