// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate-metadata enrichment for `check_ssl` — issuer, expiry, SANs.
 *
 * WHY THIS EXISTS. `check_ssl`'s tool description promised "the issuer (Certificate
 * Authority), expiry date … and supported protocol versions", and the tool returned
 * none of them — its own success finding said certificate expiry "requires a
 * dedicated TLS scanner". That was a documented capability the product did not have.
 * This closes the issuer/expiry half of the gap from Certificate Transparency; TLS
 * protocol versions remain probe-only (the operator BV_TLS_PROBE binding) and the
 * description no longer claims otherwise.
 *
 * STRICTLY NON-SCORING. This attaches to `CheckResult.metadata` and NEVER appends a
 * `Finding`. The `ssl` category score, the 17-check matrix, and the scoring parity
 * corpus are all untouched — deliberately, so a CT lookup failing (or Certspotter
 * rate-limiting) can never move a domain's grade. Contrast `mergeTlsFinding`, which
 * DOES append a finding and therefore does affect scoring.
 *
 * KEY STRENGTH IS ABSENT HERE, ON PURPOSE. Decoding the X.509 DER needs
 * `node:crypto`, and this Worker runs without the `nodejs_compat` flag. Rather than
 * guess, no `derKeyParser` is injected and the band stays `unknown`. A host that can
 * decode (bv-web-prod, which has nodejs_compat) injects one and gets real banding.
 *
 * Fail-soft: any failure returns the result unchanged.
 */

import { enrichCertificateIntelligence } from '@blackveil/dns-checks';
import type { CheckResult } from '../lib/scoring';
import type { FetchFunction } from '@blackveil/dns-checks';

/** Shape attached at `CheckResult.metadata.certificate`. */
export interface CertificateMetadataBlock {
	issuer: string | null;
	/** ISO-8601, or null when the CT record carried no such date. */
	notBefore: string | null;
	notAfter: string | null;
	expiryBand: 'expired' | 'critical' | 'warning' | 'ok' | 'unknown';
	daysRemaining: number | null;
	sanCount: number;
	serial: string | null;
	/**
	 * Always `'ct'` here. Retained explicitly so a consumer never has to assume:
	 * these fields describe the most recently LOGGED certificate, which is not
	 * necessarily the one being served right now.
	 */
	source: 'ct';
}

function toIso(epochSeconds: number | null): string | null {
	if (epochSeconds == null || !Number.isFinite(epochSeconds)) return null;
	try {
		return new Date(epochSeconds * 1000).toISOString();
	} catch {
		return null;
	}
}

/**
 * Enrich an `ssl` CheckResult with certificate metadata from CT.
 *
 * Returns the result UNCHANGED when nothing was found — an absent CT record is not
 * evidence about the domain's TLS posture, and an empty `certificate` block would
 * read as "we looked and there is no certificate".
 */
export async function enrichWithCertificateMetadata(
	result: CheckResult,
	domain: string,
	fetchFn: FetchFunction,
	nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<CheckResult> {
	let enrichment;
	try {
		enrichment = await enrichCertificateIntelligence({ domain, nowSeconds, fetchFn });
	} catch {
		return result; // fail-soft — enrichment must never break the check
	}

	if (!enrichment.available || !enrichment.meta) return result;

	const certificate: CertificateMetadataBlock = {
		issuer: enrichment.meta.issuer,
		notBefore: toIso(enrichment.meta.notBefore),
		notAfter: toIso(enrichment.meta.notAfter),
		expiryBand: enrichment.expiry.band,
		daysRemaining: enrichment.expiry.daysRemaining,
		sanCount: enrichment.meta.sans.length,
		serial: enrichment.meta.serial,
		source: 'ct',
	};

	// Spread the EXISTING metadata first so a sibling enricher's keys survive.
	return { ...result, metadata: { ...result.metadata, certificate } };
}
