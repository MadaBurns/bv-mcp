// SPDX-License-Identifier: BUSL-1.1
import { getRegistrableDomain } from '../../lib/public-suffix';
import { validateDomain } from '../../lib/sanitize';

/** Additive discovery evidence; neither a certificate nor its fan-out proves ownership. */
export interface SanCertificateProvenance {
	source: 'crtsh' | 'certspotter' | 'certstream';
	/** Canonical issuance identity; never substitute a pagination cursor or a name-set hash. */
	issuanceSha256: string | null;
	/** Candidates connected to this observation, rather than all certificates in the response. */
	candidateDomains: string[];
	candidateMappingComplete: boolean;
	/** Complete means a validated full-name issuance inside an uncut query, not an estate inventory. */
	coverage: 'complete' | 'unknown';
	/** Full-certificate registrable-domain count, withheld for incomplete or unidentified observations. */
	registrableDomainCount: number | null;
}

/** Bound work on provider-controlled names; crossing the cap withholds the fan-out count. */
const MAX_PROVENANCE_DNS_NAMES = 4096;
const MAX_PROVENANCE_CANDIDATES = 32;
export const MAX_SAN_PROVENANCE_OBSERVATIONS = 64;

export function buildSanCertificateProvenance(input: {
	source: SanCertificateProvenance['source'];
	tbsSha256?: unknown;
	dnsNames?: unknown;
	candidateDomains: readonly string[];
	/** Whole-query pagination/collection completed; incomplete queries conservatively withhold counts. */
	responseComplete: boolean;
}): SanCertificateProvenance {
	const issuanceSha256 =
		typeof input.tbsSha256 === 'string' && /^[a-fA-F0-9]{64}$/.test(input.tbsSha256) ? input.tbsSha256.toLowerCase() : null;
	const result: SanCertificateProvenance = {
		source: input.source,
		issuanceSha256,
		candidateDomains: [...new Set(input.candidateDomains)].sort().slice(0, MAX_PROVENANCE_CANDIDATES),
		candidateMappingComplete: input.candidateDomains.length <= MAX_PROVENANCE_CANDIDATES,
		coverage: 'unknown',
		registrableDomainCount: null,
	};
	// crt.sh search names are query-matched only; certstream names are aggregated.
	if (
		input.source !== 'certspotter' ||
		!issuanceSha256 ||
		!input.responseComplete ||
		!result.candidateMappingComplete ||
		!Array.isArray(input.dnsNames) ||
		input.dnsNames.length === 0 ||
		input.dnsNames.length > MAX_PROVENANCE_DNS_NAMES
	)
		return result;
	const apexes = new Set<string>();
	for (const raw of input.dnsNames) {
		if (typeof raw !== 'string') return result;
		const host = raw.toLowerCase().replace(/\.$/, '').replace(/^\*\./, '');
		if (!validateDomain(host).valid) return result;
		const apex = getRegistrableDomain(host);
		if (!apex) return result;
		apexes.add(apex);
	}
	return { ...result, coverage: 'complete', registrableDomainCount: apexes.size };
}
