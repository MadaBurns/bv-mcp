// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate Transparency source — URL construction + a pure parse of Certspotter
 * issuance JSON into `CertMetadata`.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 *
 * @module @blackveil/dns-checks/cert
 */

import { normalizeCertDate, type CertMetadata } from './cert-metadata';

export const CERTSPOTTER_ISSUANCES_URL = 'https://api.certspotter.com/v1/issuances';

/**
 * Build the Certspotter issuances URL with the expansions certificate metadata needs.
 *
 * `expand` is REPEATED, not comma-joined — Certspotter reads one field per param, and
 * a comma-joined value silently returns none of them.
 *
 * `expand=cert` carries the base64 DER used for key strength. Requesting it is
 * harmless when the caller cannot decode it (see `enrich.ts` — the decode is injected
 * and absent by default), it just goes unused.
 */
export function buildCertMetadataUrl(domain: string, includeSubdomains = true): string {
	const params = new URLSearchParams({
		domain,
		include_subdomains: String(includeSubdomains),
		expand: 'dns_names',
		match_wildcards: 'true',
	});
	params.append('expand', 'issuer');
	params.append('expand', 'not_before');
	params.append('expand', 'not_after');
	params.append('expand', 'cert');
	return `${CERTSPOTTER_ISSUANCES_URL}?${params.toString()}`;
}

interface CtIssuance {
	not_before?: string;
	not_after?: string;
	dns_names?: string[];
	issuer?: { name?: string };
	serial?: string;
	cert?: { data?: string; type?: string };
}

/**
 * Pick the most recently ISSUED entry by `not_before`.
 *
 * Deliberately not expiry-filtered: the newest issuance is the one that describes
 * the domain's current PKI posture, including when that newest cert has already
 * expired — which is precisely the state a reader needs to see. Null when nothing
 * parses. Never throws.
 */
function pickLatestIssuance(body: string): CtIssuance | null {
	let rows: CtIssuance[];
	try {
		rows = JSON.parse(body) as CtIssuance[];
	} catch {
		return null;
	}
	if (!Array.isArray(rows) || rows.length === 0) return null;
	return rows.reduce<CtIssuance | null>((best, cur) => {
		const b = normalizeCertDate(best?.not_before ?? null);
		const c = normalizeCertDate(cur.not_before ?? null);
		if (c == null) return best;
		if (b == null || c > b) return cur;
		return best;
	}, null);
}

/**
 * The base64 DER of the SAME issuance `parseCertMetadataFromCt` selects, or null when
 * absent. Kept separate from `CertMetadata` because the DER is transient key-strength
 * input, not metadata worth persisting. Never throws.
 */
export function parseCertDerFromCt(body: string): string | null {
	const latest = pickLatestIssuance(body);
	return latest?.cert?.data ?? null;
}

/** Parse Certspotter JSON → the latest certificate's metadata. Never throws. */
export function parseCertMetadataFromCt(body: string, domain: string): CertMetadata | null {
	const latest = pickLatestIssuance(body);
	if (!latest) return null;

	return {
		domain,
		issuer: latest.issuer?.name ?? null,
		notBefore: normalizeCertDate(latest.not_before ?? null),
		notAfter: normalizeCertDate(latest.not_after ?? null),
		sans: Array.isArray(latest.dns_names) ? latest.dns_names : [],
		serial: latest.serial ?? null,
		source: 'ct',
	};
}
