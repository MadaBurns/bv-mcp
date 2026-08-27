// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate enrichment orchestrator — fetch a domain's Certificate Transparency
 * record and fold it into metadata + expiry band + key-strength band.
 *
 * SCOPE. This produces ADDITIVE metadata. It emits no `Finding`, touches no
 * `CheckResult.score`, and is not part of the scored check matrix — the scoring
 * engine and its parity corpus are unaffected by anything in this module. A caller
 * attaches the output to `CheckResult.metadata`, never to `findings`.
 *
 * SOURCING. CT tells you what a CA published, not what a server is currently
 * serving. A renewed certificate appears in CT before it is installed, and a
 * self-signed or private-CA certificate never appears at all. `CertMetadata.source`
 * carries this distinction; any surface rendering these fields must preserve it.
 *
 * Degrade-soft: every fetch/parse failure collapses that source to null. Never throws.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 *
 * @module @blackveil/dns-checks/cert
 */

import type { FetchFunction } from '../types';
import { readResponseTextCapped } from '../response-body';
import { buildCertMetadataUrl, parseCertMetadataFromCt, parseCertDerFromCt } from './ct-source';
import { mergeCertSources, type CertMetadata } from './cert-metadata';
import { assessExpiry, type ExpiryAssessment } from './expiry';
import { assessKeyStrength, type KeyStrengthBand } from './key-strength';

/** Cap on the UNTRUSTED CT-feed body — a hostile or inflated upstream cannot OOM the caller. */
const CT_FEED_MAX_BODY_BYTES = 5 * 1024 * 1024;

/**
 * Decode a base64 certificate DER into key-strength primitives.
 *
 * INJECTED, never imported. Decoding X.509 requires `node:crypto`, and this package
 * is runtime-agnostic by design — it must keep running on a workerd deployment with
 * no `nodejs_compat` flag (which is exactly the bv-mcp server's configuration). A
 * host that CAN decode passes one in and gets key-strength banding; a host that
 * cannot omits it and gets `band: 'unknown'`, which is the honest answer rather than
 * a guess.
 *
 * Implementations must never throw — return null on any decode failure.
 */
export type DerKeyParser = (base64Der: string) => {
	keyType: 'rsa' | 'ec' | 'unknown';
	keyBits: number | null;
	sigAlg: string | null;
} | null;

export interface CertEnrichmentResult {
	/** True only when actual metadata was obtained. False is "we found nothing", NOT "nothing is wrong". */
	available: boolean;
	meta: CertMetadata | null;
	expiry: ExpiryAssessment;
	keyStrength: { band: KeyStrengthBand; reasons: string[] };
}

export interface CertEnrichmentOptions {
	domain: string;
	/** Current time as epoch SECONDS (injected — this package never reads a clock). */
	nowSeconds: number;
	fetchFn: FetchFunction;
	/** Optional X.509 DER decoder; absent → key strength stays `unknown`. See `DerKeyParser`. */
	derKeyParser?: DerKeyParser;
	/** Optional live-TLS probe. Absent on workerd, where a raw TLS handshake is not reachable. */
	probeLive?: (host: string) => Promise<CertMetadata | null>;
}

export async function enrichCertificateIntelligence(options: CertEnrichmentOptions): Promise<CertEnrichmentResult> {
	const { domain, nowSeconds, fetchFn, derKeyParser, probeLive } = options;

	let ct: CertMetadata | null = null;
	try {
		const res = await fetchFn(buildCertMetadataUrl(domain), { headers: { accept: 'application/json' } });
		if (res.ok) {
			const body = await readResponseTextCapped(res, CT_FEED_MAX_BODY_BYTES);
			if (body != null) {
				ct = parseCertMetadataFromCt(body, domain);
				// Key strength comes from the SAME issuance the metadata came from —
				// decoding a different cert's DER would report strength for a
				// certificate whose issuer/expiry we are not showing.
				if (ct && derKeyParser) {
					const der = parseCertDerFromCt(body);
					const ks = der ? derKeyParser(der) : null;
					if (ks) {
						ct.keyType = ks.keyType;
						ct.keyBits = ks.keyBits;
						ct.sigAlg = ks.sigAlg;
					}
				}
			}
		} else {
			void res.body?.cancel();
		}
	} catch {
		ct = null; // degrade-soft
	}

	let live: CertMetadata | null = null;
	if (probeLive) {
		try {
			live = await probeLive(domain);
		} catch {
			live = null; // degrade-soft
		}
	}

	const meta = mergeCertSources(ct, live);
	return {
		available: meta != null,
		meta,
		expiry: assessExpiry(meta?.notAfter ?? null, nowSeconds),
		keyStrength: assessKeyStrength({
			keyType: meta?.keyType,
			keyBits: meta?.keyBits,
			sigAlg: meta?.sigAlg,
		}),
	};
}
