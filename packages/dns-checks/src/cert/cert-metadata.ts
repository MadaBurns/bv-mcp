// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate metadata vocabulary — pure data, provenance-tagged.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 *
 * @module @blackveil/dns-checks/cert
 */

/** Certificate metadata, provenance-tagged. Pure data — never contains bindings. */
export interface CertMetadata {
	domain: string;
	issuer: string | null;
	/** epoch SECONDS */
	notBefore: number | null;
	/** epoch SECONDS */
	notAfter: number | null;
	sans: string[];
	serial: string | null;
	/**
	 * Where the metadata came from. `'ct'` = a Certificate Transparency log entry
	 * (what a CA published); `'live'` = read off an actual TLS handshake. These are
	 * NOT interchangeable: a renewed cert appears in CT before it is installed, and
	 * a self-signed / private-CA cert never appears in CT at all. Callers that render
	 * this must say which one they are showing.
	 */
	source: 'ct' | 'live';
	keyType?: 'rsa' | 'ec' | 'unknown';
	keyBits?: number | null;
	sigAlg?: string | null;
	chainAuthorized?: boolean | null;
	chainError?: string | null;
}

/**
 * Parse a certificate date to epoch SECONDS. Accepts an ISO-8601 string, Node's
 * `"Mon DD HH:MM:SS YYYY GMT"` form, or a numeric epoch. Never throws.
 */
export function normalizeCertDate(input: string | number | null): number | null {
	if (input == null) return null;
	if (typeof input === 'number') return Number.isFinite(input) ? Math.floor(input) : null;
	const ms = Date.parse(input);
	return Number.isNaN(ms) ? null : Math.floor(ms / 1000);
}

/**
 * Merge CT-sourced and live-probed metadata. Live (actually-served) wins field by
 * field; CT fills the gaps. Never throws.
 */
export function mergeCertSources(ct: CertMetadata | null, live: CertMetadata | null): CertMetadata | null {
	if (live && ct) {
		return {
			...ct,
			...live,
			sans: live.sans.length ? live.sans : ct.sans,
			issuer: live.issuer ?? ct.issuer,
			notAfter: live.notAfter ?? ct.notAfter,
			notBefore: live.notBefore ?? ct.notBefore,
		};
	}
	return live ?? ct ?? null;
}
