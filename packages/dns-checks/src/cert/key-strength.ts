// SPDX-License-Identifier: BUSL-1.1

/**
 * Public-key strength banding + the pure key-material normalization helpers.
 *
 * These map the primitives a DER decode yields (`asymmetricKeyType`,
 * `asymmetricKeyDetails`) onto this package's vocabulary. The decode ITSELF is not
 * here and never will be: it needs `node:crypto`, and this package is deliberately
 * runtime-agnostic (zero `node:` imports, so it runs unmodified on workerd without
 * `nodejs_compat`). See `enrich.ts` `DerKeyParser` for the injection seam.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 *
 * @module @blackveil/dns-checks/cert
 */

export type KeyStrengthBand = 'weak' | 'acceptable' | 'strong' | 'unknown';

/** Normalize a runtime's `asymmetricKeyType` ("rsa" | "ec" | "ed25519" | …) to our vocabulary. */
export function normalizeKeyType(raw: string | null | undefined): 'rsa' | 'ec' | 'unknown' {
	if (!raw) return 'unknown';
	const s = raw.toLowerCase();
	if (s === 'rsa' || s === 'rsa-pss') return 'rsa';
	if (s === 'ec' || s === 'ecdsa') return 'ec';
	return 'unknown';
}

/**
 * Map an EC named curve to its bit-strength — the field an X.509 decode exposes for
 * EC keys, which have no `modulusLength`. Accepts both the OpenSSL name
 * (`prime256v1`) and the NIST alias (`P-256`). Unknown curve → null.
 */
export function ecCurveToBits(curve: string | null | undefined): number | null {
	if (!curve) return null;
	switch (curve.toLowerCase()) {
		case 'prime256v1':
		case 'secp256r1':
		case 'p-256':
			return 256;
		case 'secp384r1':
		case 'p-384':
			return 384;
		case 'secp521r1':
		case 'p-521':
			return 521;
		default:
			return null;
	}
}

/**
 * Band a key from its type, size, and signature algorithm.
 *
 * `unknown` when there is nothing to judge — absent key material is not a finding
 * about the certificate. A weak SIGNATURE alone is enough to band `weak` even with
 * no key size, because MD5/SHA-1 is a defect on its own terms. Never throws.
 */
export function assessKeyStrength(input: { keyType?: string; keyBits?: number | null; sigAlg?: string | null }): {
	band: KeyStrengthBand;
	reasons: string[];
} {
	const reasons: string[] = [];
	const { keyType, keyBits, sigAlg } = input;
	// `sha1(?!\d)` so "sha1" matches but "sha1024"-shaped strings do not.
	const weakSig = !!sigAlg && /md5|sha1(?!\d)/i.test(sigAlg);
	if (weakSig) {
		const algDisplay = sigAlg?.toLowerCase().includes('md5') ? 'MD5' : 'SHA-1';
		reasons.push(`Weak signature algorithm: ${algDisplay}`);
	}

	if (keyType == null || keyBits == null) {
		if (weakSig) return { band: 'weak', reasons };
		return { band: 'unknown', reasons };
	}

	const isRsa = /rsa/i.test(keyType);
	const isEc = /ec|ecdsa/i.test(keyType);

	if (isRsa && keyBits < 2048) reasons.push(`RSA key too small: ${keyBits} bits`);
	if (isEc && keyBits < 256) reasons.push(`EC key too small: ${keyBits} bits`);
	if (weakSig || (isRsa && keyBits < 2048) || (isEc && keyBits < 256)) {
		return { band: 'weak', reasons };
	}
	if ((isRsa && keyBits >= 3072) || (isEc && keyBits >= 256)) {
		return { band: 'strong', reasons };
	}
	return { band: 'acceptable', reasons }; // RSA 2048..3071
}
