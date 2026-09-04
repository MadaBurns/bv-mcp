// SPDX-License-Identifier: BUSL-1.1

/**
 * A real served-certificate fixture for the DANE pin-verification tests (#841).
 *
 * Every value below was derived with OpenSSL from ONE throwaway self-signed P-256
 * certificate (CN=example.test, 1-day validity, generated outside the repo), so the
 * comparison logic is proven against an independent implementation rather than
 * against itself:
 *
 *   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
 *     -subj /CN=example.test -keyout /dev/null -out cert.pem
 *   openssl x509 -in cert.pem -outform DER -out cert.der
 *   openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform DER -out spki.der
 *   openssl dgst -sha256 -r cert.der   # LEAF_SHA256      (TLSA selector 0, matching 1)
 *   openssl dgst -sha512 -r cert.der   # LEAF_SHA512      (selector 0, matching 2)
 *   openssl dgst -sha256 -r spki.der   # LEAF_SPKI_SHA256 (selector 1, matching 1)
 *   openssl dgst -sha512 -r spki.der   # LEAF_SPKI_SHA512 (selector 1, matching 2)
 *   base64 cert.der / spki.der         # LEAF_DER_B64 / LEAF_SPKI_DER_B64 (matching 0 inputs)
 *   xxd -p cert.der / spki.der         # LEAF_DER_HEX / LEAF_SPKI_DER_HEX (matching 0 pins)
 *
 * The private key was discarded (`-keyout /dev/null`); nothing here is a secret.
 */

import type { ServedCertificate } from '../../checks/dane-analysis';

export const LEAF_DER_B64 =
	'MIIBgzCCASmgAwIBAgIUAU42LRqp7O5gToUGUj4O08EBkOMwCgYIKoZIzj0EAwIwFzEVMBMGA1UEAwwMZXhhbXBsZS50ZXN0MB4XDTI2MDkwMzIzNDUzMloXDTI2MDkwNDIzNDUzMlowFzEVMBMGA1UEAwwMZXhhbXBsZS50ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2lPDQNRz6ePZ4OCkA3yAsY8tu0ttDIj6gyo0GDLxZDAHGk1NGS1vGlya395iEerZEGImLMb9pf/cysEjHjzSEKNTMFEwHQYDVR0OBBYEFATZ4DzM2/nMBVJCQgWbIThkBpGQMB8GA1UdIwQYMBaAFATZ4DzM2/nMBVJCQgWbIThkBpGQMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAPzNiz2u+0aIJQlUNlRpHDN/wXI5FmR3nqMAvP9rjJ2QAiBDOuM+k5C7tGiagmlSOoqVJtNL2GteibqvHf8FTqfIfA==';
export const LEAF_SPKI_DER_B64 =
	'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2lPDQNRz6ePZ4OCkA3yAsY8tu0ttDIj6gyo0GDLxZDAHGk1NGS1vGlya395iEerZEGImLMb9pf/cysEjHjzSEA==';

export const LEAF_SHA256 = '7a9bcc4b1bc7d041e4a9a4165792c51ba980ee1fe649206b62ee03e36c9d3b6d';
export const LEAF_SHA512 =
	'3f073ff1e8be79dac7f333f4e55a8c1dc114a034fb597a9e17e6f1e1f4a1c9b66c5a64d0481bc8f350ca2c015e09efafe28f118f5848db1fe311d97e134c04c5';
export const LEAF_SPKI_SHA256 = '94b19b8aa7a903c5aaec27633d30f44ba3be5d3da686337f062830efcdd1db56';
export const LEAF_SPKI_SHA512 =
	'e7e28199c4b3df9fdab90e08267cd6be504935d4b44a8a2dde36636549cc01280bd54d9cae7299d45ce1fb2671528978f74d7d83423fc520107c23b3e58c2312';

/** Full-data (matching type 0) pins: hex of the DER, as TLSA presentation carries them. */
export const LEAF_DER_HEX =
	'3082018330820129a0030201020214014e362d1aa9ecee604e8506523e0ed3c10190e3300a06082a8648ce3d04030230173115301306035504030c0c6578616d706c652e74657374301e170d3236303930333233343533325a170d3236303930343233343533325a30173115301306035504030c0c6578616d706c652e746573743059301306072a8648ce3d020106082a8648ce3d03010703420004da53c340d473e9e3d9e0e0a4037c80b18f2dbb4b6d0c88fa832a341832f16430071a4d4d192d6f1a5c9adfde6211ead91062262cc6fda5ffdccac1231e3cd210a3533051301d0603551d0e0416041404d9e03cccdbf9cc05524242059b213864069190301f0603551d2304183016801404d9e03cccdbf9cc05524242059b213864069190300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100fccd8b3daefb46882509543654691c337fc172391664779ea300bcff6b8c9d900220433ae33e9390bbb4689a8269523a8a9526d34bd86b5e89baaf1dff054ea7c87c';
export const LEAF_SPKI_DER_HEX =
	'3059301306072a8648ce3d020106082a8648ce3d03010703420004da53c340d473e9e3d9e0e0a4037c80b18f2dbb4b6d0c88fa832a341832f16430071a4d4d192d6f1a5c9adfde6211ead91062262cc6fda5ffdccac1231e3cd210';

/** A digest that matches nothing — the "stale pin" of issue #841. */
export const STALE_SHA256 = 'b5d294f0346bc9b8b1d9396e93537b750784fa385d514c1bcb7f3b7a606a432a';

/**
 * A synthetic intermediate for the DANE-TA / PKIX-TA chain paths. Its digests are
 * arbitrary distinct values (they need only be findable in the chain, not derivable),
 * and it deliberately carries NO `spkiDer` — the probe contract has none for non-leaf
 * entries — so a selector-1 / matching-0 TA pin against it is UNVERIFIABLE.
 */
export const INTERMEDIATE_SHA256 = 'c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2';
export const INTERMEDIATE_SHA512 =
	'd2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5';
export const INTERMEDIATE_SPKI_SHA256 = 'e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4';
export const INTERMEDIATE_SPKI_SHA512 =
	'f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7';
/** base64 of the bytes 0x30 0x03 0x02 0x01 0x01 (a tiny stand-in DER; hex 3003020101). */
export const INTERMEDIATE_DER_B64 = 'MAMCAQE=';
export const INTERMEDIATE_DER_HEX = '3003020101';

/** The served certificate exactly as bv-tls-probe reports it, host pinned to the scanned name. */
export function servedCertificate(host = 'example.com', overrides: Partial<ServedCertificate> = {}): ServedCertificate {
	return {
		host,
		port: 443,
		capturedAt: '2026-09-04T00:00:00.000Z',
		leafDer: LEAF_DER_B64,
		leafSpkiDer: LEAF_SPKI_DER_B64,
		leafSha256: LEAF_SHA256,
		leafSha512: LEAF_SHA512,
		leafSpkiSha256: LEAF_SPKI_SHA256,
		leafSpkiSha512: LEAF_SPKI_SHA512,
		chain: [
			{ sha256: LEAF_SHA256, sha512: LEAF_SHA512, spkiSha256: LEAF_SPKI_SHA256, spkiSha512: LEAF_SPKI_SHA512, der: LEAF_DER_B64 },
			{
				sha256: INTERMEDIATE_SHA256,
				sha512: INTERMEDIATE_SHA512,
				spkiSha256: INTERMEDIATE_SPKI_SHA256,
				spkiSha512: INTERMEDIATE_SPKI_SHA512,
				der: INTERMEDIATE_DER_B64,
			},
		],
		subjectName: 'example.test',
		...overrides,
	};
}
