// SPDX-License-Identifier: BUSL-1.1

/**
 * The `metadata.servedCertificate` contract, shared by the prober (which runs in the
 * infra-probe sidecar) and its client (which runs in the main Worker and the package).
 *
 * Kept free of imports on purpose: the client must be able to load this without
 * pulling the raw-socket prober into a bundle that has no socket API.
 */

export const SERVED_CERTIFICATE_NOT_ASSESSED_REASONS = [
	/** The name has no address, or an address that is not public. */
	'no_public_address',
	/** The runtime refuses raw sockets to this address (its own network's ranges). */
	'runtime_blocked_address',
	'connect_failed',
	'timeout',
	/** The server would not negotiate TLS 1.2, the only version whose certificate is readable in the clear. */
	'tls12_refused',
	'handshake_unreadable',
	'certificate_unparseable',
	/** No raw-socket API in the runtime the prober ran in. */
	'socket_unavailable',
	/** This deployment has no probe sidecar bound, so no connection was attempted. */
	'probe_not_configured',
	/** The sidecar is bound but did not return a usable answer (down, or older than this lane). */
	'probe_unavailable',
] as const;

export type ServedCertificateNotAssessedReason = (typeof SERVED_CERTIFICATE_NOT_ASSESSED_REASONS)[number];

export const SERVED_CERTIFICATE_EXPIRY_BANDS = ['expired', 'critical', 'warning', 'ok', 'unknown'] as const;

export type ServedCertificateBlock =
	| {
			status: 'observed';
			issuer: string | null;
			subject: string | null;
			/** ISO-8601, or null when the certificate's date did not decode. */
			notBefore: string | null;
			notAfter: string | null;
			expiryBand: (typeof SERVED_CERTIFICATE_EXPIRY_BANDS)[number];
			daysRemaining: number | null;
			serial: string | null;
			fingerprintSha256: string;
			/** Always `'handshake'`: read from a live connection, not from a log. */
			source: 'handshake';
	  }
	| { status: 'not_assessed'; reason: ServedCertificateNotAssessedReason; source: 'handshake' };
