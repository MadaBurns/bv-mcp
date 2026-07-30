// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate expiry banding.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 *
 * @module @blackveil/dns-checks/cert
 */

export type ExpiryBand = 'expired' | 'critical' | 'warning' | 'ok' | 'unknown';

export interface ExpiryAssessment {
	band: ExpiryBand;
	/** Negative once the certificate has already expired. Null when notAfter is unknown. */
	daysRemaining: number | null;
}

/**
 * Classify a certificate's `notAfter` (epoch seconds) against now (epoch seconds).
 *
 * `unknown` is a distinct band, never folded into `ok`: no expiry date means we did
 * not measure one, which is not the same as a healthy one. Never throws.
 */
export function assessExpiry(notAfter: number | null, nowSeconds: number): ExpiryAssessment {
	if (notAfter == null) return { band: 'unknown', daysRemaining: null };
	const daysRemaining = Math.floor((notAfter - nowSeconds) / 86400);
	if (daysRemaining < 0) return { band: 'expired', daysRemaining };
	if (daysRemaining <= 7) return { band: 'critical', daysRemaining };
	if (daysRemaining <= 30) return { band: 'warning', daysRemaining };
	return { band: 'ok', daysRemaining };
}
