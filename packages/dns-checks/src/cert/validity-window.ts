// SPDX-License-Identifier: BUSL-1.1

/**
 * Certificate validity-window banding — automation readiness under CA/Browser Forum
 * ballot SC-081.
 *
 * SC-081's 200-day maximum certificate lifetime took force on 2026-03-15. A short
 * window is not a defect: it is the observable signature of a working automated
 * renewal pipeline, which is why the bands read as readiness (`exemplary` /
 * `automated` / `compliant`) rather than severity.
 *
 * Additive and non-scoring, like the rest of this module — see `index.ts`. This emits
 * no `Finding` and feeds no score.
 *
 * Copyright (c) 2023-2026 BLACKVEIL Security
 * Licensed under BUSL-1.1
 *
 * @module @blackveil/dns-checks/cert
 */

/** The SC-081 maximum certificate lifetime, in days. */
export const SC081_MAX_LIFETIME_DAYS = 200;

/**
 * The date the SC-081 maximum took force: 2026-03-15T00:00:00Z, epoch SECONDS.
 *
 * A FIXED standards date, deliberately a constant and never `Date.now()` — the band
 * is a property of the certificate judged against the standard, so parity fixtures
 * stay deterministic. Injectable via `assessValidityWindow`'s second parameter,
 * following the `nowSeconds` convention `assessExpiry` already sets.
 */
export const SC081_EFFECTIVE_SECONDS = 1_773_532_800;

/**
 * Automation-readiness band for a certificate's validity window.
 *
 * `unknown` is a distinct member and NEVER a boolean: an unmeasured window must not
 * compile into `false`, which would be an affirmative safety claim from zero evidence.
 * `legacy` is likewise distinct from `anomaly` — a long window issued BEFORE the
 * maximum took force was legitimately issued and is still valid.
 */
export type ValidityWindowBand =
	| 'exemplary' // <= 47d — renewal is demonstrably automated
	| 'automated' // <= 100d
	| 'compliant' // <= 200d, the SC-081 maximum
	| 'legacy' // > 200d, but issued before the maximum took force — legitimate
	| 'anomaly' // > 200d and issued under the maximum — not expected from a public CA
	| 'invalid' // notAfter <= notBefore — a degenerate window, not a measurement
	| 'unknown'; // a date was missing — we did not measure this

export interface ValidityWindowAssessment {
	band: ValidityWindowBand;
	/** Window length in days. Null when a date is unknown; never negative. */
	days: number | null;
}

/**
 * Band a certificate's validity window (both dates in epoch SECONDS) against the
 * SC-081 maximum-lifetime date.
 *
 * Reads no wall clock: `effectiveSeconds` is the standards date, passed in. Never
 * throws.
 */
export function assessValidityWindow(
	cert: { notBefore: number | null; notAfter: number | null },
	effectiveSeconds: number = SC081_EFFECTIVE_SECONDS,
): ValidityWindowAssessment {
	const { notBefore, notAfter } = cert;
	// Unmeasured is its own answer, never folded into a passing band.
	if (notBefore == null || notAfter == null) return { band: 'unknown', days: null };
	// Degenerate explicitly, rather than reporting a silent negative day count.
	if (notAfter <= notBefore) return { band: 'invalid', days: 0 };

	const days = Math.floor((notAfter - notBefore) / 86400);
	if (days <= 47) return { band: 'exemplary', days };
	if (days <= 100) return { band: 'automated', days };
	if (days <= SC081_MAX_LIFETIME_DAYS) return { band: 'compliant', days };
	// Over the maximum: only an anomaly if the maximum was in force at ISSUANCE.
	return { band: notBefore < effectiveSeconds ? 'legacy' : 'anomaly', days };
}
