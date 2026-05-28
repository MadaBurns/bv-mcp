// SPDX-License-Identifier: BUSL-1.1

/**
 * Lookalike severity calibration — issue #264.
 *
 * Pure function: classifies a registered lookalike domain into a severity
 * tier based on its detection signals. Designed so the matrix can be
 * unit-tested without DNS/HTTP plumbing.
 *
 * Matrix (issue #264):
 *   - mail-infra alone                       → MEDIUM
 *   - mail-infra + recent registration (<90d) → HIGH
 *   - mail-infra + disposable MX provider     → HIGH
 *   - mail-infra + no web content             → HIGH
 *   - web only                                → LOW
 *   - web only + recent registration (<90d)   → MEDIUM
 *
 * `registrationDays === null` means "unknown" (RDAP failed or returned no
 * event); treated as not-recent so the fallback never elevates severity
 * on a single absent signal.
 */

import type { Severity } from '../lib/scoring';

/** Severity assigned to lookalikes that should not surface as a finding at all. */
export type LookalikeSeverity = Extract<Severity, 'low' | 'medium' | 'high'>;

/** Threshold (days) below which a registration is considered "recent" per #264. */
export const RECENT_REGISTRATION_DAYS = 90;

/**
 * Finite list of disposable / throwaway MX provider hostnames. MX exchanges
 * suffixed with any of these are treated as a HIGH corroborator under the
 * #264 matrix. Easy to extend later as new providers surface in the wild.
 *
 * Match is performed as an exact-equality OR endsWith('.' + suffix) check, so
 * `smtp.mailgun.org` matches `mailgun.org` but `legit-mailgun.com` does not.
 */
export const DISPOSABLE_MX_PROVIDERS: readonly string[] = [
	'mailgun.org',
	'mailtrap.io',
	'inbox.eu',
	'temp-mail.org',
	'guerrillamail.com',
	'mailinator.com',
	'10minutemail.com',
];

/** Signals harvested per lookalike candidate; fed verbatim into the calibrator. */
export interface LookalikeSignals {
	/** A record present (web infrastructure registered). */
	hasA: boolean;
	/** Real (non-null) MX record present (mail infrastructure registered). */
	hasMX: boolean;
	/**
	 * Domain age in days since RDAP `registration` event. `null` when RDAP
	 * lookup failed, returned no event, or the TLD has no RDAP server in our
	 * fallback map. Per design: null is "unknown" and never elevates severity.
	 */
	registrationDays: number | null;
	/** MX exchange host suffix matches one of {@link DISPOSABLE_MX_PROVIDERS}. */
	mxOnDisposable: boolean;
	/**
	 * HEAD probe of the candidate domain returned a 2xx/3xx response. Fail-soft:
	 * any probe failure (connect refused, timeout, DNS lookup miss) MUST be
	 * recorded as `true` here so a flaky probe doesn't synthesise a HIGH
	 * "no-content corroborator" out of nothing.
	 */
	hasWebContent: boolean;
}

/**
 * Check whether an MX exchange host belongs to a disposable / throwaway
 * mail provider in {@link DISPOSABLE_MX_PROVIDERS}.
 */
export function isDisposableMxHost(exchange: string): boolean {
	const host = exchange.trim().toLowerCase().replace(/\.$/, '');
	if (host.length === 0) return false;
	for (const suffix of DISPOSABLE_MX_PROVIDERS) {
		if (host === suffix || host.endsWith('.' + suffix)) return true;
	}
	return false;
}

/** True when the supplied registration age signals a "recent" (<90d) registration. */
export function isRecentRegistration(registrationDays: number | null): boolean {
	return registrationDays !== null && registrationDays < RECENT_REGISTRATION_DAYS;
}

/**
 * Pure calibrator: map detection signals onto the issue #264 severity matrix.
 *
 * Implementation notes:
 *   - Mail-infra is the primary axis; web-only is the fallback axis.
 *   - HIGH requires mail-infra AND at least one corroborator
 *     (recent registration, disposable MX, or no web content).
 *   - MEDIUM is the mail-infra default (no corroborator), OR web-only +
 *     recent registration.
 *   - LOW is web-only with no corroborator.
 */
export function calibrateLookalikeSeverity(signals: LookalikeSignals): LookalikeSeverity {
	const recent = isRecentRegistration(signals.registrationDays);

	if (signals.hasMX) {
		// Mail-infra present — look for corroborators that elevate to HIGH.
		if (recent || signals.mxOnDisposable || !signals.hasWebContent) {
			return 'high';
		}
		return 'medium';
	}

	// Web-only path: A record but no MX.
	if (recent) return 'medium';
	return 'low';
}
