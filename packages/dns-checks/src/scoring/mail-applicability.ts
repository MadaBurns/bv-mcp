// SPDX-License-Identifier: BUSL-1.1

/**
 * Mail applicability: rules that restate a mail-auth finding when the control
 * cannot apply to the domain it was measured on.
 *
 * These are pure functions over completed check results. They perform no DNS
 * lookup and no I/O, so every consumer of the package applies the same rule and
 * reports the same severity. A consumer that scores the raw check results and
 * skips this step reports a silent domain's revoked DKIM keys as a high-severity
 * gap, which is the correct posture for that domain and not a gap at all.
 */

import { buildCheckResult } from './model';
import type { CheckResult, Finding } from './model';
import { isCheckMeasured } from './evidence';

/**
 * LEGACY-ONLY fallback: MX finding titles that mean "this domain does not accept
 * inbound email", consulted only when `controlPresent` is absent from the result.
 *
 * The first four are the titles `check-mx` emits on its non-mail terminal paths,
 * but every one of those paths also sets `controlPresent: false`, so against a
 * current result this set is never reached. `'No MX records found'` is emitted by
 * nothing; it is kept so synthetic and older-vintage results are still recognised.
 *
 * Do NOT add new titles here. Finding identity by string literal has no
 * compile-time or test-time link to its producer and fails silently. Key on
 * structure (`controlPresent`).
 */
const NO_INBOUND_MAIL_MX_TITLES: ReadonlySet<string> = new Set([
	'Null MX record (RFC 7505)',
	'Correctly-configured non-mail domain',
	'Non-mail domain SPF not hard-fail',
	'No MX and no SPF — domain spoofable',
	'No MX records found',
]);

/**
 * The single answer to "did the `mx` check DEFINITIVELY establish that this domain
 * accepts no inbound email": either no MX records at all, or an RFC 7505 null MX.
 *
 * Absence is asserted only from a completed measurement. Two independent guards,
 * because "no mail" is a claim made about the domain and not merely a missing signal:
 *
 *  1. `checkStatus` must be measured. A transient resolver failure could not
 *     observe the mail posture, so it supports no claim about it.
 *  2. `controlPresent`, which `check-mx` sets on every terminal path: `true` only
 *     when real mail-routing MX records were observed, `false` for both the no-MX
 *     and the null-MX declarations, `undefined` when inconclusive.
 *
 * A mail-receiving domain and an inconclusive lookup both return `false`, so
 * neither is ever treated as non-mail.
 */
export function mxDeclaresNoInboundMail(mxResult: CheckResult | undefined): boolean {
	if (!mxResult) return false;
	if (!isCheckMeasured(mxResult.checkStatus)) return false;
	if (mxResult.controlPresent === false) return true;
	if (mxResult.controlPresent === true) return false;
	return mxResult.findings.some((finding: Finding) => NO_INBOUND_MAIL_MX_TITLES.has(finding.title));
}

/**
 * Retract a DECLARED `metadata.missingControl: true` when a finding is downgraded to
 * "not applicable". Spread the result into the downgraded finding.
 *
 * `findingsIndicateMissingControl` honours a declared `true` with no severity gate, so
 * a finding rewritten to `info` but still carrying the declaration would keep zeroing
 * its category: the prose would say "expected" while the score said "absent".
 * `missingControl: false` is the scoring layer's own "measured, not a missing control"
 * declaration. Undeclared findings get no patch.
 */
export function notApplicableMetadata(finding: Finding): { metadata?: Finding['metadata'] } {
	return finding.metadata?.missingControl === true ? { metadata: { ...finding.metadata, missingControl: false } } : {};
}

/**
 * Titles `check-dkim` gives a selector whose key cannot verify a signature, meaning
 * an empty `p=` (revoked) or no `p=` at all, plus their aggregate.
 */
const UNVERIFIABLE_DKIM_KEY_TITLE_PREFIXES = ['DKIM keys revoked', 'Revoked DKIM key:', 'DKIM key record has no public key:'];

const SILENT_DOMAIN_DKIM_REASON =
	'expected — null MX and an SPF policy that authorizes no sender mean this domain neither sends nor receives mail, so revoked DKIM keys are the correct posture';

/**
 * A domain with no inbound mail (no MX or a null MX) and an SPF policy that
 * authorizes no sender neither receives nor sends mail. Revoking every DKIM key is
 * the correct posture for it, so a "keys revoked" finding is not a risk: it is
 * restated as `info`, with the reason appended and any declared missing control
 * retracted. A usable key, even a weak one, keeps its rating, because a factorable
 * key can still be used to forge mail.
 *
 * Call this on a scan's check results BEFORE computing the scan score. The DKIM
 * result is rebuilt from its adjusted findings, so its category score and `passed`
 * move with the severities; under a profile that gives DKIM a nonzero weight the
 * overall score can rise. Both conditions are read from the results themselves
 * (the `mx` result and the `noSendPolicy` marker on the `spf` findings), and a
 * result set that does not establish both is returned unchanged.
 *
 * A DKIM result that did not complete is returned as the same object: an
 * abstention has no real finding to restate, and rebuilding it from its findings
 * would turn it into a confident pass.
 */
export function applySilentDomainDkimApplicability(results: CheckResult[]): CheckResult[] {
	const mxResult = results.find((result) => result.category === 'mx');
	if (!mxDeclaresNoInboundMail(mxResult)) return results;

	const spfResult = results.find((result) => result.category === 'spf');
	const hasNoSendPolicy = spfResult?.findings.some((finding: Finding) => finding.metadata?.noSendPolicy === true) ?? false;
	if (!hasNoSendPolicy) return results;

	return results.map((result) => {
		if (result.category !== 'dkim') return result;
		if (!isCheckMeasured(result.checkStatus)) return result;
		const adjusted = result.findings.map((finding: Finding) => {
			const unverifiable = UNVERIFIABLE_DKIM_KEY_TITLE_PREFIXES.some((prefix) => finding.title.startsWith(prefix));
			if (!unverifiable || (finding.severity !== 'critical' && finding.severity !== 'high')) return finding;
			return {
				...finding,
				severity: 'info' as const,
				detail: `${finding.detail} (${SILENT_DOMAIN_DKIM_REASON})`,
				...notApplicableMetadata(finding),
			};
		});
		return buildCheckResult(result.category, adjusted, result.controlPresent, result.recordPresent, result.metadata);
	});
}
