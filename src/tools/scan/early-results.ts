// SPDX-License-Identifier: BUSL-1.1

/**
 * Early (non-scored) scan_domain results: the degraded result when scoring
 * fails, the NXDOMAIN result and the SERVFAIL (broken DNS) result. Split out of
 * scan-domain.ts (SQ-537) with no behaviour change.
 */

import { type CheckCategory, type CheckResult, type DomainContext, type Finding, computeScanEvidence } from '../../lib/scoring';
import { describeNonResolvingDomain } from '../../lib/apex-resolution';
import type { ScanDomainResult } from './scan-types';

/**
 * Build a degraded scan result when the scoring path itself fails — e.g. a
 * runtime/bundle error such as the production "m5 is not defined" ReferenceError
 * thrown from a stale bundle.
 *
 * The checks already ran successfully, so we preserve their findings and
 * per-category scores and surface them to the operator; only the weighted
 * overall score and grade are marked unavailable (`null`). This converts a total scan
 * failure (a generic "unexpected error" for every domain) into a graceful
 * degradation. Deliberately calls NO scoring-package function, since the
 * scoring package is exactly what failed.
 */
export function buildUnscoredResult(domain: string, checkResults: CheckResult[], reason: string): ScanDomainResult {
	const categoryScores = {} as Record<CheckCategory, number>;
	const findings: Finding[] = [];
	for (const check of checkResults) {
		categoryScores[check.category] = check.score;
		findings.push(...check.findings);
	}
	return {
		domain,
		score: {
			overall: null,
			grade: null,
			categoryScores,
			findings,
			summary: reason,
			evidence: computeScanEvidence(checkResults),
		},
		checks: checkResults,
		maturity: {
			stage: 0,
			label: 'Unscored',
			description: reason,
			nextStep: 'Re-run the scan. If the score stays unavailable, the scoring service is degraded — check the deployment.',
		},
		context: {
			profile: 'mail_enabled',
			signals: ['scoring unavailable — degraded result'],
			weights: {} as DomainContext['weights'],
			detectedProvider: null,
		},
		cached: false,
		timestamp: new Date().toISOString(),
		scoringNote: reason,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
	};
}

/**
 * Build a result for a domain that does not exist in DNS (apex NXDOMAIN).
 *
 * Unlike {@link buildUnscoredResult} (checks ran, scoring failed), here the
 * checks never run: a non-existent domain has no security posture to assess, and
 * running the matrix would only fabricate "absence = missing control" findings —
 * producing a misleading D+/F for a domain that simply isn't registered. We emit
 * NO findings and NO per-category scores; the score and grade are `null` and `resolves` is false
 * so aggregators exclude it rather than averaging it in.
 */
export function buildNonResolvingResult(domain: string): ScanDomainResult {
	const reason = describeNonResolvingDomain(domain);
	return {
		domain,
		score: {
			overall: null,
			grade: null,
			categoryScores: {} as Record<CheckCategory, number>,
			findings: [],
			summary: reason,
			evidence: { attempted: 0, completed: 0, ratio: 0 },
		},
		checks: [],
		maturity: {
			stage: 0,
			label: 'Does not resolve',
			description: reason,
			nextStep:
				'Confirm the domain is registered and has authoritative nameservers. If it was recently registered, DNS may not have propagated yet.',
		},
		context: {
			profile: 'mail_enabled',
			signals: ['domain does not resolve (NXDOMAIN)'],
			weights: {} as DomainContext['weights'],
			detectedProvider: null,
		},
		cached: false,
		timestamp: new Date().toISOString(),
		scoringNote: reason,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		resolves: false,
	};
}

/** Kinds of broken DNS resolution distinguished by the SERVFAIL apex probe. */
export type DnsBrokenKind = 'dnssec_bogus' | 'unresolvable';

/**
 * Build a result for a domain whose apex SERVFAILs — the zone is delegated but
 * cannot be resolved. Distinct from {@link buildNonResolvingResult} (NXDOMAIN,
 * the name does not exist) and from a normal scored result.
 *
 * Two sub-states, both confirmed (never inferred from a single transient query):
 * - `dnssec_bogus`: the validating apex query SERVFAILs but a checking-disabled
 *   (`cd=1`) retry succeeds — the zone resolves only with DNSSEC validation off,
 *   so its signatures are bogus/expired.
 * - `unresolvable`: BOTH the validating query and the `cd=1` retry SERVFAIL — a
 *   persistent broken/lame delegation, not a DNSSEC issue.
 *
 * Like the non-resolving case, we emit NO findings and NO per-category scores:
 * a zone we cannot resolve has no measurable posture, and running the matrix
 * would only fabricate "absence = missing control" findings. The score and
 * grade are `null` and `resolves` is `'broken'` so aggregators exclude it.
 */
export function buildDnsBrokenResult(domain: string, kind: DnsBrokenKind): ScanDomainResult {
	const reason =
		kind === 'dnssec_bogus'
			? `${domain} DNS resolution is broken: the zone fails DNSSEC validation (resolves only with validation disabled). Until the DNSSEC chain is fixed, validating resolvers return SERVFAIL and the domain is effectively unreachable — so there is no measurable security posture to assess.`
			: `${domain} DNS resolution is broken: the apex returns SERVFAIL and the zone is unresolvable (broken or lame delegation). With no resolvable records there is no security posture to assess.`;
	const nextStep =
		kind === 'dnssec_bogus'
			? 'Fix the DNSSEC chain (re-sign the zone / update DS at the parent) or, if DNSSEC is not intended, remove the DS records so the zone resolves cleanly. Then re-run the scan.'
			: 'Confirm the delegation is healthy: the parent NS records point at authoritative nameservers that answer for the zone. Once the zone resolves, re-run the scan.';
	const signal =
		kind === 'dnssec_bogus' ? 'DNS resolution broken (DNSSEC validation failure)' : 'DNS resolution broken (unresolvable delegation)';
	return {
		domain,
		score: {
			overall: null,
			grade: null,
			categoryScores: {} as Record<CheckCategory, number>,
			findings: [],
			summary: reason,
			evidence: { attempted: 0, completed: 0, ratio: 0 },
		},
		checks: [],
		maturity: {
			stage: 0,
			label: 'DNS resolution broken',
			description: reason,
			nextStep,
		},
		context: {
			profile: 'mail_enabled',
			signals: [signal],
			weights: {} as DomainContext['weights'],
			detectedProvider: null,
		},
		cached: false,
		timestamp: new Date().toISOString(),
		scoringNote: reason,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
		resolves: 'broken',
	};
}
