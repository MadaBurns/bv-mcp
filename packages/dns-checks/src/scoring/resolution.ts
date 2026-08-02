// SPDX-License-Identifier: BUSL-1.1

/**
 * Domain-resolution accounting — is there a domain here to measure at all?
 *
 * The failure mode this module removes: the check matrix was run against domains that
 * DO NOT EXIST, and a non-existent domain manufactures clean passes. On a dead name
 * there is no bad DNSSEC to find, no dangling CNAME to take over, no lax DANE record —
 * so `dnssec`/`dane`/`subdomain_takeover`/`subdomailing` all score 100 for the absence
 * of a problem that only a real domain could have. Located 2026-08-02 behind a
 * fabricated 88 on a name that had been NXDOMAIN for 100 days.
 *
 * A working guard already existed and was correct, but it lived in ONE consumer's
 * orchestrator (bv-mcp's `scan-domain.ts` → `buildNonResolvingResult`, which returns
 * `overall: null` with the note that scoring it "would fabricate a posture for an
 * unregistered name"). It was never in this package, so every OTHER consumer — anyone
 * vendoring `@blackveil/dns-checks` and running their own orchestration — got no
 * short-circuit at all. This module moves the SEMANTICS into the shared core.
 *
 * ## Two sources, deliberately
 *
 * 1. **Explicit** — the orchestrator's apex probe, passed in. Best evidence: it can
 *    distinguish NXDOMAIN from a broken/lame delegation. Wins whenever present.
 * 2. **Derived** — inferred from the check roster this package was handed. This is the
 *    FLOOR, and it is the reason the design is not "accept a new input": a guard that
 *    fires only on an explicit signal is silently disabled by a producer that forgets
 *    to pass it, which re-creates the exact failure being fixed one layer down.
 *
 * ## What is NOT a trigger
 *
 * Absence of mail. A domain that RESOLVES, publishes a null MX (RFC 7505) and
 * `v=spf1 -all` has deliberately and correctly opted out of mail; that is good posture
 * and must still score well. Non-resolution is the trigger, never non-use.
 *
 * Runtime-agnostic, Workers-safe: no Node APIs, no I/O.
 */

import type { CheckResult } from '../types';
import { isCheckMeasured } from './evidence';

/** Whether a domain could be measured at all. */
export type DomainResolutionState = 'resolves' | 'nxdomain' | 'unresolvable';

/**
 * Accepted spellings for the explicit resolution signal.
 *
 * The `boolean | 'broken'` arm is the tri-state bv-mcp's orchestrator already carries on
 * `ScanDomainResult.resolves`, accepted VERBATIM so the reference consumer needs no
 * mapping layer (a mapping layer is one more place to forget). The string arm is the
 * package-native spelling for new callers, which reads better than a bare boolean.
 */
export type DomainResolutionSignal = boolean | 'broken' | DomainResolutionState;

/**
 * Metadata key a check sets when it has DETERMINED that the domain does not resolve.
 *
 * Structured, not prose. Matching on a finding title would re-introduce the brittleness
 * this codebase has already been bitten by ("the old DKIM prose check counted revoked
 * keys as present"), and a title is a customer-facing string that will be reworded.
 */
export const DOMAIN_RESOLVES_METADATA_KEY = 'domainResolves';

/** Normalize any accepted spelling to the canonical state. `undefined` stays unknown. */
export function normalizeResolutionSignal(signal: DomainResolutionSignal | undefined): DomainResolutionState | undefined {
	if (signal === undefined) return undefined;
	if (signal === true || signal === 'resolves') return 'resolves';
	if (signal === false || signal === 'nxdomain') return 'nxdomain';
	if (signal === 'broken' || signal === 'unresolvable') return 'unresolvable';
	// An out-of-union value (a version-skewed producer, an unvalidated cache re-read) is
	// treated as NO signal rather than as a resolution claim — it then falls through to
	// the derived floor instead of silently asserting the domain is fine.
	return undefined;
}

/**
 * Infer non-resolution from the check roster alone.
 *
 * Keys on the `ns` check, which already makes exactly this determination and is the only
 * honest place to make it: a registered, delegated domain HAS nameservers. `check-ns`
 * queries NS, and when it finds none it falls back to an A-record probe before concluding
 * — so its `domainResolves: false` means "no NS records AND no A records", which is a
 * DNS-level fact, not a heuristic. A parked-but-live domain has nameservers and can never
 * reach that branch.
 *
 * Deliberately conservative in three ways:
 *
 * - Returns `'unresolvable'`, never `'nxdomain'`. This evidence proves the name did not
 *   answer; it cannot distinguish "never existed" from "delegated but broken". Only the
 *   explicit apex probe can, and it says so itself.
 * - Requires the `ns` check to have been MEASURED. An `ns` check that errored is
 *   inconclusive, and inconclusive is not proof of absence — that conflation is the
 *   "failure earns the exemption" bug this package has already been bitten by three
 *   times in profile detection.
 * - Does NOT consider positive evidence from other checks as a veto. On the located
 *   incident the dead domain's `ssl` check carried `controlPresent: true` (a parking
 *   origin answered on the HTTPS path) while the name itself was NXDOMAIN. A DNS-level
 *   determination outranks an HTTP-level observation.
 *
 * Returns `undefined` when nothing can be concluded — including when the roster contains
 * no `ns` check at all, which is a coverage gap, not evidence of health.
 */
export function deriveResolutionState(results: CheckResult[]): DomainResolutionState | undefined {
	for (const result of results) {
		if (result.category !== 'ns') continue;
		if (!isCheckMeasured(result.checkStatus)) continue;
		for (const finding of result.findings) {
			if (finding.metadata?.[DOMAIN_RESOLVES_METADATA_KEY] === false) return 'unresolvable';
		}
	}
	return undefined;
}

/**
 * The resolution state a scan should be judged against: explicit signal if the caller
 * supplied one, otherwise the derived floor.
 */
export function resolveScanResolutionState(
	results: CheckResult[],
	signal: DomainResolutionSignal | undefined,
): DomainResolutionState | undefined {
	return normalizeResolutionSignal(signal) ?? deriveResolutionState(results);
}

/** Whether a scan in this state can carry an honest grade. Unknown counts as measurable. */
export function isMeasurableDomain(state: DomainResolutionState | undefined): boolean {
	return state === undefined || state === 'resolves';
}

/**
 * Human-readable explanation for a scan ungraded because the domain could not be
 * resolved. Safe to render verbatim in a customer report.
 *
 * Says "measurement gap, not a security verdict" in the same words as the other ungraded
 * notes: a domain that does not resolve is not a domain with bad security, and a report
 * that implies otherwise is wrong about a third party.
 */
export function buildUnresolvableNote(state: 'nxdomain' | 'unresolvable'): string {
	const cause =
		state === 'nxdomain'
			? 'The domain does not exist in DNS (NXDOMAIN)'
			: 'The domain does not resolve — its nameservers returned no usable answer';
	return (
		`${cause}, so there is no security posture to assess and no grade is reported. ` +
		`This is a measurement gap, not a security verdict: an unresolvable name cannot be scored, ` +
		`and scoring it anyway would fabricate a posture for a domain that is not there.`
	);
}
