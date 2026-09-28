// SPDX-License-Identifier: BUSL-1.1

/**
 * `format: "compact"` for `check_lookalikes` (#1130).
 *
 * A large brand yields one or two findings PER REGISTERED CANDIDATE (an
 * attribution finding, plus a threat observation for every active non-owned
 * one). Measured on google.com: 76 findings, a 69,120-byte body in "compact"
 * mode, rejected by the MCP client as over its tool-result cap — so an agent
 * caller never saw the result at all. Same defect class as #687 (`batch_scan`).
 *
 * Compaction is a PRESENTATION transform applied at the dispatch boundary to
 * the cached, complete `CheckResult`. It never touches `score`, `passed`,
 * `checkStatus`, `partial` or the cache entry, and `format: "full"` never
 * reaches this module.
 *
 * What compact keeps:
 *  - every RUN-LEVEL finding (no `lookalikeDomain`): the threat rollup(s) and
 *    the `scan_status` notices (incomplete enumeration, ownership unmeasured,
 *    timeout …). They are few and bounded, and dropping an incompleteness
 *    notice would turn a sample into an apparent census;
 *  - the top {@link LOOKALIKE_COMPACT_TOP_N} PER-CANDIDATE findings by severity
 *    (stable: ties keep the check's emission order);
 *  - counts derived from what the check already emitted — no new predicate is
 *    introduced here (see {@link summarizeLookalikeFindings});
 *  - `truncated` + totals, so a capped list can never read as the whole set.
 */

import type { CheckResult, Finding } from '../lib/scoring';
import type { OwnershipVerdict } from '../lib/ownership-attribution';

/**
 * Per-candidate findings shown in compact mode. 10 matches `batch_scan`'s
 * 10-item ceiling — the bound #687 sized its compact payload against — and
 * keeps a google.com-sized result (76 findings) comfortably under the MCP
 * tool-result cap on both the text and the structured channel.
 */
export const LOOKALIKE_COMPACT_TOP_N = 10;

const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** Counts and truncation state carried on `structuredContent.compact`. */
export interface LookalikeCompactSummary {
	/** Distinct registered candidates reported (one attribution-axis finding each). */
	registered: number;
	/**
	 * Distinct non-owned, measured candidates with a working mail host — the
	 * threat-rollup member predicate (`members.filter(m => m.hasMX)`, #779),
	 * read from the per-candidate threat observations the rollup is built from.
	 */
	mailCapable: number;
	/** Distinct candidates `isBrandHeldRegistration` corroborated (`brandHeldRegistration: true`). */
	brandHeld: number;
	/**
	 * Distinct candidates whose ownership verdict is `third_party`. A raw
	 * verdict count: a brand-held candidate whose structural verdict was
	 * `third_party` is counted in BOTH, exactly as its finding reports it.
	 */
	thirdParty: number;
	/** Distinct registered candidates per ownership verdict (#832 vocabulary). */
	byOwnershipVerdict: Record<OwnershipVerdict, number>;
	/** Every finding in the full result. */
	totalFindings: number;
	/** Per-candidate findings in the full result. */
	candidateFindingsTotal: number;
	/** Per-candidate findings included in this compact result. */
	candidateFindingsShown: number;
	/** True when per-candidate findings were omitted. Request `format: "full"` for all of them. */
	truncated: boolean;
}

export interface CompactLookalikesResult {
	/** The findings to render/emit: run-level first, then the severity-ordered top-N. */
	findings: Finding[];
	summary: LookalikeCompactSummary;
	/** `structuredContent` payload: the full result's scalars, the compact findings, and `compact`. */
	structured: CheckResult & { compact: LookalikeCompactSummary };
}

function candidateOf(f: Finding): string | undefined {
	const d = f.metadata?.lookalikeDomain;
	return typeof d === 'string' ? d : undefined;
}

/** Derive the compact counts from the emitted findings (see field docs for each predicate's source). */
export function summarizeLookalikeFindings(findings: Finding[]): Omit<LookalikeCompactSummary, 'candidateFindingsShown' | 'truncated'> {
	const registered = new Set<string>();
	const mailCapable = new Set<string>();
	const brandHeld = new Set<string>();
	const verdictOf = new Map<string, OwnershipVerdict>();
	let candidateFindingsTotal = 0;

	for (const f of findings) {
		const domain = candidateOf(f);
		if (domain === undefined) continue;
		candidateFindingsTotal++;
		const axis = f.metadata?.findingAxis;
		if (axis === 'attribution') {
			registered.add(domain);
			const verdict = f.metadata?.ownershipVerdict;
			if (typeof verdict === 'string') verdictOf.set(domain, verdict as OwnershipVerdict);
		}
		if (axis === 'threat_observation' && f.metadata?.hasMX === true) mailCapable.add(domain);
		if (f.metadata?.brandHeldRegistration === true) brandHeld.add(domain);
	}

	const byOwnershipVerdict: Record<OwnershipVerdict, number> = { owned_by_seed: 0, third_party: 0, unattributed: 0, unmeasured: 0 };
	for (const verdict of verdictOf.values()) {
		if (verdict in byOwnershipVerdict) byOwnershipVerdict[verdict]++;
	}

	return {
		registered: registered.size,
		mailCapable: mailCapable.size,
		brandHeld: brandHeld.size,
		thirdParty: byOwnershipVerdict.third_party,
		byOwnershipVerdict,
		totalFindings: findings.length,
		candidateFindingsTotal,
	};
}

/** Build the compact view of a complete `check_lookalikes` result. */
export function compactLookalikesResult(result: CheckResult, topN: number = LOOKALIKE_COMPACT_TOP_N): CompactLookalikesResult {
	const runLevel: Finding[] = [];
	const perCandidate: Array<{ f: Finding; i: number }> = [];
	result.findings.forEach((f, i) => {
		if (candidateOf(f) === undefined) runLevel.push(f);
		else perCandidate.push({ f, i });
	});
	const top = perCandidate
		.sort((a, b) => (SEVERITY_RANK[b.f.severity] ?? 0) - (SEVERITY_RANK[a.f.severity] ?? 0) || a.i - b.i)
		.slice(0, Math.max(0, topN))
		.map(({ f }) => f);

	const summary: LookalikeCompactSummary = {
		...summarizeLookalikeFindings(result.findings),
		candidateFindingsShown: top.length,
		truncated: top.length < perCandidate.length,
	};
	const findings = [...runLevel, ...top];
	return { findings, summary, structured: { ...result, findings, compact: summary } };
}

/** Text lines appended to the compact rendering: the counts, and the truncation notice when capped. */
export function formatLookalikeCompactSummary(summary: LookalikeCompactSummary): string[] {
	const lines = [
		'',
		'### Summary',
		`- Candidates: ${summary.registered} registered, ${summary.mailCapable} mail-capable (not owned by the scanned domain), ${summary.brandHeld} brand-held, ${summary.thirdParty} third-party`,
	];
	if (summary.truncated) {
		lines.push(
			`- Truncated: showing the ${summary.candidateFindingsShown} highest-severity of ${summary.candidateFindingsTotal} per-candidate findings (${summary.totalFindings} findings in total). Request format "full" for the complete list.`,
		);
	}
	return lines;
}
