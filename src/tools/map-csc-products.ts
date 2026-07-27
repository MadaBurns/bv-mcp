// SPDX-License-Identifier: BUSL-1.1

/**
 * CSC product mapping tool (sales-upsell layer).
 * Maps a domain's observed security gaps to the four CSC commercial products.
 * Reads existing CheckResults (dmarc/ssl/dnssec) plus Spec A's RDAP lock posture.
 * Emits NO new security finding/severity — `priority` here is a SALES priority,
 * deliberately distinct from a security severity. Modeled on map-compliance.ts.
 */

import type { CheckResult } from '../lib/scoring';
import type { LockPosture } from './check-rdap-lookup';
import { checkRdapLookup, RDAP_LOOKUP_SYNC_BUDGET_MS } from './check-rdap-lookup';
import { scanDomain } from './scan-domain';
import type { ScanRuntimeOptions } from './scan/post-processing';
import type { OutputFormat } from '../handlers/tool-args';
import { sanitizeOutputText } from '../lib/output-sanitize';
import { formatScoreGrade, hasCompletedEvidence, isCompletedCheck } from '../lib/ungraded-display';
import { isDnsErrorFinding } from '../lib/dns-error-result';

export type CscProductKey = 'csc_multilock' | 'managed_dmarc' | 'digital_certificates' | 'dnssec_management';

/**
 * The STRUCTURAL twin of `caveat`. `caveat` is prose meant to be read; `caveatKind`
 * is the machine-readable reason a classifier should branch on. Before this existed,
 * `unassessedScanProduct` (here) and `isNeverRanCaveat` (`prioritize_csc_leads`)
 * classified state by comparing the `caveat` STRING against `UNASSESSED_CSC_NOTE`
 * identity, with "anything else" silently defaulting to the transient branch — a
 * renamed constant, an edited wording, or a third failure mode introduced later
 * would misclassify with no compiler or test signal. `caveatKind` cannot drift from
 * its own meaning the way a string comparison can.
 */
export type CaveatKind = 'never_ran' | 'all_transient';

/** Sales-upsell priority — NOT a security severity. */
export type CscPriority = 'high' | 'medium' | 'low' | 'none';

export interface CscProductRecommendation {
	product: CscProductKey;
	productName: string;
	recommended: boolean;
	priority: CscPriority;
	justifyingGap: string;
	relatedFindings: string[];
	/**
	 * `false` exactly for a product built by {@link unassessedScanProduct} — the
	 * category (or the whole scan) was never actually observed. Every OTHER
	 * construction site (`evalMultiLock`, `evalScanProduct`'s pass/fail/absent
	 * branches) sets this `true`. This is the render-time discriminant
	 * `formatCscProducts` MUST use to keep an unassessed product visually
	 * distinct from a genuine clean pass — before this field existed, both
	 * states shared `recommended: false` and rendered byte-identical
	 * (`✓ Managed DMARC` / `➖ Managed DMARC — OK`) in both format modes, so a
	 * transient DMARC failure was indistinguishable from a passing DMARC check
	 * on the surface most interactive clients see (compact is auto-selected
	 * for them).
	 */
	assessed: boolean;
}

export interface CscProductReport {
	domain: string;
	/** `null` when the scan produced no gradeable measurement. Never a coerced 0. */
	score: number | null;
	/** `null` when the scan produced no gradeable measurement. Never a fabricated letter. */
	grade: string | null;
	/**
	 * Is there any COMPLETED check evidence? (`hasCompletedEvidence` over the
	 * input results — NOT `isMeasured`: a total-outage scan has `checks.length >
	 * 0` too, with every check's `checkStatus` `'timeout' | 'error'`, and
	 * `isMeasured` alone could not tell that apart from a genuinely measured
	 * scan.)
	 *
	 * Distinct from having a SCORE. `buildUnscoredResult` — the shipped
	 * scoring-bundle-failure path — produces real checks with real findings and a
	 * `null` score, so `assessed` is true while the score is absent. The three
	 * scan-driven recommendations are derived from the CHECKS, not from the score,
	 * so this is the flag that says whether they mean anything — and when it is
	 * `false` they are not emitted as recommendations at all (see
	 * `unassessedScanProduct`), so no consumer can read a product gap out of a
	 * domain nobody measured by ignoring this flag.
	 */
	assessed: boolean;
	/**
	 * REQUIRED — `null` when `assessed` is `true`, a non-null string otherwise.
	 * Distinguishes "no checks ran" ({@link UNASSESSED_CSC_NOTE}) from "checks
	 * were attempted but none of them completed"
	 * ({@link buildAllTransientCscNote}) — the two failure modes
	 * `hasCompletedEvidence` collapses into the same `assessed: false`, but which
	 * are NOT the same fact and get distinct wording. Required (not optional) so
	 * every construction site — the real producer AND every hand-built test
	 * fixture — must state explicitly which reason applies; an omitted field
	 * here is exactly how a transient-outage report silently rendered the
	 * "no checks ran" text before this was made required.
	 */
	caveat: string | null;
	/**
	 * REQUIRED — the STRUCTURAL discriminant paired with `caveat`: `null` exactly
	 * when `caveat` is `null` (`assessed: true`), `'never_ran'` or `'all_transient'`
	 * otherwise. Classifiers (`unassessedScanProduct` here,
	 * `prioritize_csc_leads`' render helpers) MUST branch on this field, never on
	 * `caveat`'s string content — see the type doc on {@link CaveatKind}.
	 */
	caveatKind: CaveatKind | null;
	lockPosture: LockPosture | null;
	/**
	 * Always the four products in fixed order. When `assessed` is `false` the three
	 * scan-driven entries are `recommended: false, priority: 'none'` — absence of
	 * evidence, never a priced gap. Only `csc_multilock` can still be recommended
	 * there, and only on independent RDAP evidence.
	 */
	recommendations: CscProductRecommendation[];
	/** Count of `recommended` entries — 0 for an unassessed domain with no RDAP lock gap. */
	recommendedCount: number;
}

/**
 * The SINGLE sentence for "no check ran, so no product gap could be assessed".
 *
 * Owned here because this is where `assessed` is computed; `prioritize_csc_leads`
 * composes its per-lead note from it (leads imports from this module, never the
 * reverse). One sentence, so the two tools cannot describe the same state in two
 * vocabularies — which is exactly how they came to give opposite answers about the
 * same producer output.
 */
export const UNASSESSED_CSC_NOTE = 'No checks ran for this domain, so no product gap could be assessed.';

/**
 * A SEPARATE wording from {@link UNASSESSED_CSC_NOTE} for a different failure
 * mode. `UNASSESSED_CSC_NOTE` describes "no checks ran" (NXDOMAIN, broken
 * zone — `checkResults: []`). This describes "checks ran, none of them
 * finished" — a total DoH/network outage where every attempted check carries
 * a transient `checkStatus: 'timeout'`/`'error'`
 * (`buildDnsErrorResult`/`safeCheck`). Saying "no checks ran" there would be
 * false — N checks DID run — and would misprice the domain's condition to a
 * sales team reading this note as "nothing observed" rather than "transient,
 * retry". Mirrors `map_compliance`'s `buildAllTransientCaveat`.
 */
export function buildAllTransientCscNote(attempted: number): string {
	return (
		`${attempted} check${attempted === 1 ? '' : 's'} ${attempted === 1 ? 'was' : 'were'} attempted for this domain, ` +
		`but none of them completed (transient DNS/network failure) — no product gap could be assessed from this scan. ` +
		`This is different from no checks running at all: retry once the transient condition clears.`
	);
}

const CSC_PRODUCT_NAMES: Record<CscProductKey, string> = {
	csc_multilock: 'CSC MultiLock',
	managed_dmarc: 'Managed DMARC',
	digital_certificates: 'Digital Certificates',
	dnssec_management: 'DNSSEC management',
};

/**
 * Non-info finding titles from a failing CheckResult (mirrors map-compliance).
 * Also excludes the synthetic "check error" finding a transient DNS/network
 * failure produces (`isDnsErrorFinding`) — that finding is the ABSENCE of a
 * measurement, not a sellable gap, and must never surface as a
 * `relatedFinding` justifying an upsell.
 */
function nonInfoTitles(result: CheckResult | undefined): string[] {
	if (!result) return [];
	return result.findings.filter((f) => f.severity !== 'info' && !isDnsErrorFinding(f)).map((f) => f.title);
}

/**
 * MultiLock recommendation — reads the booleans, not `level` alone (Spec A handoff).
 * Always `assessed: true`: MultiLock reads RDAP independently of the scan (see
 * `evaluateCscProducts`'s doc on why it is never gated on `assessed`), including
 * the "unobservable" branch — RDAP genuinely returning nothing is itself a
 * definitive lookup outcome, not a transient scan failure. Out of scope for this
 * fix round.
 */
function evalMultiLock(lockPosture: LockPosture | null): CscProductRecommendation {
	const base = {
		product: 'csc_multilock' as const,
		productName: CSC_PRODUCT_NAMES.csc_multilock,
		relatedFindings: [] as string[],
		assessed: true as const,
	};
	if (lockPosture == null || lockPosture.level === 'unknown') {
		return { ...base, recommended: false, priority: 'none', justifyingGap: 'Lock posture unobservable (RDAP unavailable/redacted)' };
	}
	if (lockPosture.registryLevel === true) {
		return { ...base, recommended: false, priority: 'none', justifyingGap: 'Registry lock already in effect' };
	}
	if (lockPosture.transferLocked === false) {
		return { ...base, recommended: true, priority: 'high', justifyingGap: 'Domain transfer not locked — no registry or registrar lock' };
	}
	// registrarLevel true (or defensive fallback): registrar lock only, no server lock.
	return { ...base, recommended: true, priority: 'medium', justifyingGap: 'Registrar lock only — no registry-level (server) lock' };
}

/**
 * Scan-driven product (dmarc/ssl/dnssec). Missing category → low-priority "not observed" lead.
 *
 * `concern` (e.g. 'DMARC') is only used on the transient branch, to build the same
 * "not assessed" wording {@link unassessedScanProduct} uses for a whole-report
 * outage — see its doc for why a category whose OWN check never completed must not
 * be priced as a gap even when `assessed` is `true` overall (other categories DID
 * complete). Checking `checkStatus` here (mirrors `map_compliance`'s `completed`
 * filter) is necessary in addition to the `isDnsErrorFinding` filter in
 * `nonInfoTitles`/below: after that filter a transient result's `findings` and
 * `titles` are both empty, but `result.passed` is still `false` (set explicitly by
 * `buildDnsErrorResult`), so without this branch the code below would still fall
 * through to `recommended: true, priority: 'medium'` — an upsell justified by
 * nothing, for a category nobody actually measured.
 */
function evalScanProduct(
	product: Exclude<CscProductKey, 'csc_multilock'>,
	result: CheckResult | undefined,
	gaps: { passing: string; failing: string; absent: string },
	concern: string,
): CscProductRecommendation {
	const base = { product, productName: CSC_PRODUCT_NAMES[product], assessed: true as const };
	if (result === undefined) {
		return { ...base, recommended: true, priority: 'low', justifyingGap: gaps.absent, relatedFindings: [] };
	}
	if (!isCompletedCheck(result)) {
		// This ONE category's own check failed transiently — other categories in
		// this scan (the ones NOT reaching this branch) may well have completed,
		// which is why `'category_transient'` gets its own wording distinct from
		// the whole-report `'all_transient'` case (see `unassessedScanProduct`'s
		// doc): "checks attempted, none completed" would be a false claim about
		// this scan when it is specifically this category, not every category,
		// that never completed.
		return unassessedScanProduct(product, concern, 'category_transient');
	}
	if (result.passed) {
		return { ...base, recommended: false, priority: 'none', justifyingGap: gaps.passing, relatedFindings: [] };
	}
	const titles = nonInfoTitles(result);
	const hasSevere = result.findings.some((f) => (f.severity === 'critical' || f.severity === 'high') && !isDnsErrorFinding(f));
	return { ...base, recommended: true, priority: hasSevere ? 'high' : 'medium', justifyingGap: gaps.failing, relatedFindings: titles };
}

/**
 * The three reasons a product can go unassessed. `never_ran`/`all_transient`
 * mirror {@link CaveatKind} exactly (the WHOLE-REPORT states — every category
 * failed, or nothing ran at all). `category_transient` is a THIRD, narrower
 * state introduced by `evalScanProduct`'s `checkStatus` branch: THIS category's
 * own check failed transiently while the rest of the scan may well have
 * completed normally — `CaveatKind` deliberately does NOT gain this value
 * (it is a per-report field consumed elsewhere, e.g. `prioritize_csc_leads`'
 * `isNeverRanKind`, which is not written to expect a third state), so this is
 * a local, wider type instead of a change to the exported `CaveatKind` union.
 */
type UnassessedReason = CaveatKind | 'category_transient';

/**
 * The scan-driven product line for a domain with no COMPLETED check evidence —
 * either the WHOLE report (`caveatKind`/`'never_ran'`/`'all_transient'`, via
 * `evaluateCscProducts`) or a SINGLE category within an otherwise-assessed scan
 * (`'category_transient'`, via `evalScanProduct`'s `checkStatus` branch).
 *
 * `evalScanProduct`'s `absent` branch ("DMARC not observed") means "we looked and
 * found nothing" — a real, sellable gap. With no completed evidence nobody
 * looked, so the same branch would recommend all three products at once on the
 * strength of non-observation. This states the absence of evidence instead of
 * pricing it.
 *
 * `reason` (the STRUCTURAL discriminant, {@link UnassessedReason}) picks the
 * wording: "no checks ran" is false — and this exact text, ending up on the
 * `recommendations[].justifyingGap` WIRE field even though `formatCscProducts`
 * never prints it to prose — for a total-outage scan where N checks WERE
 * attempted; "checks attempted, none completed" is equally false when it is
 * ONE category, not the whole scan, that never completed. Classifying on
 * `reason` rather than comparing the `caveat` STRING means a renamed/edited
 * caveat wording cannot silently flip which branch this takes. Exported for
 * direct unit testing of that decoupling — see the round-6c pin test in
 * `test/map-csc-products.spec.ts`.
 */
export function unassessedScanProduct(
	product: Exclude<CscProductKey, 'csc_multilock'>,
	concern: string,
	reason: UnassessedReason | null,
): CscProductRecommendation {
	const reasonText =
		reason === 'category_transient'
			? "this category's check failed transiently — other categories in this scan may have completed normally"
			: reason === 'all_transient'
				? 'checks attempted, none completed'
				: 'no checks ran';
	return {
		product,
		productName: CSC_PRODUCT_NAMES[product],
		recommended: false,
		priority: 'none',
		assessed: false,
		justifyingGap: `${concern} not assessed — ${reasonText}`,
		relatedFindings: [],
	};
}

/**
 * Evaluate CSC product recommendations from scan results + RDAP lock posture (PURE).
 * Exported for direct unit testing without mocking scanDomain/checkRdapLookup.
 */
export function evaluateCscProducts(
	checkResults: CheckResult[],
	lockPosture: LockPosture | null,
	domain: string,
	score: number | null,
	grade: string | null,
): CscProductReport {
	const byCategory = new Map<string, CheckResult>();
	for (const r of checkResults) byCategory.set(r.category, r);

	// `isMeasured` (`checks.length > 0`) cannot tell "19 healthy checks" apart
	// from "19 checks that all timed out" — both are truthy. A total DoH/network
	// outage where every attempted check carries a transient `checkStatus:
	// 'timeout' | 'error'` previously read as `assessed: true`, so
	// `evalScanProduct` priced an upsell off `passed: false` + a "check error"
	// finding manufactured by the transient failure, not off a real gap.
	const assessed = hasCompletedEvidence(checkResults);
	const caveatKind: CaveatKind | null = assessed ? null : checkResults.length === 0 ? 'never_ran' : 'all_transient';
	const caveat = assessed ? null : checkResults.length === 0 ? UNASSESSED_CSC_NOTE : buildAllTransientCscNote(checkResults.length);

	// MultiLock is deliberately NOT gated on `assessed`: it reads the RDAP lock
	// posture, which is fetched independently of the scan. A registered domain whose
	// zone is broken can still show a genuinely unlocked transfer status, and that is
	// a real measurement — suppressing it would be the mirror defect.
	const recommendations: CscProductRecommendation[] = [
		evalMultiLock(lockPosture),
		assessed
			? evalScanProduct(
					'managed_dmarc',
					byCategory.get('dmarc'),
					{
						passing: 'DMARC policy in effect',
						failing: 'DMARC present but not passing',
						absent: 'DMARC not observed',
					},
					'DMARC',
				)
			: unassessedScanProduct('managed_dmarc', 'DMARC', caveatKind),
		assessed
			? evalScanProduct(
					'digital_certificates',
					byCategory.get('ssl'),
					{
						passing: 'TLS/SSL configuration healthy',
						failing: 'TLS/SSL issues detected',
						absent: 'TLS/SSL not observed',
					},
					'TLS/SSL',
				)
			: unassessedScanProduct('digital_certificates', 'TLS/SSL', caveatKind),
		assessed
			? evalScanProduct(
					'dnssec_management',
					byCategory.get('dnssec'),
					{
						passing: 'DNSSEC enabled',
						failing: 'DNSSEC not enabled',
						absent: 'DNSSEC not observed',
					},
					'DNSSEC',
				)
			: unassessedScanProduct('dnssec_management', 'DNSSEC', caveatKind),
	];

	return {
		domain,
		score,
		grade,
		assessed,
		caveat,
		caveatKind,
		lockPosture,
		recommendations,
		recommendedCount: recommendations.filter((r) => r.recommended).length,
	};
}

/**
 * Extract the LockPosture from a check_rdap_lookup CheckResult.
 * Spec A attaches one shared `metadata` object (with `lockPosture`) to all RDAP
 * findings, so the first finding carrying it is authoritative. Returns null when
 * none (lookup_failed / redacted) — the MultiLock line then degrades to
 * "unobservable" while the scan-driven products still evaluate.
 */
export function extractLockPosture(rdap: CheckResult): LockPosture | null {
	for (const f of rdap.findings) {
		const meta = (f as { metadata?: Record<string, unknown> }).metadata;
		const posture = meta?.lockPosture;
		if (posture && typeof posture === 'object') return posture as LockPosture;
	}
	return null;
}

const CSC_PRODUCT_ORDER: CscProductKey[] = ['csc_multilock', 'managed_dmarc', 'digital_certificates', 'dnssec_management'];

/**
 * Render a CSC product report for display.
 *
 * `assessed` is load-bearing here, not decoration. Before it was read, an
 * unassessed domain rendered "**Score:** not measured | **3** recommended"
 * followed by three priority-tagged upsells justified by "DMARC not observed" —
 * recommendations derived entirely from non-observation, sitting under a score line
 * that admitted nothing was measured. `prioritize_csc_leads` already refused to
 * print exactly that from the same producer output; this is the other half of that
 * decision, stated once for both tools.
 */
export function formatCscProducts(report: CscProductReport, format: OutputFormat = 'full'): string {
	const lines: string[] = [];
	const byKey = new Map(report.recommendations.map((r) => [r.product, r]));
	// Unassessed: no product list and no count claim — except a product that is STILL
	// recommended, which can only be MultiLock on independent RDAP evidence. Withholding
	// that would suppress a real measurement.
	const shown = CSC_PRODUCT_ORDER.map((key) => byKey.get(key)).filter(
		(r): r is CscProductRecommendation => r !== undefined && (report.assessed || r.recommended),
	);

	// `caveat` is REQUIRED on `CscProductReport`, so the real producer
	// (`evaluateCscProducts`) always states which reason applies whenever
	// `!assessed`. Falling back to `UNASSESSED_CSC_NOTE` specifically was the
	// same silent-wrong-prose shape this fix round exists to remove: a
	// transient-outage report with a somehow-unset `caveat` would render the
	// "no checks ran" text even though N checks DID run. The only genuinely
	// safe fallback here makes no specific claim.
	const caveat = report.caveat ?? 'This domain could not be assessed.';

	if (format === 'compact') {
		const countSegment = report.assessed ? ` — ${report.recommendedCount} upsell(s)` : '';
		lines.push(`CSC products: ${sanitizeOutputText(report.domain, 253)} — ${formatScoreGrade(report.score, report.grade)}${countSegment}`);
		if (!report.assessed) lines.push(caveat);
		for (const r of shown) {
			// `!r.assessed` (F1, review round 1): a product `unassessedScanProduct`
			// built — the category itself (or the whole scan) was never observed —
			// MUST NOT render as `✓`, the SAME icon a genuine clean pass gets. Before
			// this branch, both states shared `recommended: false` and rendered
			// byte-identical in compact mode (`✓ Managed DMARC`, no gap text at all)
			// — the silent drop this task exists to close, on the format every
			// interactive LLM client auto-selects.
			const icon = !r.assessed ? ' ?' : r.recommended ? ' →' : ' ✓';
			const suffix = !r.assessed
				? ` ${sanitizeOutputText(r.justifyingGap, 80)}`
				: r.recommended
					? ` [${r.priority}] ${sanitizeOutputText(r.justifyingGap, 80)}`
					: '';
			lines.push(`${icon} ${sanitizeOutputText(r.productName, 40)}${suffix}`);
		}
	} else {
		lines.push(`# CSC Product Recommendations: ${sanitizeOutputText(report.domain, 253)}`);
		const countSegment = report.assessed ? ` | **${report.recommendedCount}** recommended` : '';
		lines.push(`**Score:** ${formatScoreGrade(report.score, report.grade)}${countSegment}`);
		if (!report.assessed) lines.push(caveat);
		lines.push('');
		for (const r of shown) {
			// Same F1 fix as compact mode above: an unassessed product must not tag
			// as `— OK` (indistinguishable from a genuine clean pass) even though the
			// gap line below already names it correctly — the TAG line is what a
			// skimming reader sees first.
			const icon = !r.assessed ? '❓' : r.recommended ? '✅' : '➖';
			const tag = !r.assessed ? ' — NOT ASSESSED' : r.recommended ? ` — ${r.priority.toUpperCase()}` : ' — OK';
			lines.push(`${icon} **${sanitizeOutputText(r.productName, 40)}**${tag}`);
			lines.push(`  - ${sanitizeOutputText(r.justifyingGap, 160)}`);
			for (const f of r.relatedFindings) lines.push(`  - ${sanitizeOutputText(f, 120)}`);
		}
	}

	return lines.join('\n').trimEnd();
}

/** runtimeOptions accepted by the orchestrator — ScanRuntimeOptions plus the optional WHOIS binding the RDAP call threads. */
type CscRuntimeOptions = ScanRuntimeOptions & { whoisBinding?: { fetch: typeof fetch } };

/**
 * Map a domain's security gaps to CSC products (orchestrator — the only impure unit).
 * Runs a full scan (cached) + a budget-bounded RDAP lookup, then evaluates.
 */
export async function mapCscProducts(domain: string, kv?: KVNamespace, runtimeOptions?: CscRuntimeOptions): Promise<CscProductReport> {
	// Capture the deadline epoch BEFORE kicking off both calls so the RDAP budget
	// is not charged for scan elapsed time (the two calls are independent).
	const deadlineMs = Date.now() + RDAP_LOOKUP_SYNC_BUDGET_MS;
	const [scanResult, rdap] = await Promise.all([
		scanDomain(domain, kv, runtimeOptions),
		checkRdapLookup(domain, {
			whoisBinding: runtimeOptions?.whoisBinding,
			signal: AbortSignal.timeout(RDAP_LOOKUP_SYNC_BUDGET_MS),
			deadlineMs,
		}),
	]);
	const lockPosture = extractLockPosture(rdap);
	return evaluateCscProducts(scanResult.checks, lockPosture, domain, scanResult.score.overall, scanResult.score.grade);
}
