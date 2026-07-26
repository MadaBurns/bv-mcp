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
import { formatScoreGrade, hasCompletedEvidence } from '../lib/ungraded-display';

export type CscProductKey = 'csc_multilock' | 'managed_dmarc' | 'digital_certificates' | 'dnssec_management';

/** Sales-upsell priority — NOT a security severity. */
export type CscPriority = 'high' | 'medium' | 'low' | 'none';

export interface CscProductRecommendation {
	product: CscProductKey;
	productName: string;
	recommended: boolean;
	priority: CscPriority;
	justifyingGap: string;
	relatedFindings: string[];
}

export interface CscProductReport {
	domain: string;
	/** `null` when the scan produced no gradeable measurement. Never a coerced 0. */
	score: number | null;
	/** `null` when the scan produced no gradeable measurement. Never a fabricated letter. */
	grade: string | null;
	/**
	 * Did any check actually run? (`isMeasured` over the input results.)
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
	 * Populated only when `assessed` is `false`; `null` otherwise. Distinguishes
	 * "no checks ran" ({@link UNASSESSED_CSC_NOTE}) from "checks were attempted
	 * but none of them completed" ({@link buildAllTransientCscNote}) — the two
	 * failure modes `hasCompletedEvidence` collapses into the same `assessed:
	 * false`, but which are NOT the same fact and get distinct wording.
	 */
	caveat?: string | null;
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

/** Non-info finding titles from a failing CheckResult (mirrors map-compliance). */
function nonInfoTitles(result: CheckResult | undefined): string[] {
	if (!result) return [];
	return result.findings.filter((f) => f.severity !== 'info').map((f) => f.title);
}

/** MultiLock recommendation — reads the booleans, not `level` alone (Spec A handoff). */
function evalMultiLock(lockPosture: LockPosture | null): CscProductRecommendation {
	const base = { product: 'csc_multilock' as const, productName: CSC_PRODUCT_NAMES.csc_multilock, relatedFindings: [] as string[] };
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

/** Scan-driven product (dmarc/ssl/dnssec). Missing category → low-priority "not observed" lead. */
function evalScanProduct(
	product: Exclude<CscProductKey, 'csc_multilock'>,
	result: CheckResult | undefined,
	gaps: { passing: string; failing: string; absent: string },
): CscProductRecommendation {
	const base = { product, productName: CSC_PRODUCT_NAMES[product] };
	if (result === undefined) {
		return { ...base, recommended: true, priority: 'low', justifyingGap: gaps.absent, relatedFindings: [] };
	}
	if (result.passed) {
		return { ...base, recommended: false, priority: 'none', justifyingGap: gaps.passing, relatedFindings: [] };
	}
	const titles = nonInfoTitles(result);
	const hasSevere = result.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
	return { ...base, recommended: true, priority: hasSevere ? 'high' : 'medium', justifyingGap: gaps.failing, relatedFindings: titles };
}

/**
 * The scan-driven product line for a domain where NO check ran.
 *
 * `evalScanProduct`'s `absent` branch ("DMARC not observed") means "we looked and
 * found nothing" — a real, sellable gap. With zero checks nobody looked, so the
 * same branch would recommend all three products at once on the strength of
 * non-observation. This states the absence of evidence instead of pricing it.
 */
function unassessedScanProduct(product: Exclude<CscProductKey, 'csc_multilock'>, concern: string): CscProductRecommendation {
	return {
		product,
		productName: CSC_PRODUCT_NAMES[product],
		recommended: false,
		priority: 'none',
		justifyingGap: `${concern} not assessed — no checks ran`,
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
	const caveat = assessed ? null : checkResults.length === 0 ? UNASSESSED_CSC_NOTE : buildAllTransientCscNote(checkResults.length);

	// MultiLock is deliberately NOT gated on `assessed`: it reads the RDAP lock
	// posture, which is fetched independently of the scan. A registered domain whose
	// zone is broken can still show a genuinely unlocked transfer status, and that is
	// a real measurement — suppressing it would be the mirror defect.
	const recommendations: CscProductRecommendation[] = [
		evalMultiLock(lockPosture),
		assessed
			? evalScanProduct('managed_dmarc', byCategory.get('dmarc'), {
					passing: 'DMARC policy in effect',
					failing: 'DMARC present but not passing',
					absent: 'DMARC not observed',
				})
			: unassessedScanProduct('managed_dmarc', 'DMARC'),
		assessed
			? evalScanProduct('digital_certificates', byCategory.get('ssl'), {
					passing: 'TLS/SSL configuration healthy',
					failing: 'TLS/SSL issues detected',
					absent: 'TLS/SSL not observed',
				})
			: unassessedScanProduct('digital_certificates', 'TLS/SSL'),
		assessed
			? evalScanProduct('dnssec_management', byCategory.get('dnssec'), {
					passing: 'DNSSEC enabled',
					failing: 'DNSSEC not enabled',
					absent: 'DNSSEC not observed',
				})
			: unassessedScanProduct('dnssec_management', 'DNSSEC'),
	];

	return {
		domain,
		score,
		grade,
		assessed,
		caveat,
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

	const caveat = report.caveat ?? UNASSESSED_CSC_NOTE;

	if (format === 'compact') {
		const countSegment = report.assessed ? ` — ${report.recommendedCount} upsell(s)` : '';
		lines.push(`CSC products: ${sanitizeOutputText(report.domain, 253)} — ${formatScoreGrade(report.score, report.grade)}${countSegment}`);
		if (!report.assessed) lines.push(caveat);
		for (const r of shown) {
			const icon = r.recommended ? ' →' : ' ✓';
			const suffix = r.recommended ? ` [${r.priority}] ${sanitizeOutputText(r.justifyingGap, 80)}` : '';
			lines.push(`${icon} ${sanitizeOutputText(r.productName, 40)}${suffix}`);
		}
	} else {
		lines.push(`# CSC Product Recommendations: ${sanitizeOutputText(report.domain, 253)}`);
		const countSegment = report.assessed ? ` | **${report.recommendedCount}** recommended` : '';
		lines.push(`**Score:** ${formatScoreGrade(report.score, report.grade)}${countSegment}`);
		if (!report.assessed) lines.push(caveat);
		lines.push('');
		for (const r of shown) {
			const icon = r.recommended ? '✅' : '➖';
			const tag = r.recommended ? ` — ${r.priority.toUpperCase()}` : ' — OK';
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
