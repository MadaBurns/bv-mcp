// SPDX-License-Identifier: BUSL-1.1

/**
 * Tenant scan snapshot — the compact projection of a `ScanDomainResult` that
 * the per-tenant `scans` table stores and reads back.
 *
 * Both tenant scan paths (the queue consumer and the synchronous scan route)
 * persist `score` / `grade` / `maturity_stage` / `finding_count` columns, fan
 * `findings` out into the `findings` table, and serialise the same projection
 * into `result_json`. The fingerprint pre-flight then reads `result_json` back
 * and re-persists it under a new `cycle_id` when the domain's DNS fingerprint
 * is unchanged, so the written and parsed shapes MUST agree — this module is
 * the single definition of both directions.
 *
 * Deliberately a projection, not the whole `ScanDomainResult`: a full scan
 * carries ~19 `CheckResult`s with per-category findings and metadata, which is
 * far too large to round-trip through a D1 text column on every scan.
 *
 * `grade` is the canonical 9-band `ScanScore.grade` (the scoring SSOT), not the
 * NIST 6-band display letter. Display surfaces derive their own letter from the
 * stored numeric `score`; storing the raw field keeps the row unambiguous.
 */

import type { Finding } from '@blackveil/dns-checks/scoring';
import type { ScanDomainResult } from '../tools/scan-domain';

/**
 * Compact, round-trippable projection of a completed scan.
 *
 * `score` and `grade` are nullable because `ScanScore.overall` / `.grade` are:
 * a scan whose checks all came back inconclusive (unresolvable zone, NXDOMAIN,
 * scoring-bundle failure) is UNGRADED, and `null` is the single representation
 * of that. Substituting `0` / `'F'` here would persist a fabricated *failing
 * measurement* about a real domain into the tenant's `scans` table — and unlike
 * `null`, `0` survives every null-skipping filter downstream (it is the exact
 * defect `mean_score` and the DLQ writer were fixed for). The columns have
 * always been nullable, so no migration is involved.
 */
export interface TenantScanSnapshot {
	score: number | null;
	grade: string | null;
	maturityStage: number | null;
	findings: Finding[];
}

/**
 * Project a completed `ScanDomainResult` onto the persisted snapshot.
 *
 * Threads `overall` / `grade` through unchanged, nulls included — never
 * defaulted.
 */
export function toTenantScanSnapshot(result: ScanDomainResult): TenantScanSnapshot {
	return {
		score: result.score.overall,
		grade: result.score.grade,
		maturityStage: result.maturity?.stage ?? null,
		findings: result.score.findings ?? [],
	};
}

/**
 * Parse a `result_json` column back into a snapshot for the fingerprint
 * pre-flight. Returns `null` for anything that isn't a usable snapshot —
 * malformed JSON, a DLQ `{ error }` row, or a legacy row written before this
 * shape existed — so the caller falls through to a full scan rather than
 * re-persisting a broken row.
 */
export function parseTenantScanSnapshot(json: string | null | undefined): TenantScanSnapshot | null {
	if (!json) return null;
	let parsed: unknown;
	try {
		parsed = JSON.parse(json);
	} catch {
		return null;
	}
	if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
	const candidate = parsed as Partial<TenantScanSnapshot>;
	// Recognition is by KEY PRESENCE, not by value type. `score`/`grade` are
	// legitimately `null` on an ungraded scan, so a type-only guard would reject a
	// perfectly valid ungraded snapshot and force a needless full rescan of a
	// domain whose fingerprint is unchanged. Requiring the keys still rejects
	// everything this guard exists to reject: a DLQ `{ error }` row (neither key),
	// and a stray `CheckResult` row (`{ category, score, findings }` — has `score`
	// but no `grade`).
	const hasScore = 'score' in candidate && (typeof candidate.score === 'number' || candidate.score === null);
	const hasGrade = 'grade' in candidate && (typeof candidate.grade === 'string' || candidate.grade === null);
	if (!hasScore || !hasGrade) return null;
	return {
		score: typeof candidate.score === 'number' ? candidate.score : null,
		grade: typeof candidate.grade === 'string' ? candidate.grade : null,
		maturityStage: typeof candidate.maturityStage === 'number' ? candidate.maturityStage : null,
		findings: Array.isArray(candidate.findings) ? (candidate.findings as Finding[]) : [],
	};
}
