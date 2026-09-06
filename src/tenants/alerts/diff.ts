// SPDX-License-Identifier: BUSL-1.1
import {
	TenantCycleAlertSchema,
	TENANT_SEVERITY_LEVELS,
	hashWebhookUrl,
	type TenantCycleAlert,
	type TenantFindingDelta,
	type TenantSeverity,
} from '../../schemas/tenant-alerts';

/**
 * Pure cycle-diff engine for the Phase 3 Tenant alerts pipeline.
 *
 * `computeCycleDiff` consumes two arrays of finding rows (current cycle vs
 * baseline) — the shape matches the per-tenant `findings` D1 table in
 * src/tenants/db/schema/tenant.ts — and produces a validated `TenantCycleAlert`
 * payload ready for `sendTenantAlert`. No I/O, no env, no async; fully
 * unit-testable.
 *
 * Key behaviours:
 *   - Findings are matched by (domain, category, title), preserving duplicate
 *     occurrence counts. Equal-severity occurrences match first; remaining
 *     occurrences pair by severity descending as `severity_changed`, with
 *     unmatched current/baseline occurrences counted as `gained`/`lost`.
 *     Persisted rows have no stable cross-scan finding code, so a title change
 *     is a loss plus a gain, not a severity transition.
 *   - `highlights` is a top-N list ordered by severity desc then by domain for
 *     stability, capped at MAX_HIGHLIGHTS = 20 (the schema also enforces this).
 *   - `totals.by_severity` counts each individual delta (not just highlights)
 *     by the *new* severity (current side for severity_changed, current side for
 *     gained, baseline side for lost — i.e. whatever severity is now relevant
 *     for the operator).
 */

export interface FindingRow {
	/** Domain the finding applies to (validated by DomainSchema downstream). */
	domain: string;
	/** Check category (e.g. "dmarc", "spf", "dnssec"). 1-64 chars. */
	category: string;
	/** Severity at the time this finding was produced. */
	severity: TenantSeverity;
	/** Short human-readable headline. Sanitised by the schema. */
	title: string;
}

export interface ComputeCycleDiffOptions {
	currentCycleId: string;
	baselineCycleId: string | null;
	superTenantId: string;
	subTenantId: string;
	domainsScanned: number;
	scanAt: number;
	emittedAt?: number;
	webhookUrl: string;
}

const SEVERITY_RANK: Record<TenantSeverity, number> = {
	critical: 5,
	high: 4,
	medium: 3,
	low: 2,
	info: 1,
};

const MAX_HIGHLIGHTS = 20;

function findingKey(row: FindingRow): string {
	return JSON.stringify([row.domain, row.category, row.title]);
}

function emptySeverityCounts(): Record<TenantSeverity, number> {
	return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

interface DiffEntry {
	domain: string;
	category: string;
	delta: 'gained' | 'lost' | 'severity_changed';
	severity: TenantSeverity;
	previousSeverity?: TenantSeverity;
	title: string;
}

function groupFindings(rows: FindingRow[]): Map<string, { row: FindingRow; counts: Record<TenantSeverity, number> }> {
	const groups = new Map<string, { row: FindingRow; counts: Record<TenantSeverity, number> }>();
	for (const row of rows) {
		const key = findingKey(row);
		let group = groups.get(key);
		if (!group) {
			group = { row, counts: emptySeverityCounts() };
			groups.set(key, group);
		}
		group.counts[row.severity] += 1;
	}
	return groups;
}

function buildDiffEntries(current: FindingRow[], baseline: FindingRow[]): DiffEntry[] {
	const currentGroups = groupFindings(current);
	const baselineGroups = groupFindings(baseline);
	const entries: DiffEntry[] = [];
	for (const key of new Set([...currentGroups.keys(), ...baselineGroups.keys()])) {
		const cur = currentGroups.get(key);
		const prev = baselineGroups.get(key);
		const row = (cur ?? prev)!.row;
		const gained: TenantSeverity[] = [];
		const lost: TenantSeverity[] = [];
		for (const severity of TENANT_SEVERITY_LEVELS) {
			const difference = (cur?.counts[severity] ?? 0) - (prev?.counts[severity] ?? 0);
			for (let i = 0; i < Math.abs(difference); i++) {
				(difference > 0 ? gained : lost).push(severity);
			}
		}
		for (let i = 0; i < Math.max(gained.length, lost.length); i++) {
			const severity = gained[i];
			const previousSeverity = lost[i];
			entries.push({
				domain: row.domain,
				category: row.category,
				title: row.title,
				delta: severity === undefined ? 'lost' : previousSeverity === undefined ? 'gained' : 'severity_changed',
				severity: severity ?? previousSeverity,
				...(severity !== undefined && previousSeverity !== undefined ? { previousSeverity } : {}),
			});
		}
	}

	return entries;
}

function compareEntries(a: DiffEntry, b: DiffEntry): number {
	const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
	if (sev !== 0) return sev;
	if (a.domain !== b.domain) return a.domain < b.domain ? -1 : 1;
	if (a.category !== b.category) return a.category < b.category ? -1 : 1;
	if (a.delta !== b.delta) return a.delta < b.delta ? -1 : 1;
	if (a.title !== b.title) return a.title < b.title ? -1 : 1;
	return (b.previousSeverity ? SEVERITY_RANK[b.previousSeverity] : 0) - (a.previousSeverity ? SEVERITY_RANK[a.previousSeverity] : 0);
}

function toFindingDelta(entry: DiffEntry, opts: ComputeCycleDiffOptions): TenantFindingDelta {
	const out: TenantFindingDelta = {
		domain: entry.domain,
		category: entry.category,
		severity: entry.severity,
		title: entry.title,
		delta: entry.delta,
		cycle_id: opts.currentCycleId,
		scan_at: opts.scanAt,
	};
	if (entry.previousSeverity !== undefined) {
		out.previous_severity = entry.previousSeverity;
	}
	return out;
}

/**
 * Build a validated TenantCycleAlert payload from current vs baseline finding rows.
 *
 * Pure function — throws only if the resulting payload fails schema validation
 * (defensive, indicates a producer bug rather than a runtime/env issue).
 */
export function computeCycleDiff(current: FindingRow[], baseline: FindingRow[], opts: ComputeCycleDiffOptions): TenantCycleAlert {
	const entries = buildDiffEntries(current, baseline);
	entries.sort(compareEntries);

	const bySeverity = emptySeverityCounts();
	for (const e of entries) bySeverity[e.severity] += 1;

	const highlights = entries.slice(0, MAX_HIGHLIGHTS).map((e) => toFindingDelta(e, opts));

	const payload = {
		type: 'tenant_cycle_diff' as const,
		emitted_at: opts.emittedAt ?? Date.now(),
		super_tenant_id: opts.superTenantId,
		sub_tenant_id: opts.subTenantId,
		current_cycle_id: opts.currentCycleId,
		baseline_cycle_id: opts.baselineCycleId,
		totals: {
			domains_scanned: opts.domainsScanned,
			deltas: entries.length,
			by_severity: bySeverity,
		},
		highlights,
		webhook_url_hash: hashWebhookUrl(opts.webhookUrl),
	};

	return TenantCycleAlertSchema.parse(payload);
}

/** Exposed for tests + downstream consumers that need the canonical ordering. */
export function _severityRankForTest(): Record<TenantSeverity, number> {
	return { ...SEVERITY_RANK };
}

/** Exposed for tests; consumers should rely on schema-enforced cap. */
export const _MAX_HIGHLIGHTS = MAX_HIGHLIGHTS;

/** Re-export for convenience so consumers do not need two imports. */
export { TENANT_SEVERITY_LEVELS };
