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
 *   - Findings are grouped by (domain, category). Within a group, an entry that
 *     exists in both arrays at different severity counts as `severity_changed`;
 *     an entry that exists only in current is `gained`; only in baseline is
 *     `lost`.
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
	return `${row.domain}\x00${row.category}`;
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

function buildDiffEntries(current: FindingRow[], baseline: FindingRow[]): DiffEntry[] {
	const baselineMap = new Map<string, FindingRow>();
	for (const row of baseline) baselineMap.set(findingKey(row), row);

	const entries: DiffEntry[] = [];
	const currentSeen = new Set<string>();

	for (const cur of current) {
		const key = findingKey(cur);
		currentSeen.add(key);
		const prev = baselineMap.get(key);
		if (!prev) {
			entries.push({
				domain: cur.domain,
				category: cur.category,
				delta: 'gained',
				severity: cur.severity,
				title: cur.title,
			});
		} else if (prev.severity !== cur.severity) {
			entries.push({
				domain: cur.domain,
				category: cur.category,
				delta: 'severity_changed',
				severity: cur.severity,
				previousSeverity: prev.severity,
				title: cur.title,
			});
		}
		// same severity → not a delta
	}

	for (const prev of baseline) {
		const key = findingKey(prev);
		if (currentSeen.has(key)) continue;
		entries.push({
			domain: prev.domain,
			category: prev.category,
			delta: 'lost',
			severity: prev.severity,
			title: prev.title,
		});
	}

	return entries;
}

function compareEntries(a: DiffEntry, b: DiffEntry): number {
	const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
	if (sev !== 0) return sev;
	if (a.domain !== b.domain) return a.domain < b.domain ? -1 : 1;
	if (a.category !== b.category) return a.category < b.category ? -1 : 1;
	if (a.delta !== b.delta) return a.delta < b.delta ? -1 : 1;
	return 0;
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
export function computeCycleDiff(
	current: FindingRow[],
	baseline: FindingRow[],
	opts: ComputeCycleDiffOptions,
): TenantCycleAlert {
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
