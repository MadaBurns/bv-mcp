// SPDX-License-Identifier: BUSL-1.1

import type { TenantDbHandle } from './tenant-resolver';

/**
 * Count durable completions, including DLQ markers but excluding partial writes.
 *
 * The per-scan findings count also matches `f.domain = s.domain`. Every writer stores
 * the scan's domain on its findings, and that predicate lets SQLite use the
 * base-schema `idx_findings_domain_severity` when `idx_findings_scan_id` is missing.
 * Without it, each scan in the cycle is a full scan of `findings`. This query runs
 * once per queue message, so the cost was O(cycle scans × findings table).
 * Measured on prod 2026-09-24 at 240 scans / ~100k findings: 9.0 s and 24.0M rows
 * read per call, which stalled the weekly cycle at 240/500 (SQ-167). With the
 * domain predicate and no scan_id index: 62 ms and 52k rows.
 */
const COMPLETED_SCANS_SQL = `
	SELECT COUNT(*) AS completed_total FROM scans s
	WHERE s.cycle_id = ?
	  AND (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.domain = s.domain) >= COALESCE(s.finding_count, 0)
`;
const SYNC_COMPLETED_SQL = 'UPDATE tenant_cycles SET completed_total = MAX(completed_total, ?) WHERE id = ?';

/**
 * Synchronize instead of incrementing so redelivery and an ambiguous registry
 * write cannot count a domain twice. MAX prevents an older concurrent snapshot
 * from reducing progress. Missing cycles (ad hoc scans) remain a harmless no-op.
 * Errors propagate: queue redelivery or the scheduled sweep will retry safely.
 */
export async function synchronizeCycleProgress(registry: D1Database | undefined, tenantDb: TenantDbHandle, cycleId: string): Promise<void> {
	if (!registry) return;
	const row = await tenantDb.prepare(COMPLETED_SCANS_SQL).bind(cycleId).first<{ completed_total: number }>();
	await registry
		.prepare(SYNC_COMPLETED_SQL)
		.bind(row?.completed_total ?? 0, cycleId)
		.run();
}
