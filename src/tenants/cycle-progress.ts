// SPDX-License-Identifier: BUSL-1.1

import type { TenantDbHandle } from './tenant-resolver';

/** Count durable completions, including DLQ markers but excluding partial writes. */
const COMPLETED_SCANS_SQL = `
	SELECT COUNT(*) AS completed_total FROM scans s
	WHERE s.cycle_id = ?
	  AND (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) >= COALESCE(s.finding_count, 0)
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
