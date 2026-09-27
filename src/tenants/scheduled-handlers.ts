// SPDX-License-Identifier: BUSL-1.1

/**
 * Tenant cron orchestration — wires the DNS fingerprint, cycle-diff alerts,
 * and scanner queue producer primitives into two scheduled handlers driven by
 * Cloudflare Cron Triggers.
 *
 * Handlers:
 *   - {@link handleTenantWeeklyRescan} — Sunday 02:00 UTC. Enumerates active
 *     sub-tenants, finds domains whose `last_scanned_at + watch_interval` has
 *     elapsed, computes a DNS fingerprint per domain, and enqueues only the
 *     domains whose fingerprint actually changed. Inserts one `tenant_cycles`
 *     row per (sub_tenant, run) so progress can be tracked. A double-delivered
 *     or overlapping tick is refused by the guarded insert.
 *   - {@link handleTenantCycleAlerts} — every 15 min, alongside the existing
 *     fuzzing scan. Finds settled cycles with a pending alert, computes the
 *     diff vs the previous completed cycle, claims the cycle with a guarded
 *     `alert_sent_at` stamp, and fires the webhook only from the claiming
 *     sweep. Idempotent across ticks and overlapping sweeps.
 *
 * Both handlers are fail-soft: missing bindings / D1 errors / queue errors
 * never throw out of the cron tick (which would surface in Cloudflare's
 * scheduled-event analytics as `outcome=exception` and mask other handlers
 * sharing the same trigger). Errors are logged via `logError`.
 */

import { synchronizeCycleProgress } from './cycle-progress';
import { computeFingerprint, fingerprintsDiffer, type DnsQueryFn } from './dns-fingerprint';
import {
	computeCycleDiff,
	sendTenantAlert,
	type FindingRow,
} from './alerts';
import { buildAlertPayload, sendAlert } from '../lib/alerting';
import { createAnalyticsClient } from '../lib/analytics';
import { logEvent, logError } from '../lib/log';
import { resolveTenantUncached, type TenantDbHandle } from './tenant-resolver';
import type { ScanQueueMessage } from '../schemas/tenant-internal';

/** Cloudflare Queue producer shape — same minimal type used by routes.ts. */
type ScanQueueProducer = {
	send(message: ScanQueueMessage, options?: { contentType?: 'json' }): Promise<unknown>;
};

export type TenantScheduledEnv = {
	TENANT_REGISTRY_DB?: D1Database;
	BV_SCANNER_QUEUE?: ScanQueueProducer;
	ALERT_WEBHOOK_URL?: string;
	/** bv-web-prod binding: operator alerts to its ingest route go over it (see `sendAlert`). */
	BV_WEB?: Fetcher;
	/**
	 * `bv_dns_security_mcp` dataset binding. Optional/fail-open — when absent,
	 * `createAnalyticsClient` returns a no-op client and the weekly-rescan send
	 * loop still completes (see the `queue_batch` emission on send failure below).
	 */
	MCP_ANALYTICS?: AnalyticsEngineDataset;
};

/** Default watch interval (hours) when a domain row has it NULL. Matches the schema default. */
const DEFAULT_WATCH_INTERVAL_HOURS = 168;

/** Above this multiple of the watch interval, force a rescan even when the fingerprint is unchanged. */
const STALE_RESCAN_MULTIPLIER = 2;

/** Per-tick cap on number of cycles processed in the alert sweep — defense against runaway batches. */
const MAX_CYCLES_PER_ALERT_TICK = 100;
/** Per-tick cap on active tenants inspected by the weekly rescan dispatcher. */
const MAX_ACTIVE_TENANTS_PER_WEEKLY_TICK = 100;
/** Per-tick cap on due domains inspected for one tenant by the weekly rescan dispatcher. */
const MAX_DUE_DOMAINS_PER_TENANT_TICK = 500;

const ACTIVE_TENANTS_SQL =
	'SELECT id, super_tenant_id FROM sub_tenants WHERE active = 1 ORDER BY id LIMIT ?';
const DUE_DOMAINS_SQL = `
	SELECT domain, last_scanned_at, watch_interval_hours, fingerprint
	FROM domains
	WHERE watch = 1
	  AND (last_scanned_at IS NULL
	       OR last_scanned_at + COALESCE(watch_interval_hours, ?) * 3600000 < ?)
	ORDER BY COALESCE(last_scanned_at, 0), domain
	LIMIT ?
`;
const UPDATE_FINGERPRINT_SQL =
	'UPDATE domains SET fingerprint = ?, fingerprint_at = ? WHERE domain = ?';
/**
 * Cloudflare can deliver the weekly `0 2 * * SUN` event twice or let a slow tick
 * overlap the next invocation. A tenant cycle that started this recently belongs
 * to the same tick, never to a new week (168h apart), so a second dispatch for the
 * tenant inside this window is refused.
 */
const WEEKLY_DISPATCH_DEDUP_WINDOW_MS = 6 * 3600 * 1000;
// One guarded statement rather than a read-then-write: D1 runs each statement
// atomically against a single SQLite primary, so two overlapping invocations
// cannot both pass the NOT EXISTS probe. The loser sees `meta.changes === 0` and
// publishes nothing. The probe is served by idx_cycles_sub_tenant_ts. The first
// seven binds keep the column order; the last two feed the guard.
const INSERT_CYCLE_SQL = `
	INSERT INTO tenant_cycles (id, super_tenant_id, sub_tenant_id, started_at, expected_total, completed_total, errored_total, baseline_cycle_id)
	SELECT ?, ?, ?, ?, ?, 0, ?, ?
	WHERE NOT EXISTS (SELECT 1 FROM tenant_cycles WHERE sub_tenant_id = ? AND started_at > ?)
`;
const RECENT_CYCLE_SQL = 'SELECT id FROM tenant_cycles WHERE sub_tenant_id = ? AND started_at > ? ORDER BY started_at DESC LIMIT 1';
const INCREMENT_ERRORED_SQL =
	'UPDATE tenant_cycles SET errored_total = errored_total + ? WHERE id = ?';
const UNSETTLED_CYCLES_SQL = `
	SELECT id, super_tenant_id, sub_tenant_id, started_at FROM tenant_cycles
	WHERE alert_sent_at IS NULL AND completed_total + errored_total < expected_total
	ORDER BY started_at DESC LIMIT ?
`;
/**
 * A cycle still short of `expected_total` this long after it started will not
 * complete. The queue drops a message after `max_retries` with no durable marker
 * (bv-scanner-queue has no dead-letter queue). Healthy 500-domain cycles finish
 * in under 10 minutes. Without a deadline such a cycle never settles, never
 * alerts and is re-reconciled every tick forever (SQ-167: 09-13 and 09-20 cycles).
 */
const STALLED_CYCLE_SETTLE_MS = 6 * 3600 * 1000;
// Count every domain that never reported as errored so the cycle settles into
// the normal alert path. The guard makes this idempotent and race-safe.
const SETTLE_STALLED_CYCLE_SQL = `
	UPDATE tenant_cycles SET errored_total = expected_total - completed_total
	WHERE id = ? AND alert_sent_at IS NULL AND completed_total + errored_total < expected_total
	RETURNING expected_total, completed_total, errored_total
`;
/** Marks a stalled cycle whose progress could not be read (see {@link escalateUnreconcilableCycle}). */
const ALERT_OUTCOME_UNRECONCILABLE = 'unreconcilable';
// Moves alert_outcome NULL -> 'unreconcilable' but leaves alert_sent_at NULL, so
// the cycle stays in the reconcile loop while its operator alert fires only once.
const MARK_UNRECONCILABLE_SQL =
	'UPDATE tenant_cycles SET alert_outcome = ? WHERE id = ? AND alert_sent_at IS NULL AND alert_outcome IS NULL';
const FIND_BASELINE_CYCLE_SQL =
	'SELECT id FROM tenant_cycles WHERE sub_tenant_id = ? AND alert_sent_at IS NOT NULL ORDER BY started_at DESC LIMIT 1';
const PENDING_CYCLES_SQL = `
	SELECT id, super_tenant_id, sub_tenant_id, started_at, expected_total, completed_total, errored_total, baseline_cycle_id
	FROM tenant_cycles
	WHERE alert_sent_at IS NULL
	  AND completed_total + errored_total >= expected_total
	ORDER BY started_at ASC
	LIMIT ?
`;
// Guarded so only the sweep whose UPDATE changes the row owns the cycle's alert
// stage. Overlapping sweeps can both list the same pending cycle (SQ-197).
const STAMP_ALERT_SQL = 'UPDATE tenant_cycles SET alert_sent_at = ?, alert_outcome = ? WHERE id = ? AND alert_sent_at IS NULL';
/**
 * Provisional outcome the claiming sweep stamps BEFORE it delivers the customer
 * alert, then replaces with `sent` or `webhook_failed`. Delivery is therefore at
 * most once: a row left at `sending` means the isolate died mid-delivery.
 */
const ALERT_OUTCOME_SENDING = 'sending';
const RECORD_ALERT_OUTCOME_SQL = 'UPDATE tenant_cycles SET alert_outcome = ? WHERE id = ? AND alert_outcome = ?';
// Preserve durable queue failure markers as operational alerts while excluding
// unmeasured security findings from posture comparisons.
//
// Drive the query from the cycle's scans and join their findings. The previous
// form, `FROM findings f WHERE f.scan_id IN (... f.category ...)`, correlated
// the IN-subquery with the outer row. It scanned the whole findings table and
// re-ran the cycle subquery for every row. On prod, 2026-09-24, a 500-scan
// cycle over ~100k findings exceeded D1's CPU limit and reset the database even
// with idx_findings_scan_id present. The join returns the same rows in 14 ms.
// Every findings count also matches `domain`, so each stays bounded by the
// base-schema domain index when idx_findings_scan_id is missing (SQ-167).
const FINDINGS_FOR_CYCLE_SQL = `
	SELECT f.domain, f.category, f.severity, f.title
	FROM scans s
	JOIN findings f ON f.scan_id = s.id AND f.domain = s.domain
	WHERE s.cycle_id = ?
	  AND (s.score IS NOT NULL OR (f.category = 'queue' AND f.title = 'queue_dlq'))
	  AND (SELECT COUNT(*) FROM findings measured WHERE measured.scan_id = s.id AND measured.domain = s.domain) >= COALESCE(s.finding_count, 0)
`;

// A cycle measures only selected domains. Find each measured domain's latest
// complete, successful observation before this cycle, even when an intervening
// partial cycle skipped that domain. Failed/partial rows never replace knowledge.
// Joined from the cycle's scans like FINDINGS_FOR_CYCLE_SQL, so no findings
// access is a whole-table scan when idx_findings_scan_id is missing (SQ-167).
// Bind order is unchanged: the scan_at bound comes before the cycle id.
const BASELINE_FINDINGS_SQL = `
	SELECT f.domain, f.category, f.severity, f.title
	FROM scans current
	JOIN findings f ON f.domain = current.domain AND f.scan_id = (
		SELECT prior.id FROM scans prior
		WHERE prior.domain = current.domain AND prior.scan_at < ?
		  AND prior.cycle_id IS NOT current.cycle_id AND prior.score IS NOT NULL
		  AND (SELECT COUNT(*) FROM findings pf WHERE pf.scan_id = prior.id AND pf.domain = prior.domain) >= COALESCE(prior.finding_count, 0)
		ORDER BY prior.scan_at DESC, prior.id DESC LIMIT 1
	)
	WHERE current.cycle_id = ? AND current.score IS NOT NULL
	  AND (SELECT COUNT(*) FROM findings cf WHERE cf.scan_id = current.id AND cf.domain = current.domain) >= COALESCE(current.finding_count, 0)
`;

interface ActiveTenantRow {
	id: string;
	super_tenant_id: string;
}

interface DueDomainRow {
	domain: string;
	last_scanned_at: number | null;
	watch_interval_hours: number | null;
	fingerprint: string | null;
}

interface UnsettledCycleRow {
	id: string;
	super_tenant_id: string;
	sub_tenant_id: string;
	started_at: number;
}

interface PendingCycleRow {
	id: string;
	super_tenant_id: string;
	sub_tenant_id: string;
	started_at: number;
	expected_total: number;
	completed_total: number;
	errored_total: number;
	baseline_cycle_id: string | null;
}

interface FindingRowDb {
	domain: string;
	category: string;
	severity: string;
	title: string;
}

const ALLOWED_SEVERITIES: ReadonlySet<string> = new Set([
	'critical',
	'high',
	'medium',
	'low',
	'info',
]);

/**
 * Map a per-tenant `findings` row into the diff engine's `FindingRow` shape.
 * Defensive: rows with unrecognised severity get clamped to `'info'` rather
 * than crash the sweep, which would block every other cycle on the same tick.
 */
function toFindingRow(row: FindingRowDb): FindingRow {
	const severity = ALLOWED_SEVERITIES.has(row.severity) ? row.severity : 'info';
	return {
		domain: row.domain,
		category: row.category,
		severity: severity as FindingRow['severity'],
		title: row.title,
	};
}

/**
 * Hook the Phase 3 weekly rescan into the {@link TenantScheduledEnv}.
 *
 * Algorithm:
 *   1. Enumerate active sub_tenants from the shared registry.
 *   2. For each, look up the per-tenant D1 binding.
 *   3. Query domains where watch=1 AND (last_scanned_at IS NULL OR
 *      last_scanned_at + watch_interval_hours*3600000 < now).
 *   4. Compute fingerprint for each due domain.
 *   5. Decide whether to enqueue:
 *      - fingerprint differs from stored → enqueue
 *      - last_scanned_at NULL → enqueue (no baseline)
 *      - now - last_scanned_at > 2 * interval → enqueue (stale-rescan bypass)
 *      - otherwise → update fingerprint_at and skip
 *   6. Insert one `tenant_cycles` row per sub-tenant with `expected_total`
 *      = selected domains + DNS errors, then publish the selected scans.
 *      DNS errors initialize `errored_total` so the cycle can settle. The
 *      insert is refused, and nothing is published, when the tenant already
 *      has a cycle inside {@link WEEKLY_DISPATCH_DEDUP_WINDOW_MS}.
 *
 * Fail-soft: missing TENANT_REGISTRY_DB or BV_SCANNER_QUEUE → return early.
 * Per-domain or per-tenant errors are logged and the loop continues.
 */
export async function handleTenantWeeklyRescan(
	env: TenantScheduledEnv,
	ctx: { waitUntil: (p: Promise<unknown>) => void },
	options: {
		/** Test seam — defaults to `Date.now()`. */
		now?: () => number;
		/** Test seam — defaults to the production `queryDns`. */
		dnsQuery?: DnsQueryFn;
		/** Test seam — generate a cycle id. Defaults to `crypto.randomUUID()`. */
		newCycleId?: () => string;
	} = {},
): Promise<void> {
	void ctx; // ctx is reserved for future async telemetry
	if (!env.TENANT_REGISTRY_DB) {
		logEvent({
			timestamp: new Date().toISOString(),
			category: 'tenant.scheduled',
			severity: 'warn',
			details: { message: 'tenant_weekly_rescan_skipped_no_registry' },
		});
		return;
	}
	if (!env.BV_SCANNER_QUEUE) {
		logEvent({
			timestamp: new Date().toISOString(),
			category: 'tenant.scheduled',
			severity: 'warn',
			details: { message: 'tenant_weekly_rescan_skipped_no_queue' },
		});
		return;
	}

	const now = options.now ?? (() => Date.now());
	const newCycleId = options.newCycleId ?? (() => crypto.randomUUID());

	let tenants: ActiveTenantRow[];
	try {
		const result = await env.TENANT_REGISTRY_DB.prepare(ACTIVE_TENANTS_SQL).bind(MAX_ACTIVE_TENANTS_PER_WEEKLY_TICK).all<ActiveTenantRow>();
		tenants = result.results ?? [];
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'tenant.scheduled',
			details: { message: 'tenant_weekly_rescan_tenant_enum_failed' },
		});
		return;
	}

	for (const tenant of tenants) {
		try {
			await rescanTenant(env, tenant, { now, dnsQuery: options.dnsQuery, newCycleId });
		} catch (err) {
			// Catch-all — never let one tenant block the rest of the tick.
			logError(err instanceof Error ? err : String(err), {
				severity: 'error',
				category: 'tenant.scheduled',
				details: { message: 'tenant_weekly_rescan_tenant_failed', subTenantId: tenant.id },
			});
		}
	}
}

async function rescanTenant(
	env: TenantScheduledEnv,
	tenant: ActiveTenantRow,
	deps: {
		now: () => number;
		dnsQuery?: DnsQueryFn;
		newCycleId: () => string;
	},
): Promise<void> {
	// Phase 4: resolve the per-tenant D1 handle WITHOUT the request-scoped cache
	// (cron must not populate it). A missing backend / unresolvable tenant throws
	// `Tenant not found` — treat as provisioning lag and skip silently.
	let tenantDb: TenantDbHandle;
	try {
		tenantDb = (await resolveTenantUncached(env, tenant.id)).db;
	} catch {
		logEvent({
			timestamp: new Date().toISOString(),
			category: 'tenant.scheduled',
			severity: 'info',
			details: { message: 'tenant_weekly_rescan_tenant_binding_missing', subTenantId: tenant.id },
		});
		return;
	}

	const tNow = deps.now();
	let dueDomains: DueDomainRow[];
	try {
		const result = await tenantDb
			.prepare(DUE_DOMAINS_SQL)
			.bind(DEFAULT_WATCH_INTERVAL_HOURS, tNow, MAX_DUE_DOMAINS_PER_TENANT_TICK)
			.all<DueDomainRow>();
		dueDomains = result.results ?? [];
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'tenant.scheduled',
			details: { message: 'tenant_weekly_rescan_due_query_failed', subTenantId: tenant.id },
		});
		return;
	}

	if (dueDomains.length === 0) return;

	const cycleId = deps.newCycleId();
	let queuedCount = 0;
	let erroredCount = 0;
	const selectedDomains: string[] = [];

	for (const row of dueDomains) {
		try {
			const fp = await computeFingerprint(row.domain, { dnsQuery: deps.dnsQuery });
			if (fp.kind === 'error') {
				erroredCount += 1;
				continue;
			}

			const intervalMs = (row.watch_interval_hours ?? DEFAULT_WATCH_INTERVAL_HOURS) * 3600 * 1000;
			const stale = row.last_scanned_at !== null && tNow - row.last_scanned_at > intervalMs * STALE_RESCAN_MULTIPLIER;

			const shouldEnqueue = row.last_scanned_at === null || fingerprintsDiffer(fp.fingerprint, row.fingerprint) || stale;

			// Always refresh the cached fingerprint so silent drift is captured even
			// when we skip the scan.
			try {
				await tenantDb.prepare(UPDATE_FINGERPRINT_SQL).bind(fp.fingerprint, fp.capturedAt, row.domain).run();
			} catch {
				// Best-effort cache refresh — don't surface as cycle error.
			}

			if (!shouldEnqueue) continue;

			selectedDomains.push(row.domain);
		} catch (err) {
			erroredCount += 1;
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'tenant.scheduled',
				details: {
					message: 'tenant_weekly_rescan_domain_failed',
					subTenantId: tenant.id,
					domain: row.domain,
				},
			});
		}
	}

	const expectedTotal = selectedDomains.length + erroredCount;
	if (expectedTotal === 0) return;

	let baselineCycleId: string | null = null;
	try {
		const baselineRow = await env.TENANT_REGISTRY_DB!.prepare(FIND_BASELINE_CYCLE_SQL).bind(tenant.id).first<{ id: string }>();
		baselineCycleId = baselineRow?.id ?? null;
	} catch {
		// Baseline lookup is best-effort — alert sweep falls back to
		// `skipped_no_baseline` if there's no baseline anyway.
	}

	const dedupAfter = tNow - WEEKLY_DISPATCH_DEDUP_WINDOW_MS;
	try {
		const inserted = await env
			.TENANT_REGISTRY_DB!.prepare(INSERT_CYCLE_SQL)
			.bind(cycleId, tenant.super_tenant_id, tenant.id, tNow, expectedTotal, erroredCount, baselineCycleId, tenant.id, dedupAfter)
			.run();
		if (inserted.meta.changes === 0) {
			// The other delivery of this tick owns the tenant's cycle and its sends.
			const existing = await env
				.TENANT_REGISTRY_DB!.prepare(RECENT_CYCLE_SQL)
				.bind(tenant.id, dedupAfter)
				.first<{ id: string }>()
				.catch(() => null);
			logEvent({
				timestamp: new Date().toISOString(),
				category: 'tenant.scheduled',
				severity: 'warn',
				details: {
					message: 'tenant_weekly_rescan_skipped_duplicate',
					subTenantId: tenant.id,
					existingCycleId: existing?.id ?? null,
				},
			});
			return;
		}
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'tenant.scheduled',
			details: {
				message: 'tenant_weekly_rescan_cycle_insert_failed',
				subTenantId: tenant.id,
				cycleId,
			},
		});
		return;
	}

	// The complete expected count and fingerprint errors must exist before any
	// consumer can run. A failed insert above publishes no work.
	let sendErrors = 0;
	const sendLoopStartedAt = Date.now();
	for (const domain of selectedDomains) {
		try {
			await env.BV_SCANNER_QUEUE!.send({ cycle_id: cycleId, sub_tenant_id: tenant.id, domain }, { contentType: 'json' });
			queuedCount += 1;
		} catch (err) {
			sendErrors += 1;
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'tenant.scheduled',
				details: { message: 'tenant_weekly_rescan_queue_send_failed', subTenantId: tenant.id, cycleId },
			});
		}
	}
	if (sendErrors > 0) {
		await env.TENANT_REGISTRY_DB!.prepare(INCREMENT_ERRORED_SQL).bind(sendErrors, cycleId).run();
		erroredCount += sendErrors;
		// SQ-184: mirror the console-only failure above into `bv_dns_security_mcp`
		// via the SAME writer + `queue_batch` field conventions as the queue
		// consumer's batch-outcome counter (src/index.ts `worker.queue`), so a
		// failed BV_SCANNER_QUEUE.send during the Sunday dispatch is queryable by
		// `queryQueueFailures`/the daily digest instead of being console-only.
		// Fail-open: `createAnalyticsClient` no-ops when MCP_ANALYTICS is unbound,
		// and its internal write is already try/catch-guarded. No domain names —
		// only the aggregate failure count, matching the batch schema (no blob
		// slot exists for subTenantId/cycleId; those stay in the logError above).
		createAnalyticsClient(env.MCP_ANALYTICS).emitQueueBatchEvent({
			handler: 'tenant_weekly_rescan_queue_send',
			outcome: 'error',
			durationMs: Date.now() - sendLoopStartedAt,
			messageCount: selectedDomains.length,
			failureCount: sendErrors,
		});
	}

	logEvent({
		timestamp: new Date().toISOString(),
		category: 'tenant.scheduled',
		severity: 'info',
		details: {
			message: 'tenant_weekly_rescan_dispatched',
			subTenantId: tenant.id,
			cycleId,
			queued: queuedCount,
			errored: erroredCount,
		},
	});
}

/**
 * Settle a cycle that passed {@link STALLED_CYCLE_SETTLE_MS} still short of its
 * expected total. Every domain that never reported is counted as errored, so the
 * cycle reaches the normal alert path in the same sweep. That path compares only
 * the measured domains; unmeasured ones keep their prior knowledge. Because some
 * domains were never measured, one operator alert fires when the guarded UPDATE
 * settles the cycle. Delivery is fail-open.
 */
async function settleStalledCycle(env: TenantScheduledEnv, cycle: UnsettledCycleRow, nowMs: number): Promise<void> {
	const settled = await env
		.TENANT_REGISTRY_DB!.prepare(SETTLE_STALLED_CYCLE_SQL)
		.bind(cycle.id)
		.first<{ expected_total: number; completed_total: number; errored_total: number }>();
	if (!settled) return; // Settled concurrently (late completions or another tick).

	const details = {
		cycleId: cycle.id,
		superTenantId: cycle.super_tenant_id,
		subTenantId: cycle.sub_tenant_id,
		expected: settled.expected_total,
		completed: settled.completed_total,
		notCompleted: settled.errored_total,
		ageHours: Math.round((nowMs - cycle.started_at) / 3_600_000),
	};
	logError('tenant_cycle_settled_partial', { severity: 'error', category: 'tenant.scheduled', details });
	await sendAlert(
		env.ALERT_WEBHOOK_URL ?? '',
		buildAlertPayload({
			title: `Tenant monitoring cycle settled partial: ${details.notCompleted} of ${details.expected} domains never completed`,
			severity: 'warning',
			metrics: {
				cycle_id: details.cycleId,
				sub_tenant_id: details.subTenantId,
				expected: details.expected,
				completed: details.completed,
				not_completed: details.notCompleted,
				age_hours: details.ageHours,
			},
			threshold: `cycle complete within ${STALLED_CYCLE_SETTLE_MS / 3_600_000}h of start`,
		}),
		{ bvWeb: env.BV_WEB },
	).catch(() => {});
}

/**
 * Escalate a cycle past {@link STALLED_CYCLE_SETTLE_MS} whose progress could not
 * be reconciled this sweep: its per-tenant D1 is unreadable, or the tenant no
 * longer resolves (`Tenant not found`). Could-not-measure is not stalled, so the
 * cycle is not settled. It stays in the reconcile loop and settles normally once
 * it can be measured, and that later settle and alert stamp overwrite the marker.
 * It must not stay silent, though: the guarded mark lets exactly one sweep raise
 * ONE operator alert. Fail-open like {@link settleStalledCycle}: nothing throws.
 */
async function escalateUnreconcilableCycle(
	env: TenantScheduledEnv,
	cycle: UnsettledCycleRow,
	nowMs: number,
	reason: unknown,
): Promise<void> {
	const marked = await env
		.TENANT_REGISTRY_DB!.prepare(MARK_UNRECONCILABLE_SQL)
		.bind(ALERT_OUTCOME_UNRECONCILABLE, cycle.id)
		.run()
		.catch((err: unknown) => {
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'tenant.scheduled',
				details: { message: 'tenant_cycle_unreconcilable_mark_failed', cycleId: cycle.id },
			});
			return null;
		});
	if (!marked || marked.meta.changes === 0) return; // Mark failed, or already escalated by an earlier or concurrent sweep.

	const details = {
		cycleId: cycle.id,
		superTenantId: cycle.super_tenant_id,
		subTenantId: cycle.sub_tenant_id,
		ageHours: Math.round((nowMs - cycle.started_at) / 3_600_000),
		reason: reason instanceof Error ? reason.message : String(reason),
	};
	logError('tenant_cycle_unreconcilable', { severity: 'error', category: 'tenant.scheduled', details });
	await sendAlert(
		env.ALERT_WEBHOOK_URL ?? '',
		buildAlertPayload({
			title: 'Tenant monitoring cycle unreconcilable',
			severity: 'warning',
			metrics: {
				cycle_id: details.cycleId,
				sub_tenant_id: details.subTenantId,
				age_hours: details.ageHours,
				reason: details.reason,
			},
			threshold: `cycle progress readable within ${STALLED_CYCLE_SETTLE_MS / 3_600_000}h of start`,
		}),
		{ bvWeb: env.BV_WEB },
	).catch(() => {});
}

/**
 * Per-cycle alert sweep. Runs alongside the existing fuzzing scan on the
 * 15-minute trigger.
 *
 * First, every unsettled cycle is reconciled against its tenant D1. Past
 * {@link STALLED_CYCLE_SETTLE_MS} a measured cycle is settled partial, and one
 * whose progress cannot be read is escalated once as unreconcilable.
 *
 * For each settled cycle without an alert:
 *   1. Pull current findings (`scan_id IN (SELECT id FROM scans WHERE cycle_id = ?)`)
 *   2. Pull each measured domain's latest successful prior findings when a
 *      baseline exists; skipped and failed domains retain their prior knowledge.
 *   3. `computeCycleDiff` produces a `TenantCycleAlert` payload.
 *   4. If totals.deltas === 0 → mark `'no_diff'`, no webhook call.
 *   5. Else claim the cycle: stamp `alert_sent_at` with outcome `'sending'`,
 *      guarded on `alert_sent_at IS NULL`. Only the sweep whose stamp changed
 *      the row calls `sendTenantAlert(payload, env)`, then records `'sent'` or
 *      `'webhook_failed'`. Either way the cycle never loops or sends twice.
 *
 * Fail-soft per cycle — one failure does not stop the rest.
 */
export async function handleTenantCycleAlerts(
	env: TenantScheduledEnv,
	ctx: { waitUntil: (p: Promise<unknown>) => void },
	options: {
		/** Test seam — defaults to `Date.now()`. */
		now?: () => number;
		/** Test seam — override `sendTenantAlert` for unit/chaos tests. */
		sendAlert?: typeof sendTenantAlert;
	} = {},
): Promise<void> {
	void ctx;
	if (!env.TENANT_REGISTRY_DB) return;

	const now = options.now ?? (() => Date.now());
	const send = options.sendAlert ?? sendTenantAlert;

	// Recover completion writes lost during a registry outage, including when the
	// queue exhausted delivery retries after the tenant scan was already durable.
	try {
		const unsettled = await env.TENANT_REGISTRY_DB.prepare(UNSETTLED_CYCLES_SQL)
			.bind(MAX_CYCLES_PER_ALERT_TICK)
			.all<UnsettledCycleRow>();
		for (const cycle of unsettled.results ?? []) {
			const stalled = now() - cycle.started_at > STALLED_CYCLE_SETTLE_MS;
			let reconciled = false;
			try {
				const { db } = await resolveTenantUncached(env, cycle.sub_tenant_id);
				await synchronizeCycleProgress(env.TENANT_REGISTRY_DB, db, cycle.id);
				reconciled = true;
				if (stalled) {
					await settleStalledCycle(env, cycle, now());
				}
			} catch (err) {
				logError(err instanceof Error ? err : String(err), {
					severity: 'warn',
					category: 'tenant.scheduled',
					details: { message: 'tenant_cycle_reconcile_failed', cycleId: cycle.id },
				});
				// A settle failure is retried next tick. A cycle that cannot even be
				// measured past the deadline would otherwise fail here silently forever.
				if (stalled && !reconciled) await escalateUnreconcilableCycle(env, cycle, now(), err);
			}
		}
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'tenant.scheduled',
			details: { message: 'tenant_cycle_reconcile_query_failed' },
		});
	}

	let pending: PendingCycleRow[];
	try {
		const result = await env.TENANT_REGISTRY_DB.prepare(PENDING_CYCLES_SQL)
			.bind(MAX_CYCLES_PER_ALERT_TICK)
			.all<PendingCycleRow>();
		pending = result.results ?? [];
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'error',
			category: 'tenant.scheduled',
			details: { message: 'tenant_alert_sweep_query_failed' },
		});
		return;
	}

	for (const cycle of pending) {
		try {
			await processCycleAlert(env, cycle, { now, send });
		} catch (err) {
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'tenant.scheduled',
				details: {
					message: 'tenant_alert_sweep_cycle_failed',
					cycleId: cycle.id,
					subTenantId: cycle.sub_tenant_id,
				},
			});
		}
	}
}

async function processCycleAlert(
	env: TenantScheduledEnv,
	cycle: PendingCycleRow,
	deps: {
		now: () => number;
		send: typeof sendTenantAlert;
	},
): Promise<void> {
	// Resolves whether this sweep's write changed the row. With `claimed`, it
	// records the final outcome over this sweep's own `sending` claim.
	const stamp = async (outcome: string, claimed = false): Promise<boolean> => {
		try {
			const result = claimed
				? await env.TENANT_REGISTRY_DB!.prepare(RECORD_ALERT_OUTCOME_SQL).bind(outcome, cycle.id, ALERT_OUTCOME_SENDING).run()
				: await env.TENANT_REGISTRY_DB!.prepare(STAMP_ALERT_SQL).bind(deps.now(), outcome, cycle.id).run();
			return result.meta.changes !== 0;
		} catch (err) {
			logError(err instanceof Error ? err : String(err), {
				severity: 'warn',
				category: 'tenant.scheduled',
				details: {
					message: 'tenant_alert_stamp_failed',
					cycleId: cycle.id,
					outcome,
				},
			});
			return false;
		}
	};

	// Phase 4: cache-bypassing resolve (cron context).
	//
	// T2: distinguish a GENUINELY-missing/invalid tenant from a TRANSIENT
	// registry/D1 error. A definitive `Tenant not found` / `Invalid tenant
	// identifier` (missing row, deactivated, or absent convention binding) is
	// stamped `skipped_no_tenant_binding` — irreversible, so it must only fire for
	// a real terminal condition. Any OTHER error is transient: re-throw so the
	// outer sweep loop logs it and the cycle stays retryable (`alert_sent_at`
	// stays NULL) for the next cron tick, instead of permanently losing the alert.
	let tenantDb: TenantDbHandle;
	try {
		tenantDb = (await resolveTenantUncached(env, cycle.sub_tenant_id)).db;
	} catch (err) {
		if (
			err instanceof Error &&
			(err.message.startsWith('Tenant not found') || err.message.startsWith('Invalid tenant identifier'))
		) {
			// Tenant binding not available — mark and move on rather than loop forever.
			await stamp('skipped_no_tenant_binding');
			return;
		}
		// Transient registry/D1 error — do NOT stamp permanently skipped; leave retryable.
		throw err;
	}

	if (cycle.baseline_cycle_id === null) {
		await stamp('skipped_no_baseline');
		return;
	}

	let currentFindings: FindingRow[] = [];
	let baselineFindings: FindingRow[] = [];
	try {
		const [curr, base] = await Promise.all([
			tenantDb.prepare(FINDINGS_FOR_CYCLE_SQL).bind(cycle.id).all<FindingRowDb>(),
			tenantDb.prepare(BASELINE_FINDINGS_SQL).bind(cycle.started_at, cycle.id).all<FindingRowDb>(),
		]);
		currentFindings = (curr.results ?? []).map(toFindingRow);
		baselineFindings = (base.results ?? []).map(toFindingRow);
	} catch (err) {
		logError(err instanceof Error ? err : String(err), {
			severity: 'warn',
			category: 'tenant.scheduled',
			details: {
				message: 'tenant_alert_findings_query_failed',
				cycleId: cycle.id,
			},
		});
		// Leave the cycle retryable: a transient read must not permanently lose its alert.
		return;
	}

	const webhookUrl = env.ALERT_WEBHOOK_URL ?? '';
	const payload = computeCycleDiff(currentFindings, baselineFindings, {
		currentCycleId: cycle.id,
		baselineCycleId: cycle.baseline_cycle_id,
		superTenantId: cycle.super_tenant_id,
		subTenantId: cycle.sub_tenant_id,
		domainsScanned: cycle.completed_total,
		scanAt: cycle.started_at,
		emittedAt: deps.now(),
		webhookUrl: webhookUrl || 'https://placeholder.invalid/',
	});

	if (payload.totals.deltas === 0) {
		await stamp('no_diff');
		return;
	}

	// Claim before delivering: overlapping sweeps can both reach this point for
	// one cycle, and only the sweep whose guarded stamp changed the row may send.
	if (!(await stamp(ALERT_OUTCOME_SENDING))) return;
	const result = await deps.send(payload, { ALERT_WEBHOOK_URL: webhookUrl });
	await stamp(result.delivered ? 'sent' : 'webhook_failed', true);
}
