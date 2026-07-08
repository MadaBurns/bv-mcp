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
 *     row per (sub_tenant, run) so progress can be tracked.
 *   - {@link handleTenantCycleAlerts} — every 15 min, alongside the existing
 *     fuzzing scan. Finds settled cycles with a pending alert, computes the
 *     diff vs the previous completed cycle, fires the webhook, and stamps
 *     `alert_sent_at` + `alert_outcome`. Idempotent across ticks.
 *
 * Both handlers are fail-soft: missing bindings / D1 errors / queue errors
 * never throw out of the cron tick (which would surface in Cloudflare's
 * scheduled-event analytics as `outcome=exception` and mask other handlers
 * sharing the same trigger). Errors are logged via `logError`.
 */

import { computeFingerprint, fingerprintsDiffer, type DnsQueryFn } from './dns-fingerprint';
import {
	computeCycleDiff,
	sendTenantAlert,
	type FindingRow,
} from './alerts';
import { logEvent, logError } from '../lib/log';
import { resolveTenantUncached, type TenantDbHandle } from './tenant-resolver';
import type { ScanQueueMessage } from '../schemas/tenant-internal';

/** Cloudflare Queue producer shape — same minimal type used by routes.ts. */
type ScanQueueProducer = {
	send(message: ScanQueueMessage, options?: { contentType?: 'json' }): Promise<void>;
};

export type TenantScheduledEnv = {
	TENANT_REGISTRY_DB?: D1Database;
	BV_SCANNER_QUEUE?: ScanQueueProducer;
	ALERT_WEBHOOK_URL?: string;
	[k: string]: unknown;
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
const INSERT_CYCLE_SQL =
	'INSERT INTO tenant_cycles (id, super_tenant_id, sub_tenant_id, started_at, expected_total, completed_total, errored_total, baseline_cycle_id) ' +
	'VALUES (?, ?, ?, ?, ?, 0, 0, ?)';
const INCREMENT_ERRORED_SQL =
	'UPDATE tenant_cycles SET errored_total = errored_total + ? WHERE id = ?';
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
const STAMP_ALERT_SQL =
	'UPDATE tenant_cycles SET alert_sent_at = ?, alert_outcome = ? WHERE id = ?';
const FINDINGS_FOR_CYCLE_SQL = `
	SELECT f.domain, f.category, f.severity, f.title
	FROM findings f
	WHERE f.scan_id IN (SELECT id FROM scans WHERE cycle_id = ?)
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
 *      = enqueued domains. DNS-failed domains are recorded immediately as
 *      `errored_total` so the cycle can settle.
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
	const queueErrors: string[] = [];

	for (const row of dueDomains) {
		try {
			const fp = await computeFingerprint(row.domain, { dnsQuery: deps.dnsQuery });
			if (fp.kind === 'error') {
				erroredCount += 1;
				continue;
			}

			const intervalMs =
				(row.watch_interval_hours ?? DEFAULT_WATCH_INTERVAL_HOURS) * 3600 * 1000;
			const stale =
				row.last_scanned_at !== null &&
				tNow - row.last_scanned_at > intervalMs * STALE_RESCAN_MULTIPLIER;

			const shouldEnqueue =
				row.last_scanned_at === null ||
				fingerprintsDiffer(fp.fingerprint, row.fingerprint) ||
				stale;

			// Always refresh the cached fingerprint so silent drift is captured even
			// when we skip the scan.
			try {
				await tenantDb
					.prepare(UPDATE_FINGERPRINT_SQL)
					.bind(fp.fingerprint, fp.capturedAt, row.domain)
					.run();
			} catch {
				// Best-effort cache refresh — don't surface as cycle error.
			}

			if (!shouldEnqueue) continue;

			try {
				await env.BV_SCANNER_QUEUE!.send(
					{ cycle_id: cycleId, sub_tenant_id: tenant.id, domain: row.domain },
					{ contentType: 'json' },
				);
				queuedCount += 1;
			} catch (err) {
				queueErrors.push(row.domain);
				erroredCount += 1;
				logError(err instanceof Error ? err : String(err), {
					severity: 'warn',
					category: 'tenant.scheduled',
					details: {
						message: 'tenant_weekly_rescan_queue_send_failed',
						subTenantId: tenant.id,
						cycleId,
					},
				});
			}
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

	const expectedTotal = queuedCount + erroredCount;
	if (expectedTotal === 0) return;

	let baselineCycleId: string | null = null;
	try {
		const baselineRow = await env
			.TENANT_REGISTRY_DB!.prepare(FIND_BASELINE_CYCLE_SQL)
			.bind(tenant.id)
			.first<{ id: string }>();
		baselineCycleId = baselineRow?.id ?? null;
	} catch {
		// Baseline lookup is best-effort — alert sweep falls back to
		// `skipped_no_baseline` if there's no baseline anyway.
	}

	try {
		await env.TENANT_REGISTRY_DB!.prepare(INSERT_CYCLE_SQL)
			.bind(cycleId, tenant.super_tenant_id, tenant.id, tNow, expectedTotal, baselineCycleId)
			.run();
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

	if (erroredCount > 0) {
		try {
			await env.TENANT_REGISTRY_DB!.prepare(INCREMENT_ERRORED_SQL)
				.bind(erroredCount, cycleId)
				.run();
		} catch {
			// Log only; the cycle is still tracked, just with errored_total stuck at 0.
		}
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
 * Per-cycle alert sweep. Runs alongside the existing fuzzing scan on the
 * 15-minute trigger.
 *
 * For each settled cycle without an alert:
 *   1. Pull current findings (`scan_id IN (SELECT id FROM scans WHERE cycle_id = ?)`)
 *   2. Pull baseline findings if `baseline_cycle_id` is set.
 *   3. `computeCycleDiff` produces a `TenantCycleAlert` payload.
 *   4. If totals.deltas === 0 → mark `'no_diff'`, no webhook call.
 *   5. Else `sendTenantAlert(payload, env)`. On `delivered: false` mark
 *      `'webhook_failed'`; on success mark `'sent'`. Either way stamp
 *      `alert_sent_at` so we don't loop on the same cycle.
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
	const stamp = async (outcome: string): Promise<void> => {
		try {
			await env.TENANT_REGISTRY_DB!.prepare(STAMP_ALERT_SQL)
				.bind(deps.now(), outcome, cycle.id)
				.run();
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
			tenantDb.prepare(FINDINGS_FOR_CYCLE_SQL).bind(cycle.baseline_cycle_id).all<FindingRowDb>(),
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
		// Mark as webhook_failed-equivalent so we don't loop on a permanently-broken cycle.
		await stamp('findings_query_failed');
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

	const result = await deps.send(payload, { ALERT_WEBHOOK_URL: webhookUrl });
	await stamp(result.delivered ? 'sent' : 'webhook_failed');
}
