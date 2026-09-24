// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos hypotheses for the stalled-cycle settle (#1122) in the 15-minute
 * `handleTenantCycleAlerts` sweep (src/tenants/scheduled-handlers.ts):
 * reconcile each unsettled cycle (`synchronizeCycleProgress`,
 * src/tenants/cycle-progress.ts), then, past STALLED_CYCLE_SETTLE_MS (6h),
 * `settleStalledCycle`: a guarded `UPDATE … RETURNING`, a
 * `tenant_cycle_settled_partial` log and ONE operator alert via
 * `sendAlert(env.ALERT_WEBHOOK_URL, …, { bvWeb: env.BV_WEB })`.
 *
 * Each test is a hypothesis: "Given [failure], the sweep should [degradation]"
 * (testing-methodology principle 8). Only boundaries are mocked: the registry
 * and per-tenant D1s, the alert transport (global fetch and the BV_WEB
 * Fetcher), and time (the handler's `now` seam). The happy path against real
 * SQLite is test/tenants/cycle-alerts-d1.node.test.ts.
 *
 * ⚠️ BRITTLE BY DESIGN: the D1 mocks route every statement by SQL SUBSTRING
 * (`SQL_TAGS`) and model only the predicates these hypotheses depend on. A
 * statement that matches no tag, or more than one, is recorded as UNMATCHED
 * and every test asserts there are none. A rewrite of any of these queries in
 * scheduled-handlers.ts, cycle-progress.ts or tenant-resolver.ts therefore
 * fails here loudly: update `SQL_TAGS` and the modeled semantics in
 * `makeRegistry` together with the query.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { TenantScheduledEnv } from '../../src/tenants/scheduled-handlers';

const SQL_TAGS = {
	// Registry: src/tenants/scheduled-handlers.ts
	UNSETTLED_CYCLES: 'SELECT id, super_tenant_id, sub_tenant_id, started_at FROM tenant_cycles',
	SETTLE_STALLED: 'SET errored_total = expected_total - completed_total',
	PENDING_CYCLES: 'completed_total + errored_total >= expected_total',
	STAMP_ALERT: 'UPDATE tenant_cycles SET alert_sent_at = ?',
	// Registry: src/tenants/cycle-progress.ts
	SYNC_PROGRESS: 'SET completed_total = MAX(completed_total, ?)',
	// Registry: src/tenants/tenant-resolver.ts (convention routing)
	REGISTRY_LOOKUP: 'd1_db_id, routing_mode, active FROM sub_tenants',
	// Per-tenant D1: src/tenants/cycle-progress.ts
	COMPLETED_SCANS: 'SELECT COUNT(*) AS completed_total FROM scans s',
} as const;
type SqlTag = keyof typeof SQL_TAGS;

const REGISTRY_TAGS: readonly SqlTag[] = [
	'UNSETTLED_CYCLES',
	'SETTLE_STALLED',
	'PENDING_CYCLES',
	'STAMP_ALERT',
	'SYNC_PROGRESS',
	'REGISTRY_LOOKUP',
];
const TENANT_TAGS: readonly SqlTag[] = ['COMPLETED_SCANS'];

/**
 * The race guard SETTLE_STALLED_CYCLE_SQL must carry. The registry mock applies
 * it only when the statement contains it, so dropping the guard from the SQL
 * shows up here as a second settle rather than being masked by the mock.
 */
const SETTLE_GUARD = ['alert_sent_at IS NULL', 'completed_total + errored_total < expected_total'] as const;

const SUPER = 'super-1';
const TENANT_1 = 'tenant-1';
const TENANT_1_BINDING = 'TENANT_DB_TENANT_1';
const TENANT_2 = 'tenant-2';
const TENANT_2_BINDING = 'TENANT_DB_TENANT_2';

const STARTED_AT = 1_000_000;
const SIX_HOURS_MS = 6 * 3600 * 1000;
const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;
const PAST_DEADLINE = STARTED_AT + SIX_HOURS_MS + FIFTEEN_MINUTES_MS;

const OPS_WEBHOOK = 'https://hooks.example.com/ops-alerts';
/** On bv-web's ingest path, so `sendAlert` routes it over the BV_WEB binding when one is bound. */
const BV_WEB_INGEST_WEBHOOK = 'https://bv-web.example.com/api/internal/ops/bv-mcp-alerts/ops';

const REGISTRY_BUSY = 'D1_ERROR: database is locked: SQLITE_BUSY';
const TENANT_DB_DOWN = 'D1_ERROR: Network connection lost.';

type SqlOp = 'first' | 'all' | 'run';

interface SqlCall {
	db: string;
	tag: SqlTag | 'UNMATCHED';
	op: SqlOp;
	binds: unknown[];
	sql: string;
}

interface CycleRow {
	id: string;
	super_tenant_id: string;
	sub_tenant_id: string;
	started_at: number;
	expected_total: number;
	completed_total: number;
	errored_total: number;
	baseline_cycle_id: string | null;
	alert_sent_at: number | null;
	alert_outcome: string | null;
}

/**
 * Three domains expected. The tenant recount finds one durable completion; the
 * other two were dropped with no durable marker, so the cycle can never finish.
 *
 * No baseline keeps phase 2 (the customer diff) out of these hypotheses: a
 * settled cycle is stamped `skipped_no_baseline` and never reaches
 * `sendTenantAlert`, so every alert delivery observed here is the operator
 * settle alert.
 */
function stalledCycle(id: string, subTenantId: string, startedAt = STARTED_AT): CycleRow {
	return {
		id,
		super_tenant_id: SUPER,
		sub_tenant_id: subTenantId,
		started_at: startedAt,
		expected_total: 3,
		completed_total: 0,
		errored_total: 0,
		baseline_cycle_id: null,
		alert_sent_at: null,
		alert_outcome: null,
	};
}

type SqlHandler = (tag: SqlTag, binds: unknown[], sql: string) => unknown;

/** D1 stub that records every statement and routes it by SQL substring (see the header warning). */
function makeD1(label: string, tags: readonly SqlTag[], calls: SqlCall[], handle: SqlHandler): D1Database {
	const notModeled = () => {
		throw new Error(`${label} mock: not modeled`);
	};
	return {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const execute = async (op: SqlOp): Promise<unknown> => {
				const hits = tags.filter((tag) => sql.includes(SQL_TAGS[tag]));
				const tag = hits.length === 1 ? hits[0] : 'UNMATCHED';
				calls.push({ db: label, tag, op, binds, sql });
				if (tag === 'UNMATCHED') throw new Error(`${label} mock: unmatched SQL`);
				return handle(tag, binds, sql);
			};
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				first: async () => (await execute('first')) ?? null,
				all: async () => ({ results: (await execute('all')) ?? [], success: true, meta: {} }),
				run: async () => {
					await execute('run');
					return { success: true, meta: {} };
				},
				raw: notModeled,
			};
			return stmt as unknown as D1PreparedStatement;
		},
		batch: notModeled,
		exec: notModeled,
		dump: notModeled,
		withSession: notModeled,
	} as unknown as D1Database;
}

/**
 * Stateful registry: one shared `tenant_cycles` table, so consecutive and
 * concurrent sweeps observe each other's writes.
 */
function makeRegistry(
	calls: SqlCall[],
	options: {
		cycles: CycleRow[];
		tenants: string[];
		/** Cycle ids whose settle UPDATE throws. */
		settleFailsFor?: string[];
		/** Hold every UNSETTLED read until this many sweeps have read, so all of them saw the same pre-settle snapshot. */
		concurrentSweeps?: number;
	},
) {
	const cycles = new Map(options.cycles.map((cycle) => [cycle.id, { ...cycle }]));
	const isUnsettled = (c: CycleRow) => c.alert_sent_at === null && c.completed_total + c.errored_total < c.expected_total;
	let readers = 0;
	let releaseReaders = () => {};
	const allReadersArrived = new Promise<void>((resolve) => {
		releaseReaders = resolve;
	});

	const db = makeD1('registry', REGISTRY_TAGS, calls, async (tag, binds, sql) => {
		switch (tag) {
			case 'UNSETTLED_CYCLES': {
				const snapshot = [...cycles.values()]
					.filter(isUnsettled)
					.sort((a, b) => b.started_at - a.started_at)
					.slice(0, binds[0] as number)
					.map(({ id, super_tenant_id, sub_tenant_id, started_at }) => ({ id, super_tenant_id, sub_tenant_id, started_at }));
				if (options.concurrentSweeps) {
					readers += 1;
					if (readers >= options.concurrentSweeps) releaseReaders();
					await allReadersArrived;
				}
				return snapshot;
			}
			case 'REGISTRY_LOOKUP': {
				const id = binds[0] as string;
				return options.tenants.includes(id)
					? { id, super_tenant_id: SUPER, d1_db_id: `db-${id}`, routing_mode: 'convention', active: 1 }
					: null;
			}
			case 'SYNC_PROGRESS': {
				const [completed, id] = binds as [number, string];
				const cycle = cycles.get(id);
				if (cycle) cycle.completed_total = Math.max(cycle.completed_total, completed);
				return undefined;
			}
			case 'SETTLE_STALLED': {
				const id = binds[0] as string;
				if (options.settleFailsFor?.includes(id)) throw new Error(REGISTRY_BUSY);
				const cycle = cycles.get(id);
				const guarded = SETTLE_GUARD.every((predicate) => sql.includes(predicate));
				if (!cycle || (guarded && !isUnsettled(cycle))) return null;
				cycle.errored_total = cycle.expected_total - cycle.completed_total;
				if (!sql.includes('RETURNING')) return null;
				return { expected_total: cycle.expected_total, completed_total: cycle.completed_total, errored_total: cycle.errored_total };
			}
			case 'PENDING_CYCLES':
				return [...cycles.values()]
					.filter((c) => c.alert_sent_at === null && c.completed_total + c.errored_total >= c.expected_total)
					.sort((a, b) => a.started_at - b.started_at)
					.slice(0, binds[0] as number)
					.map((c) => ({ ...c }));
			case 'STAMP_ALERT': {
				const [sentAt, outcome, id] = binds as [number, string, string];
				const cycle = cycles.get(id);
				if (cycle) Object.assign(cycle, { alert_sent_at: sentAt, alert_outcome: outcome });
				return undefined;
			}
			default:
				throw new Error(`registry mock: ${tag} not modeled`);
		}
	});

	return { db, cycle: (id: string) => ({ ...cycles.get(id) }) };
}

/** Per-tenant D1: answers the durable-completion recount, or fails it while `outage.down` is set. */
function makeTenantDb(label: string, calls: SqlCall[], completedByCycle: Record<string, number>, outage = { down: false }): D1Database {
	return makeD1(label, TENANT_TAGS, calls, (_tag, binds) => {
		if (outage.down) throw new Error(TENANT_DB_DOWN);
		return { completed_total: completedByCycle[binds[0] as string] ?? 0 };
	});
}

/**
 * Built from scratch, never spread from `cloudflare:test`'s env: the Workers
 * pool binds a BV_WEB stub that answers 200, which would quietly give H2 an
 * alert transport it is supposed to lack.
 */
function sweepEnv(
	registry: D1Database,
	tenantDbs: Record<string, D1Database>,
	alerting: { ALERT_WEBHOOK_URL?: string; BV_WEB?: Fetcher } = {},
): TenantScheduledEnv {
	return { TENANT_REGISTRY_DB: registry, ...tenantDbs, ...alerting } as TenantScheduledEnv;
}

const ctx = { waitUntil: (_promise: Promise<unknown>) => undefined };

interface Delivery {
	transport: 'fetch' | 'BV_WEB';
	url: string;
	body: string;
}

interface LogLine {
	error?: string;
	category?: string;
	details?: Record<string, unknown>;
}

let deliveries: Delivery[];
let consoleLines: unknown[];

function recordDelivery(transport: Delivery['transport'], input: RequestInfo | URL, init?: RequestInit) {
	deliveries.push({ transport, url: String(input), body: String(init?.body ?? '') });
}

/** The alert webhook boundary: every global fetch is an operator-alert delivery attempt here. */
function stubWebhook(respond: () => Promise<Response>) {
	vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
		recordDelivery('fetch', input, init);
		return respond();
	});
}

function logLines(): LogLine[] {
	return consoleLines.flatMap((line) => {
		if (typeof line !== 'string') return [];
		try {
			return [JSON.parse(line) as LogLine];
		} catch {
			return [];
		}
	});
}

const settledPartialLogs = () => logLines().filter((line) => line.error === 'tenant_cycle_settled_partial');
const reconcileFailures = () => logLines().filter((line) => line.details?.message === 'tenant_cycle_reconcile_failed');
const settleCalls = (calls: SqlCall[], cycleId: string) => calls.filter((c) => c.tag === 'SETTLE_STALLED' && c.binds[0] === cycleId);
const unmatchedSql = (calls: SqlCall[]) => calls.filter((c) => c.tag === 'UNMATCHED').map((c) => `${c.db}: ${c.sql.trim()}`);

beforeEach(() => {
	deliveries = [];
	consoleLines = [];
	stubWebhook(async () => new Response('ok'));
	vi.spyOn(console, 'log').mockImplementation((line?: unknown) => {
		consoleLines.push(line);
	});
});

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe('Tenant stalled-cycle settle chaos (#1122)', () => {
	it('H1: Given the per-tenant D1 throws during the progress recount of a cycle past the 6h deadline, the sweep does NOT settle it (could not measure is not stalled) and still settles the next tenant', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const calls: SqlCall[] = [];
		// cycle-1 is newer, so UNSETTLED_CYCLES (ORDER BY started_at DESC) hands it to the loop first.
		const registry = makeRegistry(calls, {
			cycles: [stalledCycle('cycle-1', TENANT_1, STARTED_AT + 1_000), stalledCycle('cycle-2', TENANT_2)],
			tenants: [TENANT_1, TENANT_2],
		});
		const tenant1Outage = { down: true };
		const env = sweepEnv(
			registry.db,
			{
				[TENANT_1_BINDING]: makeTenantDb(TENANT_1, calls, { 'cycle-1': 1 }, tenant1Outage),
				[TENANT_2_BINDING]: makeTenantDb(TENANT_2, calls, { 'cycle-2': 1 }),
			},
			{ ALERT_WEBHOOK_URL: OPS_WEBHOOK },
		);

		await expect(handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE })).resolves.toBeUndefined();

		// The recount reached the broken D1 and failed there.
		const failedRecount = calls.findIndex((c) => c.db === TENANT_1 && c.tag === 'COMPLETED_SCANS');
		expect(failedRecount).toBeGreaterThanOrEqual(0);
		// An unmeasured cycle is never settled or alerted...
		expect(settleCalls(calls, 'cycle-1')).toHaveLength(0);
		expect(registry.cycle('cycle-1')).toMatchObject({ completed_total: 0, errored_total: 0, alert_sent_at: null });
		// ...and the recount failure is logged against it rather than thrown.
		expect(reconcileFailures()).toEqual([
			expect.objectContaining({ error: TENANT_DB_DOWN, details: expect.objectContaining({ cycleId: 'cycle-1' }) }),
		]);

		// Positive control in the same sweep: the identical cycle on a healthy D1
		// settles and alerts once, after the failed tenant.
		const [settleCycle2] = settleCalls(calls, 'cycle-2');
		expect(calls.indexOf(settleCycle2)).toBeGreaterThan(failedRecount);
		expect(registry.cycle('cycle-2')).toMatchObject({ completed_total: 1, errored_total: 2, alert_outcome: 'skipped_no_baseline' });
		expect(deliveries).toHaveLength(1);
		expect(deliveries[0].body).toContain('cycle_id: cycle-2');
		expect(settledPartialLogs().map((line) => line.details?.cycleId)).toEqual(['cycle-2']);

		// Deferred, not lost: once the D1 answers, the next sweep measures cycle-1 and settles it.
		tenant1Outage.down = false;
		await handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE + FIFTEEN_MINUTES_MS });
		expect(settleCalls(calls, 'cycle-1')).toHaveLength(1);
		expect(registry.cycle('cycle-1')).toMatchObject({ completed_total: 1, errored_total: 2, alert_outcome: 'skipped_no_baseline' });
		expect(deliveries.map((d) => d.body.includes('cycle_id: cycle-1'))).toEqual([false, true]);
		expect(unmatchedSql(calls)).toEqual([]);
	});

	it('H2: Given a stalled cycle and no alert transport (ALERT_WEBHOOK_URL and BV_WEB both unbound), the sweep still settles it exactly once, logs the settle, and resolves', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const calls: SqlCall[] = [];
		const registry = makeRegistry(calls, { cycles: [stalledCycle('cycle-1', TENANT_1)], tenants: [TENANT_1] });
		const env = sweepEnv(registry.db, { [TENANT_1_BINDING]: makeTenantDb(TENANT_1, calls, { 'cycle-1': 1 }) });
		expect(env.ALERT_WEBHOOK_URL).toBeUndefined();
		expect(env.BV_WEB).toBeUndefined();

		await expect(handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE })).resolves.toBeUndefined();

		// Reconcile, settle, then the settled cycle takes the normal alert path in the same sweep.
		expect(calls.map((c) => `${c.db}:${c.tag}`)).toEqual([
			'registry:UNSETTLED_CYCLES',
			'registry:REGISTRY_LOOKUP',
			`${TENANT_1}:COMPLETED_SCANS`,
			'registry:SYNC_PROGRESS',
			'registry:SETTLE_STALLED',
			'registry:PENDING_CYCLES',
			'registry:REGISTRY_LOOKUP',
			'registry:STAMP_ALERT',
		]);
		expect(registry.cycle('cycle-1')).toMatchObject({
			completed_total: 1,
			errored_total: 2,
			alert_sent_at: PAST_DEADLINE,
			alert_outcome: 'skipped_no_baseline',
		});
		expect(settledPartialLogs()).toHaveLength(1);
		expect(settledPartialLogs()[0].details).toMatchObject({ cycleId: 'cycle-1', expected: 3, completed: 1, notCompleted: 2 });
		expect(deliveries).toHaveLength(0);
		expect(reconcileFailures()).toEqual([]);
	});

	const deliveryFailures = [
		{
			name: 'the webhook answers HTTP 503',
			url: OPS_WEBHOOK,
			transport: 'fetch',
			respond: async () => new Response('upstream unavailable', { status: 503 }),
			logged: { error: 'Alert webhook returned HTTP 503', transport: 'public_url' },
		},
		{
			name: 'fetch rejects',
			url: OPS_WEBHOOK,
			transport: 'fetch',
			respond: async (): Promise<Response> => {
				throw new TypeError('Network connection lost.');
			},
			logged: { error: 'Network connection lost.', transport: 'public_url' },
		},
		{
			name: 'the BV_WEB service binding rejects',
			url: BV_WEB_INGEST_WEBHOOK,
			transport: 'BV_WEB',
			respond: async (): Promise<Response> => {
				throw new Error('bv-web binding unavailable');
			},
			logged: { error: 'bv-web binding unavailable', transport: 'service_binding' },
		},
	] as const;

	it.each(deliveryFailures)(
		'H3: Given $name, the stalled cycle is still settled, the sweep resolves, and the delivery failure is logged rather than thrown',
		async ({ url, transport, respond, logged }) => {
			const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
			const calls: SqlCall[] = [];
			const registry = makeRegistry(calls, { cycles: [stalledCycle('cycle-1', TENANT_1)], tenants: [TENANT_1] });
			if (transport === 'fetch') stubWebhook(respond);
			const bvWeb = {
				fetch: async (input: RequestInfo | URL, init?: RequestInit) => {
					recordDelivery('BV_WEB', input, init);
					return respond();
				},
			} as unknown as Fetcher;
			const env = sweepEnv(
				registry.db,
				{ [TENANT_1_BINDING]: makeTenantDb(TENANT_1, calls, { 'cycle-1': 1 }) },
				{ ALERT_WEBHOOK_URL: url, BV_WEB: bvWeb },
			);

			await expect(handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE })).resolves.toBeUndefined();

			// Exactly one delivery attempt, over the expected transport, and it failed.
			expect(deliveries.map((d) => d.transport)).toEqual([transport]);
			expect(deliveries[0].body).toContain('cycle_id: cycle-1');
			// The settle landed before the alert and is not undone by the failure.
			expect(settleCalls(calls, 'cycle-1')).toHaveLength(1);
			expect(registry.cycle('cycle-1')).toMatchObject({ completed_total: 1, errored_total: 2, alert_outcome: 'skipped_no_baseline' });
			expect(settledPartialLogs()).toHaveLength(1);
			// Logged by the alert transport...
			expect(logLines().filter((line) => line.category === 'alerting')).toEqual([
				expect.objectContaining({ error: logged.error, details: expect.objectContaining({ transport: logged.transport }) }),
			]);
			// ...and never thrown into the per-cycle reconcile handler.
			expect(reconcileFailures()).toEqual([]);
			expect(unmatchedSql(calls)).toEqual([]);
		},
	);

	it('H4: Given two consecutive sweeps over the same stalled cycle, it is settled and alerted exactly once', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const calls: SqlCall[] = [];
		const registry = makeRegistry(calls, { cycles: [stalledCycle('cycle-1', TENANT_1)], tenants: [TENANT_1] });
		const env = sweepEnv(
			registry.db,
			{ [TENANT_1_BINDING]: makeTenantDb(TENANT_1, calls, { 'cycle-1': 1 }) },
			{ ALERT_WEBHOOK_URL: OPS_WEBHOOK },
		);

		await handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE });
		await handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE + FIFTEEN_MINUTES_MS });

		// The settle moved the cycle out of UNSETTLED_CYCLES, so the second sweep never re-reconciles it.
		expect(calls.filter((c) => c.tag === 'UNSETTLED_CYCLES')).toHaveLength(2);
		expect(calls.filter((c) => c.tag === 'COMPLETED_SCANS')).toHaveLength(1);
		expect(settleCalls(calls, 'cycle-1')).toHaveLength(1);
		expect(deliveries).toHaveLength(1);
		expect(settledPartialLogs()).toHaveLength(1);
		expect(registry.cycle('cycle-1')).toMatchObject({ completed_total: 1, errored_total: 2, alert_sent_at: PAST_DEADLINE });
		expect(unmatchedSql(calls)).toEqual([]);
	});

	it('H4: Given two concurrent sweeps that BOTH listed the same stalled cycle, the guarded UPDATE … RETURNING lets only one of them settle and alert', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const calls: SqlCall[] = [];
		const registry = makeRegistry(calls, {
			cycles: [stalledCycle('cycle-1', TENANT_1)],
			tenants: [TENANT_1],
			concurrentSweeps: 2,
		});
		const env = sweepEnv(
			registry.db,
			{ [TENANT_1_BINDING]: makeTenantDb(TENANT_1, calls, { 'cycle-1': 1 }) },
			{ ALERT_WEBHOOK_URL: OPS_WEBHOOK },
		);

		await expect(
			Promise.all([
				handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE }),
				handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE }),
			]),
		).resolves.toEqual([undefined, undefined]);

		// Race control: both sweeps reached the settle for the same cycle...
		expect(settleCalls(calls, 'cycle-1')).toHaveLength(2);
		// ...but only the one whose UPDATE returned a row alerted.
		expect(deliveries).toHaveLength(1);
		expect(settledPartialLogs()).toHaveLength(1);
		expect(registry.cycle('cycle-1')).toMatchObject({ completed_total: 1, errored_total: 2 });
		expect(reconcileFailures()).toEqual([]);
		expect(unmatchedSql(calls)).toEqual([]);
	});

	it('H5: Given the registry settle UPDATE itself throws for one tenant, the sweep logs it, leaves that cycle retryable, and still settles the next tenant', async () => {
		const { handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');
		const calls: SqlCall[] = [];
		// cycle-1 is newer, so the loop reaches the failing settle first.
		const registry = makeRegistry(calls, {
			cycles: [stalledCycle('cycle-1', TENANT_1, STARTED_AT + 1_000), stalledCycle('cycle-2', TENANT_2)],
			tenants: [TENANT_1, TENANT_2],
			settleFailsFor: ['cycle-1'],
		});
		const env = sweepEnv(
			registry.db,
			{
				[TENANT_1_BINDING]: makeTenantDb(TENANT_1, calls, { 'cycle-1': 1 }),
				[TENANT_2_BINDING]: makeTenantDb(TENANT_2, calls, { 'cycle-2': 1 }),
			},
			{ ALERT_WEBHOOK_URL: OPS_WEBHOOK },
		);

		await expect(handleTenantCycleAlerts(env, ctx, { now: () => PAST_DEADLINE })).resolves.toBeUndefined();

		// The failing settle was attempted, then the loop moved on to the next tenant.
		const [failedSettle] = settleCalls(calls, 'cycle-1');
		const [settleCycle2] = settleCalls(calls, 'cycle-2');
		expect(failedSettle).toBeDefined();
		expect(settleCycle2).toBeDefined();
		expect(calls.indexOf(settleCycle2)).toBeGreaterThan(calls.indexOf(failedSettle));
		expect(registry.cycle('cycle-2')).toMatchObject({ completed_total: 1, errored_total: 2, alert_outcome: 'skipped_no_baseline' });
		expect(deliveries).toHaveLength(1);
		expect(deliveries[0].body).toContain('cycle_id: cycle-2');
		expect(settledPartialLogs().map((line) => line.details?.cycleId)).toEqual(['cycle-2']);
		// The failure is logged against cycle-1, which stays unsettled for the next tick.
		expect(reconcileFailures()).toEqual([
			expect.objectContaining({ error: REGISTRY_BUSY, details: expect.objectContaining({ cycleId: 'cycle-1' }) }),
		]);
		expect(registry.cycle('cycle-1')).toMatchObject({ completed_total: 1, errored_total: 0, alert_sent_at: null });
		expect(unmatchedSql(calls)).toEqual([]);
	});
});
