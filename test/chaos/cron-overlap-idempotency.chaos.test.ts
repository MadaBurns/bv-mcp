// SPDX-License-Identifier: BUSL-1.1

/**
 * Chaos F: cron overlap and idempotency.
 *
 * Cloudflare can deliver a scheduled event twice (retry-on-slow-ack) or let a
 * slow tick's async work overlap the next tick's invocation. Each test below
 * takes the form "Given [overlap/failure], the system should [degrade
 * gracefully]." Per the testing-methodology skill (principle 8), each
 * hypothesis and its negative control are recorded verbatim in a ticket
 * comment (SQ-193) alongside this file, not just asserted here.
 *
 * Only D1, the scanner queue, Analytics Engine (via `fetch`), `fetch` itself,
 * and `Date`/timer seams are mocked — everything else (routeCron,
 * normalizeCron, handleTenantWeeklyRescan, handleTenantCycleAlerts,
 * handleDailyDigest, worker.scheduled) runs real production code.
 *
 * D1/queue mock patterns are copied in-file from
 * `test/chaos/tenant-cron.chaos.test.ts` and `test/tenants/cron.integration.test.ts`
 * per the ticket's declared-files scope — those two files are read-only
 * references, not edited here.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import type { TenantScheduledEnv } from '../../src/tenants/scheduled-handlers';
import type { DnsQueryFn } from '../../src/tenants/dns-fingerprint';
import type { DohResponse } from '../../src/lib/dns-types';

// handleDailyDigest runs the SPF canary first (20 real outbound DoH probes).
// Stubbed the same way test/client-ip-audit.spec.ts does it — the canary
// itself isn't part of H3's hypothesis (AE query failure), and letting its
// real DoH fetches run would make this suite depend on outbound network
// access it doesn't have in the Workers test pool.
vi.mock('../../src/lib/spf-canary', async () => {
	const actual = await vi.importActual<typeof import('../../src/lib/spf-canary')>('../../src/lib/spf-canary');
	return {
		...actual,
		runSpfCanary: async () => ({ totalProbed: 0, nullCount: 0, errorCount: 0, nullRate: 0, nullDomains: [], errorDomains: [] }),
	};
});

const SUPER = 'super-tenant-1';
const TENANT_A = 'tenant-1';
const TENANT_A_BINDING = 'TENANT_DB_TENANT_1';
const REGISTRY_ROW_A = { id: TENANT_A, super_tenant_id: SUPER, d1_db_id: 'db-1', routing_mode: 'convention', active: 1 };

function makeCtx() {
	return { waitUntil: (_p: Promise<unknown>) => undefined };
}

const okMeta = (): D1ExecResult => ({ count: 0, duration: 0 }) as unknown as D1ExecResult;

const okDns: DnsQueryFn = async (_d, _t): Promise<DohResponse> => ({ Status: 0, Answer: [] }) as unknown as DohResponse;

/** Recording D1 stub that returns canned rows by SQL substring (copied from tenant-cron.chaos.test.ts). */
function makeRecordingD1(rowsByTag: Record<string, unknown[]>) {
	const calls: Array<{ sql: string; binds: unknown[] }> = [];
	const lookup = (sql: string): unknown[] => {
		for (const tag of Object.keys(rowsByTag)) if (sql.includes(tag)) return rowsByTag[tag];
		return [];
	};
	const db: Record<string, unknown> = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					calls.push({ sql, binds });
					return (lookup(sql)[0] ?? null) as T | null;
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					return { results: lookup(sql) as T[], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ sql, binds });
					return { success: true, meta: {} } as unknown as D1Response;
				},
				async raw() {
					return [] as unknown[];
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
		batch: async () => [],
		exec: async () => okMeta(),
		dump: () => {
			throw new Error('ni');
		},
		withSession: () => {
			throw new Error('ni');
		},
	};
	return { db: db as unknown as D1Database, calls };
}

/**
 * Poll a synchronous predicate across microtask ticks (no real timers/IO
 * involved anywhere downstream, so every mocked D1/queue call resolves on the
 * microtask queue). Used to pause the test exactly once an in-flight handler
 * has reached a specific, observable point (e.g. "the cycle row exists but
 * the send loop hasn't finished") without guessing at await counts.
 */
async function flushUntil(predicate: () => boolean, maxTicks = 500): Promise<void> {
	for (let i = 0; i < maxTicks; i++) {
		if (predicate()) return;
		await Promise.resolve();
	}
	throw new Error('flushUntil: condition not met within microtask budget');
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
 * A registry D1 stub that keeps a real in-memory `tenant_cycles` table and
 * evaluates the SAME WHERE predicates the production SQL uses (matched by
 * substring, same technique as `makeRecordingD1`), so two concurrently
 * running handlers observe each other's writes exactly like a shared D1
 * database would — needed for H2, where `handleTenantCycleAlerts` must see
 * the row `handleTenantWeeklyRescan` inserted moments earlier in the same
 * tick. `sub_tenants` reads (active-tenant enumeration + per-tenant registry
 * lookup) are served from static fixture rows since nothing mutates them.
 */
function makeStatefulRegistry(tenants: Array<{ id: string; super_tenant_id: string }>, registryRows: Record<string, unknown>) {
	const cycles = new Map<string, CycleRow>();
	const calls: Array<{ sql: string; binds: unknown[] }> = [];

	const db: Record<string, unknown> = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					calls.push({ sql, binds });
					if (sql.includes('d1_db_id, routing_mode, active FROM sub_tenants')) {
						return (registryRows[binds[0] as string] ?? null) as T | null;
					}
					// FIND_BASELINE_CYCLE_SQL — no baseline fixture needed for H1/H2 (cycle
					// creation and the "don't touch a fresh cycle" assertions don't depend
					// on it; `baseline_cycle_id: null` just means alert processing would
					// stamp `skipped_no_baseline` if it ever reached that cycle, which H2
					// asserts it does not).
					return null as T | null;
				},
				async all<T = unknown>() {
					calls.push({ sql, binds });
					if (sql.includes('FROM sub_tenants WHERE active = 1')) {
						return { results: tenants as unknown as T[], success: true, meta: {} } as unknown as D1Result<T>;
					}
					if (sql.includes('completed_total + errored_total < expected_total')) {
						// UNSETTLED_CYCLES_SQL
						const rows = [...cycles.values()].filter(
							(c) => c.alert_sent_at === null && c.completed_total + c.errored_total < c.expected_total,
						);
						return { results: rows as unknown as T[], success: true, meta: {} } as unknown as D1Result<T>;
					}
					if (sql.includes('completed_total + errored_total >= expected_total')) {
						// PENDING_CYCLES_SQL
						const rows = [...cycles.values()].filter(
							(c) => c.alert_sent_at === null && c.completed_total + c.errored_total >= c.expected_total,
						);
						return { results: rows as unknown as T[], success: true, meta: {} } as unknown as D1Result<T>;
					}
					return { results: [] as T[], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ sql, binds });
					if (sql.includes('INSERT INTO tenant_cycles')) {
						const [id, superTenantId, subTenantId, startedAt, expectedTotal, erroredCount, baselineCycleId] = binds as [
							string,
							string,
							string,
							number,
							number,
							number,
							string | null,
						];
						cycles.set(id, {
							id,
							super_tenant_id: superTenantId,
							sub_tenant_id: subTenantId,
							started_at: startedAt,
							expected_total: expectedTotal,
							completed_total: 0,
							errored_total: erroredCount,
							baseline_cycle_id: baselineCycleId,
							alert_sent_at: null,
							alert_outcome: null,
						});
					} else if (sql.includes('UPDATE tenant_cycles SET errored_total = errored_total + ?')) {
						const [inc, id] = binds as [number, string];
						const row = cycles.get(id);
						if (row) row.errored_total += inc;
					} else if (sql.includes('UPDATE tenant_cycles SET completed_total = MAX(completed_total, ?)')) {
						const [val, id] = binds as [number, string];
						const row = cycles.get(id);
						if (row) row.completed_total = Math.max(row.completed_total, val);
					} else if (sql.includes('UPDATE tenant_cycles SET alert_sent_at = ?, alert_outcome = ?')) {
						const [sentAt, outcome, id] = binds as [number, string, string];
						const row = cycles.get(id);
						if (row) {
							row.alert_sent_at = sentAt;
							row.alert_outcome = outcome;
						}
					}
					return { success: true, meta: {} } as unknown as D1Response;
				},
				async raw() {
					return [] as unknown[];
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
		batch: async () => [],
		exec: async () => okMeta(),
		dump: () => {
			throw new Error('ni');
		},
		withSession: () => {
			throw new Error('ni');
		},
	};
	return { db: db as unknown as D1Database, cycles, calls };
}

describe('Chaos F: cron overlap and idempotency', () => {
	describe('H1: weekly rescan cron fires TWICE for the same week', () => {
		it(
			'FALSIFIED: no double-fire guard exists — two scheduled() calls for the same tick insert TWO ' +
				'tenant_cycles rows and enqueue each domain TWICE, not once (guard absent — filed as follow-up, see SQ-193 comment)',
			async () => {
				const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');

				const due = [
					{ domain: 'a.example.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
					{ domain: 'b.example.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
				];
				// Same mock registry/tenant-db state is read by BOTH calls — matching the
				// real hazard: `last_scanned_at` only advances once a scan COMPLETES (via
				// the queue consumer, elsewhere), never during dispatch itself, so a
				// double-delivered tick sees the identical "due" set both times.
				const registry = makeRecordingD1({
					'FROM sub_tenants WHERE active = 1': [{ id: TENANT_A, super_tenant_id: SUPER }],
					'd1_db_id, routing_mode, active FROM sub_tenants': [REGISTRY_ROW_A],
				});
				const tenant = makeRecordingD1({ 'FROM domains': due });

				const queueSends: unknown[] = [];
				const queue = {
					async send(msg: unknown) {
						queueSends.push(msg);
					},
				};
				const customEnv: TenantScheduledEnv = {
					...env,
					TENANT_REGISTRY_DB: registry.db,
					BV_SCANNER_QUEUE: queue,
					[TENANT_A_BINDING]: tenant.db,
				} as TenantScheduledEnv;

				const T0 = 9_999_999_999_999;
				let cycleCounter = 0;
				const newCycleId = () => `cycle-${(cycleCounter += 1)}`;

				// Two independent scheduled() deliveries, same scheduledTime, run
				// sequentially (Cloudflare would run them as separate isolate
				// invocations, not concurrently within one) — that's exactly what
				// "fires twice" means operationally.
				await expect(handleTenantWeeklyRescan(customEnv, makeCtx(), { now: () => T0, newCycleId, dnsQuery: okDns })).resolves.toBeUndefined();
				await expect(handleTenantWeeklyRescan(customEnv, makeCtx(), { now: () => T0, newCycleId, dnsQuery: okDns })).resolves.toBeUndefined();

				const cycleInserts = registry.calls.filter((c) => c.sql.includes('INSERT INTO tenant_cycles'));
				// H1 as phrased ("exactly one tenant_cycles row … enqueues each domain
				// once") is FALSIFIED: nothing in handleTenantWeeklyRescan / rescanTenant
				// deduplicates a same-tick redelivery (no week-marker, no upsert-by-week
				// key, no advisory lock). This asserts the MEASURED behavior instead.
				expect(cycleInserts).toHaveLength(2);
				expect(queueSends).toHaveLength(4); // 2 domains x 2 deliveries, not 2.
			},
		);
	});

	describe('H2: 15-min sweep runs while a weekly rescan is mid-enqueue for the same tenant', () => {
		it('the sweep does not settle/alert on the brand-new (age < 6h) cycle, and both handlers resolve', async () => {
			const { handleTenantWeeklyRescan, handleTenantCycleAlerts } = await import('../../src/tenants/scheduled-handlers');

			const registry = makeStatefulRegistry([{ id: TENANT_A, super_tenant_id: SUPER }], { [TENANT_A]: REGISTRY_ROW_A });
			const due = [
				{ domain: 'a.example.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
				{ domain: 'b.example.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
			];
			const tenant = makeRecordingD1({ 'FROM domains': due });

			// Gate the FIRST queue.send so handleTenantWeeklyRescan pauses mid-enqueue —
			// after INSERT_CYCLE_SQL has run (expected_total=2, completed=0, errored=0)
			// but before any domain has been durably queued.
			let releaseSend!: () => void;
			const sendGate = new Promise<void>((resolve) => {
				releaseSend = resolve;
			});
			const queueSends: unknown[] = [];
			let sendCalls = 0;
			const queue = {
				async send(msg: unknown) {
					sendCalls += 1;
					if (sendCalls === 1) await sendGate;
					queueSends.push(msg);
				},
			};

			const customEnv: TenantScheduledEnv = {
				...env,
				TENANT_REGISTRY_DB: registry.db,
				BV_SCANNER_QUEUE: queue,
				[TENANT_A_BINDING]: tenant.db,
			} as TenantScheduledEnv;

			const T0 = 1_700_000_000_000;
			const CYCLE_ID = 'cycle-mid-enqueue';
			const weeklyPromise = handleTenantWeeklyRescan(customEnv, makeCtx(), {
				now: () => T0,
				newCycleId: () => CYCLE_ID,
				dnsQuery: okDns,
			});

			// Wait until the cycle row is durably inserted (observable via the stateful
			// registry) but the send loop is still blocked on the gate.
			await flushUntil(() => registry.cycles.has(CYCLE_ID));
			const midCycle = registry.cycles.get(CYCLE_ID)!;
			expect(midCycle).toMatchObject({ expected_total: 2, completed_total: 0, errored_total: 0, alert_sent_at: null });

			// The 15-min sweep runs concurrently, 60s later (well under the 6h stall
			// threshold) — still mid-enqueue on the weekly rescan side.
			const sendAlertMock = vi.fn(async () => ({ delivered: true, status: 200 }));
			const alertsPromise = handleTenantCycleAlerts(customEnv, makeCtx(), { now: () => T0 + 60_000, sendAlert: sendAlertMock });
			await expect(alertsPromise).resolves.toBeUndefined();

			// The brand-new cycle must not be settled or alerted on: it's below the
			// PENDING_CYCLES_SQL threshold (0+0 < 2) and below the stalled-settle age
			// (60s << 6h), so neither the settle path nor the stamp path may touch it.
			const afterAlerts = registry.cycles.get(CYCLE_ID)!;
			expect(afterAlerts.alert_sent_at).toBeNull();
			expect(afterAlerts.alert_outcome).toBeNull();
			expect(sendAlertMock).not.toHaveBeenCalled();
			expect(registry.calls.some((c) => c.sql.includes('errored_total = expected_total - completed_total'))).toBe(false);
			expect(registry.calls.some((c) => c.sql.includes('alert_sent_at = ?, alert_outcome = ?'))).toBe(false);

			// Let the weekly rescan finish and confirm it too resolves cleanly.
			releaseSend();
			await expect(weeklyPromise).resolves.toBeUndefined();
			expect(queueSends).toHaveLength(2);
		});
	});

	describe("H3: daily-digest cron's Analytics Engine query fails (422/500)", () => {
		let originalFetch: typeof globalThis.fetch;
		let webhookCalls: Array<{ url: string; body: string }> = [];
		let aeStatus = 422;

		beforeEach(() => {
			webhookCalls = [];
			aeStatus = 422;
			originalFetch = globalThis.fetch;
			globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
				if (url.includes('/analytics_engine/sql')) {
					return new Response(JSON.stringify({ error: 'ae unavailable' }), {
						status: aeStatus,
						headers: { 'content-type': 'application/json' },
					});
				}
				if (url.startsWith('https://hooks.example.test/cron-overlap-193')) {
					webhookCalls.push({ url, body: typeof init?.body === 'string' ? init.body : '' });
					return new Response('ok', { status: 200 });
				}
				return originalFetch(input as RequestInfo, init);
			}) as typeof fetch;
		});

		afterEach(() => {
			globalThis.fetch = originalFetch;
			vi.restoreAllMocks();
		});

		it.each([422, 500])(
			'AE returns %i: handleDailyDigest resolves, logs the failure, and sends NO digest that tick (skip-with-log, not degrade-and-send)',
			async (status) => {
				aeStatus = status;
				const { handleDailyDigest } = await import('../../src/scheduled');
				const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

				await expect(
					handleDailyDigest({
						ALERT_WEBHOOK_URL: 'https://hooks.example.test/cron-overlap-193',
						CF_ACCOUNT_ID: 'acct',
						CF_ANALYTICS_TOKEN: 'token',
					}),
				).resolves.toBeUndefined();

				// No digest webhook was sent — the AE throw aborts the try block BEFORE
				// `sendAlert` is reached, so this tick emits nothing rather than a
				// partial/degraded digest. That satisfies the contract's "or skips it
				// with a log" branch.
				expect(webhookCalls).toHaveLength(0);
				const logged = logSpy.mock.calls.map((c) => String(c[0])).join('\n');
				expect(logged).toContain('Daily tier digest failed');
				expect(logged).toContain(String(status));
			},
		);
	});

	describe('H4: routeCron receives an unknown cron string', () => {
		it(
			'FALSIFIED: an unrecognized cron is NOT a distinct "unknown" route — routeCron folds it into the same ' +
				"'periodic' fallback as the legitimate 15-min sweep, so scheduled() runs the full periodic handler set " +
				'(including the tenant cycle-alerts handler), with no dedicated unknown-cron log line',
			async () => {
				const { routeCron } = await import('../../src/index');
				// Not a recognized route AND not a plausible 5-field cron at all.
				expect(routeCron('not a cron expression')).toBe('periodic');
				// Even a well-formed but otherwise-unmapped 5-field cron folds to the
				// same fallback (no distinct "unrecognized" branch exists).
				expect(routeCron('17 3 * * 2')).toBe('periodic');
			},
		);

		it(
			'FALSIFIED (integration): scheduled() with an unknown cron string still invokes handleTenantCycleAlerts ' +
				'(a tenant handler) — contradicts "resolves without running any tenant handler" — but scheduled() ' +
				'itself does resolve without throwing',
			async () => {
				const handleTenantWeeklyRescanMock = vi.fn(async (_e: unknown, _c: unknown) => undefined);
				const handleTenantCycleAlertsMock = vi.fn(async (_e: unknown, _c: unknown) => undefined);
				const handleScheduledMock = vi.fn(async (_e: unknown) => undefined);
				const handleDailyDigestMock = vi.fn(async (_e: unknown) => undefined);
				const handleFuzzingScanMock = vi.fn(async (_e: unknown) => undefined);
				const handleClientIpHeaderAuditMock = vi.fn(async (_e: unknown) => undefined);

				vi.doMock('../../src/tenants/scheduled-handlers', async () => {
					const actual = await vi.importActual<typeof import('../../src/tenants/scheduled-handlers')>(
						'../../src/tenants/scheduled-handlers',
					);
					return {
						...actual,
						handleTenantWeeklyRescan: handleTenantWeeklyRescanMock,
						handleTenantCycleAlerts: handleTenantCycleAlertsMock,
					};
				});
				vi.doMock('../../src/scheduled', async () => {
					const actual = await vi.importActual<typeof import('../../src/scheduled')>('../../src/scheduled');
					return {
						...actual,
						handleScheduled: handleScheduledMock,
						handleDailyDigest: handleDailyDigestMock,
						handleFuzzingScan: handleFuzzingScanMock,
						handleClientIpHeaderAudit: handleClientIpHeaderAuditMock,
					};
				});
				vi.resetModules();

				const worker = (await import('../../src')).default;
				const ctx = createExecutionContext();
				await expect(
					worker.scheduled!(
						{ scheduledTime: Date.now(), cron: 'garbage not a cron', type: 'scheduled' } as ScheduledEvent,
						env as unknown as Parameters<NonNullable<typeof worker.scheduled>>[1],
						ctx,
					),
				).resolves.toBeUndefined();
				await waitOnExecutionContext(ctx);

				// The periodic fallback set ran in full, including the tenant cycle
				// alerts handler — the ticket's H4 premise that NO tenant handler runs
				// for an unknown cron does not hold against the actual dispatcher.
				expect(handleScheduledMock).toHaveBeenCalledTimes(1);
				expect(handleFuzzingScanMock).toHaveBeenCalledTimes(1);
				expect(handleClientIpHeaderAuditMock).toHaveBeenCalledTimes(1);
				expect(handleTenantCycleAlertsMock).toHaveBeenCalledTimes(1);
				// The weekly-rescan branch specifically does NOT run (it's gated on the
				// dedicated Sunday-02:00 route, not the periodic fallback).
				expect(handleTenantWeeklyRescanMock).not.toHaveBeenCalled();
				expect(handleDailyDigestMock).not.toHaveBeenCalled();

				vi.doUnmock('../../src/tenants/scheduled-handlers');
				vi.doUnmock('../../src/scheduled');
				vi.resetModules();
			},
		);
	});
});
