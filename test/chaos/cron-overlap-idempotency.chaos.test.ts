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
		afterEach(() => {
			vi.restoreAllMocks();
		});

		/**
		 * Registry for H1: the `makeRecordingD1` fixtures plus an in-memory
		 * `tenant_cycles` that honours INSERT_CYCLE_SQL's double-fire guard ONLY
		 * when the statement carries it (the `WHERE NOT EXISTS` probe, evaluated
		 * from the statement's own guard binds). Dropping the guard from the
		 * production SQL therefore shows up here as a second cycle row and a second
		 * round of sends, not as a mock error.
		 */
		function makeGuardedCycleRegistry() {
			const recording = makeRecordingD1({
				'FROM sub_tenants WHERE active = 1': [{ id: TENANT_A, super_tenant_id: SUPER }],
				'd1_db_id, routing_mode, active FROM sub_tenants': [REGISTRY_ROW_A],
			});
			const cycles: Array<{ id: string; sub_tenant_id: string; started_at: number }> = [];
			const startedAfter = (subTenantId: string, after: number) =>
				cycles.filter((c) => c.sub_tenant_id === subTenantId && c.started_at > after).sort((a, b) => b.started_at - a.started_at);
			const db = {
				...(recording.db as unknown as Record<string, unknown>),
				prepare(sql: string) {
					const insert = sql.includes('INSERT INTO tenant_cycles');
					const recent = sql.includes('SELECT id FROM tenant_cycles WHERE sub_tenant_id = ? AND started_at > ?');
					if (!insert && !recent) return recording.db.prepare(sql);
					let binds: unknown[] = [];
					const stmt = {
						bind(...args: unknown[]) {
							binds = args;
							return stmt;
						},
						async run() {
							recording.calls.push({ sql, binds });
							const [id, , subTenantId, startedAt] = binds as [string, string, string, number];
							const [guardTenant, guardAfter] = binds.slice(7) as [string, number];
							if (sql.includes('WHERE NOT EXISTS') && startedAfter(guardTenant, guardAfter).length > 0) {
								return { success: true, meta: { changes: 0 } } as unknown as D1Response;
							}
							cycles.push({ id, sub_tenant_id: subTenantId, started_at: startedAt });
							return { success: true, meta: { changes: 1 } } as unknown as D1Response;
						},
						async first<T = unknown>(): Promise<T | null> {
							recording.calls.push({ sql, binds });
							const [newest] = startedAfter(binds[0] as string, binds[1] as number);
							return (newest ? { id: newest.id } : null) as T | null;
						},
					};
					return stmt as unknown as D1PreparedStatement;
				},
			};
			return { db: db as unknown as D1Database, calls: recording.calls, cycles };
		}

		it(
			'two scheduled() deliveries of the same tick create exactly ONE tenant_cycles row and enqueue each due domain once: ' +
				'the guarded insert refuses the second and logs tenant_weekly_rescan_skipped_duplicate with the existing cycle id',
			async () => {
				const { handleTenantWeeklyRescan } = await import('../../src/tenants/scheduled-handlers');

				const due = [
					{ domain: 'a.example.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
					{ domain: 'b.example.com', last_scanned_at: null, watch_interval_hours: 168, fingerprint: null },
				];
				// Same tenant-db state is read by BOTH calls — matching the real hazard:
				// `last_scanned_at` only advances once a scan COMPLETES (via the queue
				// consumer, elsewhere), never during dispatch itself, so a
				// double-delivered tick sees the identical "due" set both times.
				const registry = makeGuardedCycleRegistry();
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
				const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

				const T0 = 9_999_999_999_999;
				let cycleCounter = 0;
				const newCycleId = () => `cycle-${(cycleCounter += 1)}`;

				// Two independent scheduled() deliveries, same scheduledTime, run
				// sequentially (Cloudflare would run them as separate isolate
				// invocations, not concurrently within one) — that's exactly what
				// "fires twice" means operationally.
				await expect(handleTenantWeeklyRescan(customEnv, makeCtx(), { now: () => T0, newCycleId, dnsQuery: okDns })).resolves.toBeUndefined();
				await expect(handleTenantWeeklyRescan(customEnv, makeCtx(), { now: () => T0, newCycleId, dnsQuery: okDns })).resolves.toBeUndefined();

				// Race control: BOTH deliveries reached the cycle insert with the full due set...
				const cycleInserts = registry.calls.filter((c) => c.sql.includes('INSERT INTO tenant_cycles'));
				expect(cycleInserts).toHaveLength(2);
				// ...scoped to this tenant and anchored on the tick time (the 6h dispatch window).
				expect(cycleInserts[1].binds.slice(7)).toEqual([TENANT_A, T0 - 6 * 3600 * 1000]);
				// ...but the guard admitted only the first: one cycle row, one send per due domain.
				expect(registry.cycles.map((c) => c.id)).toEqual(['cycle-1']);
				expect(queueSends).toHaveLength(due.length);
				expect(queueSends).toEqual(due.map((row) => ({ cycle_id: 'cycle-1', sub_tenant_id: TENANT_A, domain: row.domain })));
				const skipped = logSpy.mock.calls
					.map((call) => {
						try {
							return JSON.parse(String(call[0])) as { details?: Record<string, unknown> };
						} catch {
							return null;
						}
					})
					.filter((line) => line?.details?.message === 'tenant_weekly_rescan_skipped_duplicate');
				// (subTenantId is present but redacted by the logger's tenantId key rule.)
				expect(skipped).toEqual([expect.objectContaining({ details: expect.objectContaining({ existingCycleId: 'cycle-1' }) })]);
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
			'FIXED (SQ-198): an unrecognized cron is a distinct "unknown" route, never the "periodic" fallback used ' +
				'by the legitimate 15-min sweep',
			async () => {
				const { routeCron } = await import('../../src/index');
				// Not a recognized route AND not a plausible 5-field cron at all.
				expect(routeCron('not a cron expression')).toBe('unknown');
				// Even a well-formed but otherwise-unmapped 5-field cron routes to
				// 'unknown', not the periodic fallback.
				expect(routeCron('17 3 * * 2')).toBe('unknown');
				// Negative control on the fallback itself: the actual periodic cron
				// still routes to 'periodic', so 'unknown' is a genuinely separate
				// branch rather than routeCron always returning 'unknown' now.
				expect(routeCron('*/15 * * * *')).toBe('periodic');
			},
		);

		it(
			'FIXED (SQ-198): scheduled() with an unknown cron string invokes NO handler (tenant or periodic), logs a ' +
				"single structured warn ('cron'/'unknown_cron') carrying the cron string, and resolves without throwing",
			async () => {
				const handleTenantWeeklyRescanMock = vi.fn(async (_e: unknown, _c: unknown) => undefined);
				const handleTenantCycleAlertsMock = vi.fn(async (_e: unknown, _c: unknown) => undefined);
				const handleScheduledMock = vi.fn(async (_e: unknown) => undefined);
				const handleDailyDigestMock = vi.fn(async (_e: unknown) => undefined);
				const handleFuzzingScanMock = vi.fn(async (_e: unknown) => undefined);
				const handleClientIpHeaderAuditMock = vi.fn(async (_e: unknown) => undefined);
				const handleBrandAuditWatchesMock = vi.fn(async (_e: unknown, _c: unknown) => undefined);

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
						handleBrandAuditWatches: handleBrandAuditWatchesMock,
					};
				});
				vi.resetModules();

				const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

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

				// No handler — tenant or periodic — ran for the unrecognized cron.
				expect(handleScheduledMock).not.toHaveBeenCalled();
				expect(handleFuzzingScanMock).not.toHaveBeenCalled();
				expect(handleClientIpHeaderAuditMock).not.toHaveBeenCalled();
				expect(handleTenantCycleAlertsMock).not.toHaveBeenCalled();
				expect(handleBrandAuditWatchesMock).not.toHaveBeenCalled();
				expect(handleTenantWeeklyRescanMock).not.toHaveBeenCalled();
				expect(handleDailyDigestMock).not.toHaveBeenCalled();

				// A single structured warn was logged, carrying the offending cron string.
				const unknownCronLogs = logSpy.mock.calls
					.map((c) => String(c[0]))
					.filter((line) => line.includes('"result":"unknown_cron"'));
				expect(unknownCronLogs).toHaveLength(1);
				expect(unknownCronLogs[0]).toContain('"category":"cron"');
				expect(unknownCronLogs[0]).toContain('"severity":"warn"');
				expect(unknownCronLogs[0]).toContain('garbage not a cron');

				vi.doUnmock('../../src/tenants/scheduled-handlers');
				vi.doUnmock('../../src/scheduled');
				vi.resetModules();
			},
		);
	});
});
