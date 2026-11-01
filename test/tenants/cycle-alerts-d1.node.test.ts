// SPDX-License-Identifier: BUSL-1.1

import { readFileSync, readdirSync } from 'node:fs';
import { URL } from 'node:url';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { handleTenantCycleAlerts, handleTenantWeeklyRescan } from '../../src/tenants/scheduled-handlers';
import { synchronizeCycleProgress } from '../../src/tenants/cycle-progress';
import { resetTenantResolverCache, resolveTenantUncached } from '../../src/tenants/tenant-resolver';
import type { TenantCycleAlert } from '../../src/schemas/tenant-alerts';
import type { DnsQueryFn } from '../../src/tenants/dns-fingerprint';
import { emitScanCapture, makeScanDomainResult } from '../helpers/scan-capture';

// SQ-496: the weekly-rescan coverage cases drive the REAL queue consumer, so only
// the scan engine itself is replaced: it reports a fixed graded result.
const handleToolsCallMock = vi.hoisted(() => vi.fn());
vi.mock('../../src/handlers/tools', () => ({ handleToolsCall: handleToolsCallMock }));
// The consumer's import graph reaches a Durable Object class; Node has no workerd runtime module.
vi.mock('cloudflare:workers', () => ({ DurableObject: class {} }));

let runtime: Miniflare;
let registry: D1Database;
let tenant: D1Database;
const ctx = { waitUntil: (_promise: Promise<unknown>) => undefined };

async function migrate(db: D1Database, kind: 'registry' | 'tenant') {
	const directory = new URL(`../../src/tenants/db/migrations/${kind}/`, import.meta.url);
	for (const file of readdirSync(directory)
		.filter((name) => name.endsWith('.sql'))
		.sort()) {
		await db.exec(
			readFileSync(new URL(file, directory), 'utf8')
				.replace(/--[^\n]*/g, '')
				.replace(/\s+/g, ' ')
				.trim(),
		);
	}
}

function environment() {
	return { TENANT_REGISTRY_DB: registry, TENANT_DB_TENANT_1: tenant, ALERT_WEBHOOK_URL: 'https://example.com/webhook' };
}

async function cycle(id: string, startedAt: number, expected: number, baseline: string | null = 'cycle-baseline') {
	await registry
		.prepare(
			'INSERT INTO tenant_cycles (id, super_tenant_id, sub_tenant_id, started_at, expected_total, baseline_cycle_id) VALUES (?, ?, ?, ?, ?, ?)',
		)
		.bind(id, 'super-1', 'tenant-1', startedAt, expected, baseline)
		.run();
}

async function scan(
	id: string,
	domain: string,
	cycleId: string,
	at: number,
	titles: string[],
	score: number | null = 70,
	expected = titles.length,
) {
	await tenant.prepare('INSERT OR IGNORE INTO domains (domain, source, added_at) VALUES (?, ?, ?)').bind(domain, 'seed', 1).run();
	await tenant
		.prepare('INSERT INTO scans (id, domain, scan_at, score, finding_count, cycle_id) VALUES (?, ?, ?, ?, ?, ?)')
		.bind(id, domain, at, score, expected, cycleId)
		.run();
	for (const [index, title] of titles.entries()) {
		await tenant
			.prepare('INSERT INTO findings (id, scan_id, domain, category, severity, title) VALUES (?, ?, ?, ?, ?, ?)')
			.bind(`${id}-${index}`, id, domain, 'spf', 'high', title)
			.run();
	}
}

beforeEach(async () => {
	runtime = new Miniflare(
		convertV4MiniflareOptions({
			modules: true,
			script: 'export default { fetch() { return new Response("ok") } }',
			d1Databases: { REGISTRY: `registry-${crypto.randomUUID()}`, TENANT: `tenant-${crypto.randomUUID()}` },
		}),
	);
	registry = (await runtime.getD1Database('REGISTRY')) as unknown as D1Database;
	tenant = (await runtime.getD1Database('TENANT')) as unknown as D1Database;
	await migrate(registry, 'registry');
	await migrate(tenant, 'tenant');
	await registry
		.prepare('INSERT INTO super_tenants (id, name, api_key_hash, d1_binding_prefix, created_at) VALUES (?, ?, ?, ?, ?)')
		.bind('super-1', 'Synthetic super tenant', 'synthetic-key-hash', 'TENANT_DB_', 1)
		.run();
	await registry
		.prepare('INSERT INTO sub_tenants (id, super_tenant_id, name, d1_db_id, created_at) VALUES (?, ?, ?, ?, ?)')
		.bind('tenant-1', 'super-1', 'Synthetic tenant', 'synthetic-db', 1)
		.run();
});

afterEach(async () => {
	await runtime?.dispose();
});

describe('Tenant cycle lifecycle against real D1', () => {
	it('persists the full cycle before immediate completions and does not double-count replay', async () => {
		for (const domain of ['a.example.com', 'b.example.com']) {
			await tenant.prepare('INSERT INTO domains (domain, source, added_at) VALUES (?, ?, ?)').bind(domain, 'seed', 1).run();
		}
		const env = environment();
		const handle = (await resolveTenantUncached(env, 'tenant-1')).db;
		const expectedCounts: number[] = [];
		await handleTenantWeeklyRescan(
			{
				...env,
				BV_SCANNER_QUEUE: {
					send: async (message) => {
						const persisted = await registry
							.prepare('SELECT expected_total FROM tenant_cycles WHERE id = ?')
							.bind(message.cycle_id)
							.first<{ expected_total: number }>();
						expectedCounts.push(persisted?.expected_total ?? -1);
						await scan(`scan-${message.domain}`, message.domain, message.cycle_id, 1001, []);
						await synchronizeCycleProgress(registry, handle, message.cycle_id);
						await synchronizeCycleProgress(registry, handle, message.cycle_id);
					},
				},
			},
			ctx,
			{
				now: () => 1000,
				newCycleId: () => 'cycle-fast',
				dnsQuery: async () => ({ Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [], Answer: [] }),
			},
		);
		expect(expectedCounts).toEqual([2, 2]);
		expect(
			await registry.prepare('SELECT expected_total, completed_total FROM tenant_cycles WHERE id = ?').bind('cycle-fast').first(),
		).toEqual({ expected_total: 2, completed_total: 2 });
	});

	it('compares only measured domains with their latest complete pre-cycle observations', async () => {
		await cycle('cycle-current', 1000, 4);
		await scan('a-old', 'a.example.com', 'cycle-baseline', 100, ['Old finding']);
		await scan('a-latest', 'a.example.com', 'cycle-intermediate', 500, ['Current finding']);
		await scan('a-failed', 'a.example.com', 'cycle-failed', 700, ['Failure'], null);
		await scan('a-partial', 'a.example.com', 'cycle-partial', 800, ['Partial finding'], 70, 2);
		await scan('a-future', 'a.example.com', 'cycle-future', 2000, ['Future finding']);
		await scan('a-current', 'a.example.com', 'cycle-current', 1001, ['Current finding']);
		await scan('b-old', 'b.example.com', 'cycle-baseline', 100, ['Unscanned finding']);
		await scan('c-old', 'c.example.com', 'cycle-baseline', 100, ['Resolved finding']);
		await scan('c-current', 'c.example.com', 'cycle-current', 1001, []);
		await scan('d-old', 'd.example.com', 'cycle-baseline', 100, ['Unmeasured finding']);
		await scan('d-current', 'd.example.com', 'cycle-current', 1001, ['queue_dlq'], null);
		await tenant.prepare('UPDATE findings SET category = ? WHERE scan_id = ?').bind('queue', 'd-current').run();
		await scan('e-old', 'e.example.com', 'cycle-baseline', 100, ['Incomplete finding']);
		await scan('e-current', 'e.example.com', 'cycle-current', 1001, [], 70, 1);
		// Exercise the read predicates independently of progress; an already-settled
		// legacy cycle may contain an incomplete row, which must still be excluded.
		await registry.prepare('UPDATE tenant_cycles SET completed_total = 4 WHERE id = ?').bind('cycle-current').run();
		const alerts: TenantCycleAlert[] = [];
		await handleTenantCycleAlerts(environment(), ctx, {
			now: () => 3000,
			sendAlert: async (payload) => {
				alerts.push(payload);
				return { delivered: true };
			},
		});
		expect(alerts).toHaveLength(1);
		expect(alerts[0].highlights).toEqual([
			expect.objectContaining({ domain: 'c.example.com', title: 'Resolved finding', delta: 'lost' }),
			expect.objectContaining({ domain: 'd.example.com', title: 'queue_dlq', delta: 'gained' }),
		]);
	});

	it('recovers lost registry progress without counting incomplete writes or duplicating completions', async () => {
		await cycle('cycle-recover', 1000, 3, null);
		await scan('complete', 'a.example.com', 'cycle-recover', 1001, ['Measured finding']);
		await scan('dlq', 'b.example.com', 'cycle-recover', 1001, ['queue_dlq'], null);
		await scan('partial', 'c.example.com', 'cycle-recover', 1001, [], 70, 1);
		await handleTenantCycleAlerts(environment(), ctx, { now: () => 2000 });
		expect(
			await registry.prepare('SELECT completed_total, alert_sent_at FROM tenant_cycles WHERE id = ?').bind('cycle-recover').first(),
		).toEqual({ completed_total: 2, alert_sent_at: null });
		await tenant
			.prepare('INSERT INTO findings (id, scan_id, domain, category, severity, title) VALUES (?, ?, ?, ?, ?, ?)')
			.bind('repaired', 'partial', 'c.example.com', 'spf', 'high', 'Measured finding')
			.run();
		await handleTenantCycleAlerts(environment(), ctx, { now: () => 3000 });
		await handleTenantCycleAlerts(environment(), ctx, { now: () => 4000 });
		expect(
			await registry.prepare('SELECT completed_total, alert_sent_at FROM tenant_cycles WHERE id = ?').bind('cycle-recover').first(),
		).toEqual({ completed_total: 3, alert_sent_at: 3000 });
	});

	// SQ-167: the prod tenant DB lacked idx_findings_scan_id (migration 0002). The
	// per-message completion count then did a full `findings` scan per cycle scan,
	// 9.0 s / 24M rows at 240 scans, and the weekly cycle stalled at 240/500.
	it('keeps every per-scan findings access index-bounded when idx_findings_scan_id is missing', async () => {
		await tenant.exec('DROP INDEX idx_findings_scan_id');
		await cycle('cycle-current', 10_000, 2);
		await scan('a-old', 'a.example.com', 'cycle-baseline', 100, ['Old finding']);
		await scan('a-current', 'a.example.com', 'cycle-current', 10_001, ['Current finding']);
		await scan('b-current', 'b.example.com', 'cycle-current', 10_001, []);

		const statements: string[] = [];
		const recordingTenant = {
			prepare(sql: string) {
				statements.push(sql);
				return tenant.prepare(sql);
			},
		} as unknown as D1Database;
		// Built once as a variable (not an inline literal) so the extra tenant binding is
		// not rejected by TypeScript's excess-property check on ResolverEnv / TenantScheduledEnv.
		const recordingEnv = { ...environment(), TENANT_DB_TENANT_1: recordingTenant };
		await synchronizeCycleProgress(registry, (await resolveTenantUncached(recordingEnv, 'tenant-1')).db, 'cycle-current');
		await handleTenantCycleAlerts(recordingEnv, ctx, {
			now: () => 20_000,
			sendAlert: async () => ({ delivered: true }),
		});
		expect(
			await registry.prepare('SELECT completed_total, alert_outcome FROM tenant_cycles WHERE id = ?').bind('cycle-current').first(),
		).toEqual({ completed_total: 2, alert_outcome: 'sent' });

		const findingsStatements = [...new Set(statements.filter((sql) => /\bfindings\s+\w+/.test(sql)))];
		// Completion count, current-cycle findings, and baseline findings.
		expect(findingsStatements.length).toBeGreaterThanOrEqual(3);
		for (const sql of findingsStatements) {
			const aliases = [...sql.matchAll(/\bfindings\s+(?!WHERE\b)(\w+)/g)].map((m) => m[1]);
			const placeholders = (sql.match(/\?/g) ?? []).length;
			const plan = await tenant
				.prepare(`EXPLAIN QUERY PLAN ${sql}`)
				.bind(...Array<null>(placeholders).fill(null))
				.all<{ detail: string }>();
			const fullScans = plan.results.map((row) => row.detail).filter((detail) => aliases.some((alias) => detail === `SCAN ${alias}`));
			expect({ sql: sql.replace(/\s+/g, ' ').trim(), fullScans }).toEqual({ sql: sql.replace(/\s+/g, ' ').trim(), fullScans: [] });
		}
	});

	it('settles a stalled cycle as partial once and raises one operator alert', async () => {
		const operatorAlerts: string[] = [];
		vi.stubGlobal('fetch', async (_url: string, init?: RequestInit) => {
			operatorAlerts.push(String(init?.body ?? ''));
			return new Response('ok');
		});
		try {
			const startedAt = 1_000_000;
			const sixHours = 6 * 3600 * 1000;
			await cycle('cycle-stalled', startedAt, 3);
			await scan('a-old', 'a.example.com', 'cycle-baseline', 100, ['Old finding']);
			await scan('a-current', 'a.example.com', 'cycle-stalled', startedAt + 1, ['Old finding']);
			const tenantAlerts: TenantCycleAlert[] = [];
			const sweep = (now: number) =>
				handleTenantCycleAlerts(environment(), ctx, {
					now: () => now,
					sendAlert: async (payload) => {
						tenantAlerts.push(payload);
						return { delivered: true };
					},
				});
			const row = () =>
				registry
					.prepare('SELECT completed_total, errored_total, alert_sent_at, alert_outcome FROM tenant_cycles WHERE id = ?')
					.bind('cycle-stalled')
					.first();

			// Before the deadline a short cycle is only reconciled, never settled.
			await sweep(startedAt + sixHours);
			expect(await row()).toEqual({ completed_total: 1, errored_total: 0, alert_sent_at: null, alert_outcome: null });
			expect(operatorAlerts).toHaveLength(0);

			// Past the deadline the missing domains become errored and the cycle settles.
			await sweep(startedAt + sixHours + 1);
			expect(await row()).toEqual({
				completed_total: 1,
				errored_total: 2,
				alert_sent_at: startedAt + sixHours + 1,
				alert_outcome: 'no_diff',
			});
			expect(operatorAlerts).toHaveLength(1);
			expect(operatorAlerts[0]).toContain('settled partial: 2 of 3 domains never completed');
			expect(operatorAlerts[0]).toContain('cycle_id: cycle-stalled');
			expect(tenantAlerts).toHaveLength(0);

			// A settled cycle is never re-settled or re-alerted.
			await sweep(startedAt + 2 * sixHours);
			expect(operatorAlerts).toHaveLength(1);
		} finally {
			vi.unstubAllGlobals();
		}
	});

	describe('retry budget (SQ-501)', () => {
		const startedAt = 1_000_000;
		const budget = 7 * 24 * 3600 * 1000;

		function captureOperatorAlerts(): string[] {
			const bodies: string[] = [];
			vi.stubGlobal('fetch', async (_url: string, init?: RequestInit) => {
				bodies.push(String(init?.body ?? ''));
				return new Response('ok');
			});
			return bodies;
		}
		const cycleRow = (id: string) =>
			registry.prepare('SELECT alert_sent_at, alert_outcome FROM tenant_cycles WHERE id = ?').bind(id).first();

		it('abandons a cycle whose tenant stays unreconcilable past the budget, with one extra operator alert', async () => {
			const operatorAlerts = captureOperatorAlerts();
			try {
				// 'tenant-2' is registered but has no TENANT_DB_TENANT_2 binding, so every reconcile throws `Tenant not found`.
				await registry
					.prepare('INSERT INTO sub_tenants (id, super_tenant_id, name, d1_db_id, created_at) VALUES (?, ?, ?, ?, ?)')
					.bind('tenant-2', 'super-1', 'Unbound tenant', 'unbound-db', 1)
					.run();
				await registry
					.prepare('INSERT INTO tenant_cycles (id, super_tenant_id, sub_tenant_id, started_at, expected_total) VALUES (?, ?, ?, ?, ?)')
					.bind('cycle-unbound', 'super-1', 'tenant-2', startedAt, 3)
					.run();
				const sweep = (now: number) => handleTenantCycleAlerts(environment(), ctx, { now: () => now });

				// Exactly at the budget it is still retryable: escalated once, not abandoned.
				await sweep(startedAt + budget);
				expect(await cycleRow('cycle-unbound')).toEqual({ alert_sent_at: null, alert_outcome: 'unreconcilable' });
				expect(operatorAlerts).toHaveLength(1);
				expect(operatorAlerts[0]).toContain('unreconcilable');

				// One tick past the budget it is stamped terminal and raises exactly one more alert.
				await sweep(startedAt + budget + 1);
				expect(await cycleRow('cycle-unbound')).toEqual({ alert_sent_at: startedAt + budget + 1, alert_outcome: 'abandoned_retry_budget' });
				expect(operatorAlerts).toHaveLength(2);
				expect(operatorAlerts[1]).toContain('abandoned after retry budget');
				expect(operatorAlerts[1]).toContain('cycle_id: cycle-unbound');

				// It has left the reconcile loop: no further reads, no further alerts.
				await sweep(startedAt + budget + 2);
				expect(operatorAlerts).toHaveLength(2);
			} finally {
				vi.unstubAllGlobals();
			}
		});

		it('abandons a settled cycle whose findings read keeps failing past the budget, and never earlier', async () => {
			const operatorAlerts = captureOperatorAlerts();
			try {
				await cycle('cycle-pending', startedAt, 1);
				await registry.prepare('UPDATE tenant_cycles SET completed_total = 1 WHERE id = ?').bind('cycle-pending').run();
				const failingTenant = new Proxy(tenant, {
					get(target, prop) {
						if (prop === 'prepare') {
							return (sql: string) => {
								if (/\bFROM findings\b/i.test(sql)) throw new Error('simulated tenant D1 read failure');
								return target.prepare(sql);
							};
						}
						const value = Reflect.get(target, prop, target);
						return typeof value === 'function' ? value.bind(target) : value;
					},
				});
				const env = { ...environment(), TENANT_DB_TENANT_1: failingTenant };
				const sweep = (now: number) => handleTenantCycleAlerts(env, ctx, { now: () => now, sendAlert: async () => ({ delivered: true }) });

				// Within the budget the cycle stays retryable and silent.
				await sweep(startedAt + budget);
				expect(await cycleRow('cycle-pending')).toEqual({ alert_sent_at: null, alert_outcome: null });
				expect(operatorAlerts).toHaveLength(0);

				// Past the budget it is abandoned once.
				await sweep(startedAt + budget + 1);
				expect(await cycleRow('cycle-pending')).toEqual({ alert_sent_at: startedAt + budget + 1, alert_outcome: 'abandoned_retry_budget' });
				expect(operatorAlerts).toHaveLength(1);
				expect(operatorAlerts[0]).toContain('cycle_id: cycle-pending');

				await sweep(startedAt + budget + 2);
				expect(operatorAlerts).toHaveLength(1);
			} finally {
				vi.unstubAllGlobals();
			}
		});
	});
});

describe('Tenant weekly rescan coverage against real D1 (SQ-496)', () => {
	const WEEK_MS = 168 * 3600 * 1000;
	const DAY_MS = 24 * 3600 * 1000;

	/** Every DNS lookup answers one SPF TXT record, so the fingerprint follows `spf`. */
	function dns(spf: string): DnsQueryFn {
		return async (domain) => ({
			Status: 0,
			TC: false,
			RD: true,
			RA: true,
			AD: false,
			CD: false,
			Question: [],
			Answer: [{ name: domain, type: 16, TTL: 300, data: `"${spf}"` }],
		});
	}

	async function seedDomains(domains: string[]) {
		await tenant.batch(
			domains.map((domain) => tenant.prepare('INSERT INTO domains (domain, source, added_at) VALUES (?, ?, ?)').bind(domain, 'seed', 1)),
		);
	}

	/**
	 * One cron tick at `now`. Every enqueued message is consumed immediately by the
	 * real `processScanMessage`, which persists the scan and stamps the domain row.
	 * The consumer's clock is injected as `now + stampLagMs`, so a scan "finishes"
	 * `stampLagMs` after its dispatch tick without racing `Date.now()`.
	 * Returns the enqueued domains.
	 */
	async function weeklyTick(now: number, dnsQuery: DnsQueryFn, stampLagMs = 0): Promise<string[]> {
		const { processScanMessage } = await import('../../src/tenants/queue-consumer');
		const env = environment();
		const enqueued: string[] = [];
		await handleTenantWeeklyRescan(
			{
				...env,
				BV_SCANNER_QUEUE: {
					send: async (message) => {
						enqueued.push(message.domain);
						expect(await processScanMessage(message, 1, env as never, { ...ctx, now: () => now + stampLagMs })).toBe('ack');
					},
				},
			},
			ctx,
			{ now: () => now, newCycleId: () => `cycle-${now}`, dnsQuery },
		);
		return enqueued;
	}

	beforeEach(() => {
		resetTenantResolverCache();
		handleToolsCallMock.mockReset();
		handleToolsCallMock.mockImplementation(async (call: { arguments: { domain: string } }, _kv: unknown, runtimeOptions: unknown) => {
			emitScanCapture(runtimeOptions as never, call.arguments.domain, { score: 81, grade: 'B+' });
			return { isError: false, content: [{ type: 'text', text: 'ok' }] };
		});
	});

	it('scans all 600 watched domains over two weekly ticks; the second tick picks the 100 the first left', async () => {
		const domains = Array.from({ length: 600 }, (_, i) => `d${String(i).padStart(3, '0')}.example.com`);
		await seedDomains(domains);
		const tick1 = Date.now();

		const first = await weeklyTick(tick1, dns('v=spf1 -all'));
		expect(first).toHaveLength(500);
		const stamped = await tenant
			.prepare('SELECT COUNT(*) AS n FROM domains WHERE last_scanned_at IS NOT NULL AND last_score = 81 AND last_grade = ?')
			.bind('B+')
			.first<{ n: number }>();
		expect(stamped?.n).toBe(500);

		const second = await weeklyTick(tick1 + WEEK_MS, dns('v=spf1 -all'));
		expect(second).toHaveLength(100);
		expect(second.filter((domain) => first.includes(domain))).toEqual([]);
		expect(new Set([...first, ...second]).size).toBe(600);
	}, 120_000);

	it('does not re-enqueue a domain scanned yesterday, nor one past its interval whose fingerprint is unchanged', async () => {
		await seedDomains(['steady.example.com']);
		const tick1 = Date.now();
		expect(await weeklyTick(tick1, dns('v=spf1 -all'))).toEqual(['steady.example.com']);

		// Scanned yesterday, unchanged DNS: not due, not re-enqueued.
		expect(await weeklyTick(tick1 + DAY_MS, dns('v=spf1 -all'))).toEqual([]);
		// One week on, inside 2x its interval and unchanged: the fingerprint skip holds it back.
		expect(await weeklyTick(tick1 + WEEK_MS, dns('v=spf1 -all'))).toEqual([]);
		// Positive control at the same point: a DNS change is enqueued. So the domain was due
		// a week on (the due grace), and the skip above came from the fingerprint, not the due query.
		expect(await weeklyTick(tick1 + WEEK_MS + 1, dns('v=spf1 ~all'))).toEqual(['steady.example.com']);
	}, 60_000);

	// The due grace (DUE_GRACE_MS, 6h) lets a scan that finished shortly after its dispatch tick
	// still count as belonging to that tick. The edge is `last_scanned_at + interval < tick + 6h`.
	// Both clocks are injected, so these are exact, not racing `Date.now()`.
	describe('due-grace boundary with an explicit stamp lag', () => {
		const T0 = 1_800_000_000_000;
		const HOUR_MS = 3600 * 1000;
		const MINUTE_MS = 60 * 1000;

		it.each([
			['5h59m', 5 * HOUR_MS + 59 * MINUTE_MS, ['lag.example.com']],
			['6h01m', 6 * HOUR_MS + MINUTE_MS, []],
		])('a scan stamped %s after its dispatch tick is due at the next weekly tick only when inside the grace', async (_label, lag, expected) => {
			await seedDomains(['lag.example.com']);
			expect(await weeklyTick(T0, dns('v=spf1 -all'), lag)).toEqual(['lag.example.com']);
			// Changed DNS would enqueue the domain if the due query returns it, so an empty
			// result below can only come from the due query excluding it.
			expect(await weeklyTick(T0 + WEEK_MS, dns('v=spf1 ~all'))).toEqual(expected);
		}, 60_000);

		it('rescans a domain past 2x its interval even though its fingerprint is unchanged (stale branch)', async () => {
			await seedDomains(['stale.example.com']);
			expect(await weeklyTick(T0, dns('v=spf1 -all'))).toEqual(['stale.example.com']);
			// Inside the stale window (2x interval, less the 6h grace): due, unchanged DNS, skipped.
			expect(await weeklyTick(T0 + 2 * WEEK_MS - 6 * HOUR_MS, dns('v=spf1 -all'))).toEqual([]);
			// Past 2x the interval: forced rescan, with the SAME fingerprint as the skip above.
			expect(await weeklyTick(T0 + 2 * WEEK_MS, dns('v=spf1 -all'))).toEqual(['stale.example.com']);
		}, 60_000);
	});

	describe('ungraded scans and missed stamps', () => {
		const T0 = 1_800_000_000_000;

		async function domainRow(domain: string) {
			return tenant
				.prepare('SELECT last_scanned_at, last_score, last_grade FROM domains WHERE domain = ?')
				.bind(domain)
				.first<{ last_scanned_at: number | null; last_score: number | null; last_grade: string | null }>();
		}

		function mockUngradedScan() {
			handleToolsCallMock.mockReset();
			handleToolsCallMock.mockImplementation(async (call: { arguments: { domain: string } }, _kv: unknown, runtimeOptions: unknown) => {
				const ungraded = makeScanDomainResult(call.arguments.domain);
				(runtimeOptions as { scanResultCapture: (r: unknown) => void }).scanResultCapture({
					...ungraded,
					score: { ...ungraded.score, overall: null, grade: null },
				});
				return { isError: false, content: [{ type: 'text', text: 'ok' }] };
			});
		}

		it('an ungraded scan does not advance last_scanned_at: the domain keeps its prior stamp and stays due next tick', async () => {
			await seedDomains(['dead.example.com']);
			await tenant
				.prepare('UPDATE domains SET last_scanned_at = ?, last_score = 70, last_grade = ? WHERE domain = ?')
				.bind(T0 - 10 * 24 * 3600 * 1000, 'C', 'dead.example.com')
				.run();
			mockUngradedScan();

			// Due (stamped 10 days ago on a 7-day interval) and DNS changed, so it is dispatched and scanned ungraded.
			expect(await weeklyTick(T0, dns('v=spf1 -all'))).toEqual(['dead.example.com']);
			// The scan row is durable, with a null score ...
			expect(
				await tenant.prepare('SELECT score, grade FROM scans WHERE domain = ?').bind('dead.example.com').first(),
			).toEqual({ score: null, grade: null });
			// ... but the stamp, score and grade are untouched.
			expect(await domainRow('dead.example.com')).toEqual({ last_scanned_at: T0 - 10 * 24 * 3600 * 1000, last_score: 70, last_grade: 'C' });
			// So it is still due at the next tick (past the 6h dispatch dedup window), and a changed fingerprint dispatches it again.
			expect(await weeklyTick(T0 + 7 * 3600 * 1000, dns('v=spf1 ~all'))).toEqual(['dead.example.com']);
		}, 60_000);

		it('a never-scanned domain whose first scan is ungraded stays unstamped (NULL), not stamped with a fabricated grade', async () => {
			await seedDomains(['never.example.com']);
			mockUngradedScan();
			expect(await weeklyTick(T0, dns('v=spf1 -all'))).toEqual(['never.example.com']);
			expect(await domainRow('never.example.com')).toEqual({ last_scanned_at: null, last_score: null, last_grade: null });
		}, 60_000);

		it('re-stamps from the persisted scan when the stamp UPDATE failed, idempotently, without a second scan row', async () => {
			await seedDomains(['restamp.example.com']);
			await cycle('cycle-restamp', T0, 1);
			let failNextStamp = true;
			const flakyTenant = new Proxy(tenant, {
				get(target, prop) {
					if (prop === 'prepare') {
						return (sql: string) => {
							if (failNextStamp && sql.startsWith('UPDATE domains SET last_scanned_at')) {
								failNextStamp = false;
								throw new Error('simulated stamp failure');
							}
							return target.prepare(sql);
						};
					}
					const value = Reflect.get(target, prop, target);
					return typeof value === 'function' ? value.bind(target) : value;
				},
			});
			const env = { ...environment(), TENANT_DB_TENANT_1: flakyTenant };
			const { processScanMessage } = await import('../../src/tenants/queue-consumer');
			const message = { cycle_id: 'cycle-restamp', sub_tenant_id: 'tenant-1', domain: 'restamp.example.com' };
			const consume = (at: number) => processScanMessage(message, 1, env as never, { ...ctx, now: () => at });

			// First delivery persists the scan, but the stamp is lost.
			expect(await consume(T0 + 1000)).toBe('ack');
			expect(failNextStamp).toBe(false);
			expect(await domainRow('restamp.example.com')).toEqual({ last_scanned_at: null, last_score: null, last_grade: null });

			// Redelivery takes the 'complete' path and re-stamps from the persisted scan_at (not the redelivery clock).
			expect(await consume(T0 + 99_000)).toBe('ack');
			expect(await domainRow('restamp.example.com')).toEqual({ last_scanned_at: T0 + 1000, last_score: 81, last_grade: 'B+' });

			// A further redelivery is a no-op: same stamp, still one scan row.
			expect(await consume(T0 + 199_000)).toBe('ack');
			expect(await domainRow('restamp.example.com')).toEqual({ last_scanned_at: T0 + 1000, last_score: 81, last_grade: 'B+' });
			expect(
				await tenant.prepare('SELECT COUNT(*) AS n FROM scans WHERE domain = ?').bind('restamp.example.com').first<{ n: number }>(),
			).toEqual({ n: 1 });
		}, 60_000);
	});
});
