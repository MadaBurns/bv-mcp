// SPDX-License-Identifier: BUSL-1.1

import { readFileSync, readdirSync } from 'node:fs';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { handleTenantCycleAlerts, handleTenantWeeklyRescan } from '../../src/tenants/scheduled-handlers';
import { synchronizeCycleProgress } from '../../src/tenants/cycle-progress';
import { resolveTenantUncached } from '../../src/tenants/tenant-resolver';
import type { TenantCycleAlert } from '../../src/schemas/tenant-alerts';

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
		await handleTenantCycleAlerts(environment(), ctx);
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
});
