// SPDX-License-Identifier: BUSL-1.1
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import worker from '../../src';
import { resetTenantResolverCache } from '../../src/tenants/tenant-resolver';

const TEST_INTERNAL_KEY = 'tenant-orchestrator-internal-key';

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	REQUIRE_INTERNAL_AUTH?: string;
	TENANT_REGISTRY_DB?: D1Database;
	[k: string]: unknown;
};

/** 
 * Mock D1 that records calls and can simulate latency/contention.
 */
function makeHammerMockD1(name: string) {
	const calls: Array<{ db: string; sql: string; binds: unknown[] }> = [];
	const db: D1Database = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first<T = unknown>(): Promise<T | null> {
					calls.push({ db: name, sql, binds });
					// Simulate slight D1 latency (5-10ms)
					await new Promise(r => setTimeout(r, 5 + Math.random() * 5));
					if (sql.includes('sub_tenants')) {
						return { id: name.replace('TENANT_DB_', '').toLowerCase(), active: 1, d1_db_id: 'fake-id' } as unknown as T;
					}
					return null;
				},
				async all<T = unknown>() {
					calls.push({ db: name, sql, binds });
					await new Promise(r => setTimeout(r, 5 + Math.random() * 5));
					return { results: [], success: true, meta: {} } as unknown as D1Result<T>;
				},
				async run() {
					calls.push({ db: name, sql, binds });
					await new Promise(r => setTimeout(r, 5 + Math.random() * 5));
					return { success: true, meta: {} } as unknown as D1Response;
				},
			};
			return stmt as unknown as D1PreparedStatement;
		},
	} as unknown as D1Database;
	return { db, calls };
}

describe('Multi-Tenant Hammer — Orchestrator Stress Test', () => {
	beforeEach(() => {
		resetTenantResolverCache();
		vi.restoreAllMocks();
	});

	it('should handle concurrent requests from multiple tenants without cross-contamination', async () => {
		const e = env as TestEnv;
		e.BV_WEB_INTERNAL_KEY = TEST_INTERNAL_KEY;
		e.REQUIRE_INTERNAL_AUTH = 'true';

		const registry = makeHammerMockD1('REGISTRY');
		e.TENANT_REGISTRY_DB = registry.db;

		// Setup 5 mock tenants
		const tenants = ['tenant-a', 'tenant-b', 'tenant-c', 'tenant-d', 'tenant-e'];
		const tenantMocks: Record<string, ReturnType<typeof makeHammerMockD1>> = {};
		
		for (const id of tenants) {
			const binding = `TENANT_DB_${id.toUpperCase().replace('-', '_')}`;
			tenantMocks[id] = makeHammerMockD1(binding);
			e[binding] = tenantMocks[id].db;
		}

		// Fire 10 concurrent requests (2 per tenant)
		const requests = tenants.flatMap(id => [
			new Request(`https://api.blackveil.local/internal/tenants/portfolio`, {
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${TEST_INTERNAL_KEY}`,
					'X-Tenant': id,
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ domains: [`${id}-1.com`, `${id}-2.com`] }),
			}),
			new Request(`https://api.blackveil.local/internal/tenants/scan`, {
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${TEST_INTERNAL_KEY}`,
					'X-Tenant': id,
					'Content-Type': 'application/json',
				},
				body: JSON.stringify({ domains: [`${id}-scan.com`], force_refresh: true }),
			})
		]);

		const ctxs = requests.map(() => createExecutionContext());
		const results = await Promise.all(requests.map((req, i) => worker.fetch(req, e, ctxs[i])));
		
		// Wait for all audit events (ctx.waitUntil)
		await Promise.all(ctxs.map(ctx => waitOnExecutionContext(ctx)));

		// Verify all returned 200
		for (const res of results) {
			expect(res.status).toBe(200);
		}

		// Verify no cross-contamination in DB calls
		for (const id of tenants) {
			const mock = tenantMocks[id];
			const binding = `TENANT_DB_${id.toUpperCase().replace('-', '_')}`;
			
			// All calls in this mock should only ever refer to this tenant's domains
			for (const call of mock.calls) {
				expect(call.db).toBe(binding);
				const bindsStr = JSON.stringify(call.binds);
				if (bindsStr.includes('.com')) {
					expect(bindsStr).toContain(id);
				}
			}
		}

		// Verify audit registry received events for all tenants
		const auditCalls = registry.calls.filter(c => c.sql.includes('audit_events'));
		expect(auditCalls.length).toBe(requests.length);
		
		const auditBinds = auditCalls.map(c => JSON.stringify(c.binds));
		for (const id of tenants) {
			expect(auditBinds.some(b => b.includes(id))).toBe(true);
		}
	});
});
