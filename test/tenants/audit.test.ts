import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { recordAuditEvent } from '../../src/tenants/audit';

/**
 * Unit tests for the fail-soft `recordAuditEvent()` helper
 * (Phase 6 cross-tenant audit log foundation).
 *
 * Behaviour invariants under test:
 *  - happy path inserts a single row with all required + supplied optional fields
 *  - blob is JSON-stringified and persisted
 *  - blob >4 KB is truncated
 *  - sensitive keys (api_key, password, etc.) are redacted before persist
 *  - control characters in blob string values are stripped
 *  - invalid event (Zod failure) is swallowed — does not throw
 *  - D1 throw is swallowed — does not throw
 *  - timestamp = Date.now() at write time
 *  - id = a UUIDv4 from crypto.randomUUID()
 *  - waitUntil dispatches the work when an ExecutionContext is supplied
 */

type InsertCall = {
	table: unknown;
	values: Record<string, unknown> | Array<Record<string, unknown>>;
};

function makeFakeDb(opts?: { throwOnInsert?: boolean }) {
	const calls: InsertCall[] = [];
	const db = {
		insert(table: unknown) {
			return {
				values: async (v: Record<string, unknown>) => {
					calls.push({ table, values: v });
					if (opts?.throwOnInsert) {
						throw new Error('D1_ERROR: simulated insert failure');
					}
					return { success: true };
				},
			};
		},
	};
	return { db: db as never, calls };
}

const minimalEvent = {
	actorPrincipal: 'k_abc123',
	actorTier: 'developer' as const,
	action: 'portfolio.upsert',
	resourceType: 'domain',
	outcome: 'success' as const,
};

describe('recordAuditEvent — happy path', () => {
	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date('2026-01-01T00:00:00Z'));
	});
	afterEach(() => {
		vi.useRealTimers();
		vi.restoreAllMocks();
	});

	it('inserts one row with the required fields', async () => {
		const { db, calls } = makeFakeDb();
		await recordAuditEvent(db, minimalEvent);

		expect(calls.length).toBe(1);
		const row = calls[0].values as Record<string, unknown>;
		expect(row.actor_principal).toBe('k_abc123');
		expect(row.actor_tier).toBe('developer');
		expect(row.action).toBe('portfolio.upsert');
		expect(row.resource_type).toBe('domain');
		expect(row.outcome).toBe('success');
	});

	it('sets timestamp to Date.now()', async () => {
		const { db, calls } = makeFakeDb();
		const expected = Date.now();
		await recordAuditEvent(db, minimalEvent);
		const row = calls[0].values as Record<string, unknown>;
		expect(row.timestamp).toBe(expected);
	});

	it('sets id to a UUIDv4 string', async () => {
		const { db, calls } = makeFakeDb();
		await recordAuditEvent(db, minimalEvent);
		const row = calls[0].values as Record<string, unknown>;
		expect(typeof row.id).toBe('string');
		// rough UUIDv4 shape
		expect(row.id as string).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
	});

	it('persists optional super_tenant_id, sub_tenant_id, request_id, cf_ray, ip_hash, resource_id', async () => {
		const { db, calls } = makeFakeDb();
		await recordAuditEvent(db, {
			...minimalEvent,
			superTenantId: 'st_1',
			subTenantId: 'sb_1',
			resourceId: 'res_1',
			requestId: 'r_abc',
			cfRay: '12345-DFW',
			ipHash: 'i_deadbeef',
		});
		const row = calls[0].values as Record<string, unknown>;
		expect(row.super_tenant_id).toBe('st_1');
		expect(row.sub_tenant_id).toBe('sb_1');
		expect(row.resource_id).toBe('res_1');
		expect(row.request_id).toBe('r_abc');
		expect(row.cf_ray).toBe('12345-DFW');
		expect(row.ip_hash).toBe('i_deadbeef');
	});

	it('omits optional fields when not provided (null/undefined in row)', async () => {
		const { db, calls } = makeFakeDb();
		await recordAuditEvent(db, minimalEvent);
		const row = calls[0].values as Record<string, unknown>;
		// blob unset → null/undefined
		expect(row.blob == null).toBe(true);
		expect(row.super_tenant_id == null).toBe(true);
	});
});

describe('recordAuditEvent — blob handling', () => {
	it('JSON-stringifies the blob', async () => {
		const { db, calls } = makeFakeDb();
		await recordAuditEvent(db, { ...minimalEvent, blob: { domain: 'example.com', count: 3 } });
		const row = calls[0].values as Record<string, unknown>;
		expect(typeof row.blob).toBe('string');
		const parsed = JSON.parse(row.blob as string);
		expect(parsed.domain).toBe('example.com');
		expect(parsed.count).toBe(3);
	});

	it('truncates blob >4 KB', async () => {
		const { db, calls } = makeFakeDb();
		const big = 'x'.repeat(10_000);
		await recordAuditEvent(db, { ...minimalEvent, blob: { huge: big } });
		const row = calls[0].values as Record<string, unknown>;
		expect((row.blob as string).length).toBeLessThanOrEqual(4096);
	});

	it('redacts sensitive keys (api_key, password, authorization, secret, token)', async () => {
		const { db, calls } = makeFakeDb();
		await recordAuditEvent(db, {
			...minimalEvent,
			blob: {
				api_key: 'sk_live_abcdef',
				password: 'hunter2',
				authorization: 'Bearer xyz',
				secret: 'shhh',
				token: 't_123',
				safe: 'visible',
			},
		});
		const row = calls[0].values as Record<string, unknown>;
		const parsed = JSON.parse(row.blob as string);
		expect(parsed.api_key).not.toBe('sk_live_abcdef');
		expect(parsed.password).not.toBe('hunter2');
		expect(parsed.authorization).not.toBe('Bearer xyz');
		expect(parsed.secret).not.toBe('shhh');
		expect(parsed.token).not.toBe('t_123');
		expect(parsed.safe).toBe('visible');
	});

	it('strips control characters from blob string values', async () => {
		const { db, calls } = makeFakeDb();
		await recordAuditEvent(db, {
			...minimalEvent,
			blob: { note: 'line1\nline2\tinjected\x07bell' },
		});
		const row = calls[0].values as Record<string, unknown>;
		const parsed = JSON.parse(row.blob as string);
		expect(parsed.note).not.toContain('\n');
		expect(parsed.note).not.toContain('\x07');
	});
});

describe('recordAuditEvent — fail-soft', () => {
	it('does not throw when actorTier is invalid (Zod rejection)', async () => {
		const { db, calls } = makeFakeDb();
		const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

		await expect(
			recordAuditEvent(db, { ...minimalEvent, actorTier: 'admin' as never }),
		).resolves.toBeUndefined();

		expect(calls.length).toBe(0);
		expect(warn).toHaveBeenCalled();
		warn.mockRestore();
	});

	it('does not throw when D1 insert throws', async () => {
		const { db } = makeFakeDb({ throwOnInsert: true });
		const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

		await expect(recordAuditEvent(db, minimalEvent)).resolves.toBeUndefined();
		expect(warn).toHaveBeenCalled();
		warn.mockRestore();
	});
});

describe('recordAuditEvent — ExecutionContext', () => {
	it('dispatches via ctx.waitUntil when ctx is provided', async () => {
		const { db, calls } = makeFakeDb();
		const promises: Promise<unknown>[] = [];
		const ctx = {
			waitUntil(p: Promise<unknown>) {
				promises.push(p);
			},
			passThroughOnException() {},
		} as unknown as ExecutionContext;

		const ret = recordAuditEvent(db, minimalEvent, ctx);
		// returns immediately
		expect(ret).toBeInstanceOf(Promise);
		await ret;
		expect(promises.length).toBe(1);
		await Promise.all(promises);
		expect(calls.length).toBe(1);
	});
});
