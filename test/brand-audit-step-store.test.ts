// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

interface D1Call {
	sql: string;
	binds: unknown[];
}

function makeMockD1(rows: Map<string, { audit_id: string; target: string; step: string; status: string; payload_json: string | null; error: string | null; updated_at: number }>) {
	const calls: D1Call[] = [];
	const key = (auditId: unknown, target: unknown, step: unknown) => `${String(auditId)}\0${String(target)}\0${String(step)}`;
	const db = {
		prepare(sql: string) {
			let binds: unknown[] = [];
			const stmt = {
				bind(...args: unknown[]) {
					binds = args;
					return stmt;
				},
				async first() {
					calls.push({ sql, binds });
					if (sql.includes('FROM brand_audit_steps')) {
						return rows.get(key(binds[0], binds[1], binds[2])) ?? null;
					}
					return null;
				},
				async run() {
					calls.push({ sql, binds });
					if (sql.includes('INSERT INTO brand_audit_steps')) {
						rows.set(key(binds[0], binds[1], binds[2]), {
							audit_id: String(binds[0]),
							target: String(binds[1]),
							step: String(binds[2]),
							status: String(binds[3]),
							payload_json: binds[4] === null ? null : String(binds[4]),
							error: binds[5] === undefined ? null : (binds[5] as string | null),
							updated_at: Number(binds[6]),
						});
					}
					return { success: true, meta: { changes: 1, last_row_id: 0, duration: 0, rows_read: 0, rows_written: 1, size_after: 0 } };
				},
			};
			return stmt;
		},
	} as unknown as D1Database;
	return { db, calls };
}

describe('createD1BrandAuditStepStore', () => {
	it('upserts and reads a completed step with parsed JSON payload', async () => {
		const { createD1BrandAuditStepStore } = await import('../src/lib/brand-audit-step-store');
		const rows = new Map<string, { audit_id: string; target: string; step: string; status: string; payload_json: string | null; error: string | null; updated_at: number }>();
		const { db, calls } = makeMockD1(rows);
		const store = createD1BrandAuditStepStore(db, () => 1_800_000_000_000);

		await store.put({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'discovery',
			status: 'completed',
			payload: { candidates: ['example.net'], nested: { score: 0.91 } },
		});

		const record = await store.get('aud-1', 'example.com', 'discovery');

		expect(record).toEqual({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'discovery',
			status: 'completed',
			payload: { candidates: ['example.net'], nested: { score: 0.91 } },
			error: undefined,
		});

		const upsert = calls.find((c) => c.sql.includes('INSERT INTO brand_audit_steps'));
		expect(upsert?.sql).toContain('ON CONFLICT(audit_id, target, step)');
		expect(upsert?.binds).toEqual([
			'aud-1',
			'example.com',
			'discovery',
			'completed',
			JSON.stringify({ candidates: ['example.net'], nested: { score: 0.91 } }),
			null,
			1_800_000_000_000,
		]);
	});

	it('does not throw forever on malformed payload JSON', async () => {
		const { createD1BrandAuditStepStore } = await import('../src/lib/brand-audit-step-store');
		const rows = new Map([
			[
				'aud-1\0example.com\0classification',
				{
					audit_id: 'aud-1',
					target: 'example.com',
					step: 'classification',
					status: 'completed',
					payload_json: '{not-json',
					error: null,
					updated_at: 1_800_000_000_000,
				},
			],
		]);
		const { db } = makeMockD1(rows);
		const store = createD1BrandAuditStepStore(db);

		await expect(store.get('aud-1', 'example.com', 'classification')).resolves.toEqual({
			auditId: 'aud-1',
			target: 'example.com',
			step: 'classification',
			status: 'failed',
			payload: null,
			error: 'Malformed payload_json in brand_audit_steps',
		});
	});

	it('rejects payloads that cannot be serialized before writing to D1', async () => {
		const { createD1BrandAuditStepStore } = await import('../src/lib/brand-audit-step-store');
		const { db } = makeMockD1(new Map());
		const store = createD1BrandAuditStepStore(db);

		await expect(
			store.put({
				auditId: 'aud-1',
				target: 'example.com',
				step: 'classification',
				status: 'completed',
				payload: { count: 1n },
			}),
		).rejects.toThrow('brand_audit_step_payload_not_serializable');
	});
});
