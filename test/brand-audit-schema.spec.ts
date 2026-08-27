import { describe, expect, it } from 'vitest';
import { getTableConfig } from 'drizzle-orm/sqlite-core';
import { brandAuditTargets, brandAuditWatches } from '../src/lib/db/brand-audit-schema';

describe('brand audit schema', () => {
	it('declares status/created_at index for the running-target reaper', () => {
		const t = getTableConfig(brandAuditTargets);
		const idx = t.indexes.find((i) => i.config.name === 'idx_brand_audit_targets_status_created_at');
		expect(idx).toBeDefined();
	});

	it('declares the durable webhook baseline and pending-outbox columns', () => {
		const columns = getTableConfig(brandAuditWatches).columns.map((column) => column.name);
		expect(columns).toEqual(
			expect.arrayContaining(['last_classification_hash', 'last_classification_result_json', 'pending_webhook_json']),
		);
	});
});
