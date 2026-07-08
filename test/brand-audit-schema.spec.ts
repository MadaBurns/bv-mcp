import { describe, expect, it } from 'vitest';
import { getTableConfig } from 'drizzle-orm/sqlite-core';
import { brandAuditTargets } from '../src/lib/db/brand-audit-schema';

describe('brand audit schema', () => {
	it('declares status/created_at index for the running-target reaper', () => {
		const t = getTableConfig(brandAuditTargets);
		const idx = t.indexes.find((i) => i.config.name === 'idx_brand_audit_targets_status_created_at');
		expect(idx).toBeDefined();
	});
});
