// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';

import {
	assertRequiredBrandAuditColumns,
	resolveBrandAuditDatabase,
	runBrandAuditSchemaPreflight,
} from '../../scripts/brand-audit-schema-preflight.mjs';

const CONFIG = JSON.stringify({
	d1_databases: [{ binding: 'BRAND_AUDIT_DB', database_name: 'brand-audit-prod', database_id: 'db-id' }],
});

describe('brand-audit remote schema preflight', () => {
	it('uses the exact BRAND_AUDIT_DB deployment binding and a read-only remote query', () => {
		const spawnSync = vi.fn(() => ({
			status: 0,
			stdout: JSON.stringify([
				{
					success: true,
					results: [{ name: 'last_classification_result_json' }, { name: 'pending_webhook_json' }],
				},
			]),
			stderr: '',
		}));

		expect(
			runBrandAuditSchemaPreflight('wrangler.production.jsonc', {
				readFileSync: () => CONFIG,
				spawnSync,
				wranglerCliPath: '/safe/wrangler-cli.js',
			}),
		).toEqual({ database: 'brand-audit-prod' });
		const [, args] = spawnSync.mock.calls[0];
		expect(args).toContain('d1');
		expect(args).toContain('execute');
		expect(args).toContain('--remote');
		expect(args).toContain('--json');
		expect(args.join(' ')).toContain("pragma_table_info('brand_audit_watches')");
		expect(args).not.toContain('--file');
	});

	it('fails closed when either required column is absent', () => {
		expect(() =>
			assertRequiredBrandAuditColumns(
				JSON.stringify([{ success: true, results: [{ name: 'last_classification_result_json' }] }]),
			),
		).toThrow(/pending_webhook_json/);
	});

	it('fails closed when the deployment config omits the binding', () => {
		expect(() => resolveBrandAuditDatabase({ d1_databases: [] })).toThrow(/BRAND_AUDIT_DB/);
	});

	it('fails closed on a Wrangler query error or invalid output', () => {
		expect(() => assertRequiredBrandAuditColumns('not-json')).toThrow(/invalid JSON/);
		expect(() => assertRequiredBrandAuditColumns(JSON.stringify([{ success: false, results: [] }]))).toThrow(/query failed/);
	});
});
