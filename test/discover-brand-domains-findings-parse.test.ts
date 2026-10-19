// SPDX-License-Identifier: BUSL-1.1

/**
 * `discoverBrandDomainsFindings` parses the stored `result_json` through the module-private
 * `safeParse`: valid JSON is surfaced, while null / empty / malformed JSON degrades to
 * `result: null` instead of throwing (the row's status and error still come through).
 */

import { describe, expect, it } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';

type TargetRow = {
	target: string;
	status: 'queued' | 'running' | 'completed' | 'failed';
	result_json: string | null;
	error: string | null;
	completed_at: number | null;
};

/** Minimal D1 double: the audits query returns an owned audit row, the targets query returns `targetRow`. */
function fakeDb(targetRow: TargetRow | null): D1Database {
	return {
		prepare(sql: string) {
			return {
				bind() {
					return {
						async first() {
							if (sql.includes('FROM brand_audits')) return { id: 'op-1', owner_id: 'owner-1', status: 'completed' };
							return targetRow;
						},
					};
				},
			};
		},
	} as unknown as D1Database;
}

function summaryMetadata(result: CheckResult): Record<string, unknown> {
	const summary = result.findings.find((f) => f.metadata?.summary === true);
	expect(summary).toBeDefined();
	return summary!.metadata as Record<string, unknown>;
}

describe('discoverBrandDomainsFindings result_json parsing', () => {
	it('surfaces the parsed object for valid JSON', async () => {
		const { discoverBrandDomainsFindings } = await import('../src/tools/discover-brand-domains-start');
		const stored = { category: 'brand_discovery', score: 100, findings: [] };
		const result = await discoverBrandDomainsFindings(
			'op-1',
			'owner-1',
			{ db: fakeDb({ target: 'example.com', status: 'completed', result_json: JSON.stringify(stored), error: null, completed_at: 1 }) },
		);
		const meta = summaryMetadata(result);
		expect(meta.status).toBe('completed');
		expect(meta.result).toEqual(stored);
	});

	it('returns result null when result_json is null', async () => {
		const { discoverBrandDomainsFindings } = await import('../src/tools/discover-brand-domains-start');
		const result = await discoverBrandDomainsFindings(
			'op-1',
			'owner-1',
			{ db: fakeDb({ target: 'example.com', status: 'failed', result_json: null, error: 'discovery timed out', completed_at: 1 }) },
		);
		const meta = summaryMetadata(result);
		expect(meta.status).toBe('failed');
		expect(meta.result).toBeNull();
		expect(meta.error).toBe('discovery timed out');
	});

	it('returns result null instead of throwing when result_json is malformed', async () => {
		const { discoverBrandDomainsFindings } = await import('../src/tools/discover-brand-domains-start');
		const result = await discoverBrandDomainsFindings(
			'op-1',
			'owner-1',
			{ db: fakeDb({ target: 'example.com', status: 'completed', result_json: '{not json', error: null, completed_at: 1 }) },
		);
		expect(summaryMetadata(result).result).toBeNull();
	});
});
