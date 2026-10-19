// SPDX-License-Identifier: BUSL-1.1
//
// discoverBrandDomainsFindings — the gate order (US-13 / SQ-373):
//   operationId shape → owner-scoped audit lookup → target row → terminal status.
// The success/parse path is covered by discover-brand-domains-findings-parse.test.ts;
// this pins the error findings (they are client-visible) and that earlier gates
// short-circuit before later D1 reads.

import { describe, expect, it, vi } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';

type Audit = { id: string; owner_id: string; status: string } | null;
type Target = { target: string; status: string; result_json: string | null; error: string | null; completed_at: number | null } | null;

function fakeDb(audit: Audit, target: Target) {
	const seen: string[] = [];
	const prepare = vi.fn((sql: string) => ({
		bind: () => ({
			first: async () => {
				seen.push(sql.includes('FROM brand_audits') ? 'audit' : 'target');
				return sql.includes('FROM brand_audits') ? audit : target;
			},
		}),
	}));
	return { db: { prepare } as unknown as D1Database, seen, prepare };
}

function onlyFinding(result: CheckResult) {
	expect(result.findings).toHaveLength(1);
	return result.findings[0];
}

async function findings(operationId: unknown, ownerId: string, db: D1Database) {
	const { discoverBrandDomainsFindings } = await import('../src/tools/discover-brand-domains-start');
	return discoverBrandDomainsFindings(operationId as string, ownerId, { db });
}

const OWNED: Audit = { id: 'op-1', owner_id: 'owner-1', status: 'running' };

describe('discoverBrandDomainsFindings — gates', () => {
	it.each([
		['empty', ''],
		['whitespace', '   '],
		['non-string', 123],
		['undefined', undefined],
	])('%s operationId → invalidInput, no D1 read', async (_label, operationId) => {
		const { db, prepare } = fakeDb(OWNED, null);
		const f = onlyFinding(await findings(operationId, 'owner-1', db));
		expect(f.title).toBe('Discover brand domains findings: invalidInput');
		expect(f.severity).toBe('high');
		expect(f.detail).toBe('operationId is required.');
		expect(f.metadata?.invalidInput).toBe(true);
		expect(prepare).not.toHaveBeenCalled();
	});

	it('unknown audit → notFound (operation message), target never read', async () => {
		const { db, seen } = fakeDb(null, null);
		const f = onlyFinding(await findings('op-1', 'owner-1', db));
		expect(f.title).toBe('Discover brand domains findings: notFound');
		expect(f.detail).toBe('No discovery operation found with id op-1.');
		expect(f.metadata).toMatchObject({ notFound: true, operationId: 'op-1' });
		expect(seen).toEqual(['audit']);
	});

	it("another owner's audit is indistinguishable from an unknown one (ID-enumeration defense)", async () => {
		const { db, seen } = fakeDb({ id: 'op-1', owner_id: 'someone-else', status: 'completed' }, null);
		const f = onlyFinding(await findings('op-1', 'owner-1', db));
		expect(f.detail).toBe('No discovery operation found with id op-1.');
		expect(seen).toEqual(['audit']);
	});

	it('owned audit without a target row → notFound (target message)', async () => {
		const { db, seen } = fakeDb(OWNED, null);
		const f = onlyFinding(await findings('op-1', 'owner-1', db));
		expect(f.title).toBe('Discover brand domains findings: notFound');
		expect(f.detail).toBe('No discovery target found for operation op-1.');
		expect(seen).toEqual(['audit', 'target']);
	});

	it.each(['queued', 'running'])('a %s target → notReady with the current status', async (status) => {
		const { db } = fakeDb(OWNED, { target: 'example.com', status, result_json: null, error: null, completed_at: null });
		const f = onlyFinding(await findings('op-1', 'owner-1', db));
		expect(f.title).toBe('Discover brand domains findings: notReady');
		expect(f.detail).toBe(`Discovery operation op-1 is currently ${status}. Poll again with discover_brand_domains_status.`);
		expect(f.metadata).toMatchObject({ notReady: true, operationId: 'op-1', currentStatus: status });
	});

	it('a failed target is terminal: summary finding carries status=failed and the error', async () => {
		const { db } = fakeDb(OWNED, { target: 'example.com', status: 'failed', result_json: null, error: 'boom', completed_at: 5 });
		const f = onlyFinding(await findings('op-1', 'owner-1', db));
		expect(f.title).toBe('Brand-domain discovery op-1: failed');
		expect(f.severity).toBe('info');
		expect(f.detail).toBe('status=failed target=example.com');
		expect(f.metadata).toMatchObject({
			summary: true,
			auditId: 'op-1',
			operationId: 'op-1',
			target: 'example.com',
			status: 'failed',
			result: null,
			error: 'boom',
		});
	});
});
