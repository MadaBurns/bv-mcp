// test/internal-access-log.spec.ts
// SPDX-License-Identifier: BUSL-1.1
//
// FOLLOW-UP B1: the internal service-binding path (/internal/tools/{call,batch})
// writes an mcp_access_log row tagged source='internal' (bv-web-forwarded scans
// were previously invisible to /internal/analytics/usage). ip_hash='unknown',
// key_hash=null, x-bv-caller → client_type.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { setupFetchMock, mockTxtRecords } from './helpers/dns-mock';

const fetchMock = setupFetchMock();
afterEach(() => {
	fetchMock.restore();
	vi.restoreAllMocks();
});

/** Fake D1 that records prepare/bind calls and resolves run/all. */
function createFakeD1() {
	const run = vi.fn(async () => ({ success: true }));
	const all = vi.fn(async () => ({ results: [] }));
	const bind = vi.fn(() => ({ run, all }));
	const prepare = vi.fn(() => ({ bind }));
	return { db: { prepare } as unknown as D1Database, prepare, bind, run };
}

/** Fake executionCtx capturing deferred work so the test can await the insert. */
function createFakeCtx() {
	const promises: Promise<unknown>[] = [];
	return {
		ctx: { waitUntil: (p: Promise<unknown>) => promises.push(p), passThroughOnException: () => undefined } as unknown as ExecutionContext,
		drain: () => Promise.all(promises),
	};
}

describe('internal /tools/call access logging', () => {
	it('writes one internal-source row for a domain-bearing tool', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const { internalRoutes } = await import('../src/internal');
		const fake = createFakeD1();
		const { ctx, drain } = createFakeCtx();
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: fake.db };

		const res = await internalRoutes.request(
			'/tools/call',
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json', 'x-bv-caller': 'admin-analytics' },
				body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
			},
			env,
			ctx,
		);
		expect(res.status).toBe(200);
		await drain();

		const insertCall = fake.prepare.mock.calls.find((call) => String(call[0]).includes('INSERT INTO mcp_access_log'));
		expect(insertCall).toBeDefined();
		expect(fake.bind).toHaveBeenCalledWith(
			'unknown', // ip_hash
			'unknown', // ip_masked
			'check_spf',
			'example.com',
			null, // country
			null, // user_agent
			expect.any(Number),
			0, // rate_limited
			null, // ip_ciphertext
			null, // ip_key_version
			null, // city
			null, // region
			null, // latitude
			null, // longitude
			null, // asn
			null, // as_org
			null, // ptr_hostname
			null, // key_hash
			'admin-analytics', // client_type ← x-bv-caller
			null, // colo
			null, // session_hash
			'tools/call',
			'internal', // transport
			'pass',
			'internal', // source
		);
	});

	it('does not write a row for a no-domain tool (parity with public path)', async () => {
		const { internalRoutes } = await import('../src/internal');
		const fake = createFakeD1();
		const { ctx, drain } = createFakeCtx();
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: fake.db };

		const res = await internalRoutes.request(
			'/tools/call',
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: 'explain_finding', arguments: { finding: 'spf_missing' } }),
			},
			env,
			ctx,
		);
		expect(res.status).toBe(200);
		await drain();
		expect(fake.prepare.mock.calls.some((call) => String(call[0]).includes('INSERT INTO mcp_access_log'))).toBe(false);
	});

	it('writes no row when neither INTELLIGENCE_DB nor MCP_ANALYTICS_QUEUE is bound (BSL self-host)', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const { internalRoutes } = await import('../src/internal');
		const { ctx, drain } = createFakeCtx();
		const env = { REQUIRE_INTERNAL_AUTH: 'false' };

		const res = await internalRoutes.request(
			'/tools/call',
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
			},
			env,
			ctx,
		);
		expect(res.status).toBe(200);
		await drain();
		// No DB bound → recordMcpAccessLog early-returns; nothing to assert beyond not throwing.
	});
});

describe('internal /tools/batch access logging', () => {
	it('writes one internal-source row per processed domain', async () => {
		mockTxtRecords(['v=spf1 -all']);
		const { internalRoutes } = await import('../src/internal');
		const fake = createFakeD1();
		const { ctx, drain } = createFakeCtx();
		const env = { REQUIRE_INTERNAL_AUTH: 'false', INTELLIGENCE_DB: fake.db };

		const res = await internalRoutes.request(
			'/tools/batch',
			{
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ tool: 'check_spf', domains: ['example.com', 'example.net'] }),
			},
			env,
			ctx,
		);
		expect(res.status).toBe(200);
		await drain();

		// Two access-log inserts (one per domain), both with source='internal' (trailing bind arg).
		const accessLogBinds = fake.bind.mock.calls.filter((call) => call.length === 25 && call[24] === 'internal');
		expect(accessLogBinds).toHaveLength(2);
		const domains = accessLogBinds.map((call) => call[3]).sort();
		expect(domains).toEqual(['example.com', 'example.net']);
	});
});
