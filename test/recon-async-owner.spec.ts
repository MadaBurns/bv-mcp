// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it, vi } from 'vitest';
import { handleToolsCall } from '../src/handlers/tools';

function fakeKv() {
	const store = new Map<string, string>();
	return {
		get: vi.fn(async (key: string) => store.get(key) ?? null),
		put: vi.fn(async (key: string, value: string) => {
			store.set(key, value);
		}),
	} as unknown as KVNamespace;
}

function binding(routes: Record<string, unknown>) {
	return {
		fetch: vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			void init;
			const url = String(input);
			for (const [fragment, body] of Object.entries(routes)) {
				if (url.includes(fragment)) return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
			}
			return new Response(JSON.stringify({ error: 'not found' }), { status: 404, headers: { 'content-type': 'application/json' } });
		}),
	};
}

function asJson(result: unknown): string {
	return JSON.stringify(result);
}

describe('async recon owner binding', () => {
	it('binds bucket scan status/findings to the principal that started the scan', async () => {
		const kv = fakeKv();
		const reconBinding = binding({
			'/buckets/api/scan/trigger': { scanId: 'scan_own_1', status: 'running' },
			'/buckets/api/scan/status/scan_own_1': { scanId: 'scan_own_1', status: 'completed' },
			'/buckets/api/findings': { count: 0, data: [] },
		});

		await handleToolsCall(
			{ name: 'scan_buckets_start', arguments: { target: 'example.com' } },
			undefined,
			{ reconBinding, reconAuthToken: 'tok', rateLimitKv: kv, keyHash: 'owner-a', principalId: 'owner-a' },
		);

		const denied = await handleToolsCall(
			{ name: 'scan_buckets_status', arguments: { scanId: 'scan_own_1' } },
			undefined,
			{ reconBinding, reconAuthToken: 'tok', rateLimitKv: kv, keyHash: 'owner-b', principalId: 'owner-b' },
		);
		expect(asJson(denied)).toContain('not owned by this principal');

		const allowed = await handleToolsCall(
			{ name: 'scan_buckets_findings', arguments: { scanId: 'scan_own_1' } },
			undefined,
			{ reconBinding, reconAuthToken: 'tok', rateLimitKv: kv, keyHash: 'owner-a', principalId: 'owner-a' },
		);
		expect(asJson(allowed)).toContain('Bucket findings');
	});

	it('requires scanId for bucket findings so reads can be owner-bound', async () => {
		const reconBinding = binding({
			'/buckets/api/findings': { count: 1, data: [{ bucket: 'leak-example' }] },
		});

		const denied = await handleToolsCall(
			{ name: 'scan_buckets_findings', arguments: {} },
			undefined,
			{ reconBinding, reconAuthToken: 'tok', rateLimitKv: fakeKv(), keyHash: 'owner-a', principalId: 'owner-a' },
		);

		expect(asJson(denied)).toContain('Missing required parameter: scanId');
		expect(reconBinding.fetch).not.toHaveBeenCalled();
	});

	it('binds OSINT status/report to the principal that started the investigation', async () => {
		const kv = fakeKv();
		const reconBinding = binding({
			'/osint/api/investigate/domain': { investigationId: 'inv_own_1', status: 'running' },
			'/osint/api/investigation/inv_own_1/report': { total: 0, findings: [] },
			'/osint/api/investigation/inv_own_1': { investigationId: 'inv_own_1', status: 'completed' },
		});

		await handleToolsCall(
			{ name: 'osint_investigate_domain_start', arguments: { query: 'example.com' } },
			undefined,
			{ reconBinding, reconAuthToken: 'tok', rateLimitKv: kv, keyHash: 'owner-a', principalId: 'owner-a' },
		);

		const denied = await handleToolsCall(
			{ name: 'osint_investigation_report', arguments: { investigationId: 'inv_own_1' } },
			undefined,
			{ reconBinding, reconAuthToken: 'tok', rateLimitKv: kv, keyHash: 'owner-b', principalId: 'owner-b' },
		);
		expect(asJson(denied)).toContain('not owned by this principal');

		const allowed = await handleToolsCall(
			{ name: 'osint_investigation_status', arguments: { investigationId: 'inv_own_1' } },
			undefined,
			{ reconBinding, reconAuthToken: 'tok', rateLimitKv: kv, keyHash: 'owner-a', principalId: 'owner-a' },
		);
		expect(asJson(allowed)).toContain('Investigation inv_own_1');
	});
});
