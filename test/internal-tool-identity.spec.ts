// SPDX-License-Identifier: BUSL-1.1

// @ts-expect-error cloudflare:test exports are injected by the Workers Vitest pool at runtime.
import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it, vi } from 'vitest';
import worker from '../src';
import { deriveCanonicalTenantPrincipal } from '../src/lib/auth-principal';

const WEB_KEY = 'web-internal-tool-identity-key';
const TENANT_TOOL_KEY = 'tenant-tool-delegation-key-32-bytes-minimum';
const WATCH_CLEANUP_KEY = 'watch-cleanup-capability-key-32-bytes-minimum';

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	BV_MCP_TOOL_DELEGATION_KEY?: string;
	BV_MCP_WATCH_CLEANUP_KEY?: string;
	BV_MOBILE_INTERNAL_KEY?: string;
	BV_MCP_BRAND_WEBHOOK_KEY?: string;
	BV_API_KEY?: string;
	BRAND_AUDIT_DB?: D1Database;
	OAUTH_ISSUER?: string;
};

async function send(
	headers: HeadersInit,
	customEnv: TestEnv,
	body: { name: string; arguments: Record<string, unknown> } = {
		name: 'register_brand_audit_watch',
		arguments: { domain: 'example.com', interval: 'weekly' },
	},
): Promise<Response> {
	const request = new Request('https://example.com/internal/tools/call', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${WEB_KEY}`, ...headers },
		body: JSON.stringify(body),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

async function sendBatch(headers: HeadersInit, customEnv: TestEnv): Promise<Response> {
	const request = new Request('https://example.com/internal/tools/batch', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body: JSON.stringify({ tool: 'scan_domain', domains: ['example.com'] }),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

describe('internal tool-door tenant identity', () => {
	it('binds the trusted web tenant header into brand-watch ownership', async () => {
		const bound: unknown[][] = [];
		const db = {
			prepare: vi.fn((_sql: string) => ({
				bind: (...args: unknown[]) => {
					bound.push(args);
					return {
						first: async () => ({ count: 0 }),
						run: async () => ({ success: true }),
					};
				},
			})),
			batch: vi.fn(async () => [
				{ success: true, results: [], meta: { changes: 0 } },
				{ success: true, results: [], meta: { changes: 0 } },
			]),
		} as unknown as D1Database;
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: WEB_KEY,
			BV_MCP_TOOL_DELEGATION_KEY: TENANT_TOOL_KEY,
			BRAND_AUDIT_DB: db,
			OAUTH_ISSUER: 'https://example.com',
		} as TestEnv;

		const response = await send(
			{ Authorization: `Bearer ${TENANT_TOOL_KEY}`, 'X-Tenant': 'tenant_123', 'X-Auth-Tier': 'developer' },
			customEnv,
		);
		expect(response.status).toBe(200);
		const canonicalPrincipal = await deriveCanonicalTenantPrincipal('https://example.com', 'tenant_123');
		expect(bound.some((args) => args.includes(canonicalPrincipal))).toBe(true);
		expect(canonicalPrincipal).toMatch(/^[0-9a-f]{64}$/);
	});

	it('rejects incomplete or invalid tenant context before tool execution', async () => {
		const prepare = vi.fn();
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: WEB_KEY,
			BV_MCP_TOOL_DELEGATION_KEY: TENANT_TOOL_KEY,
			BRAND_AUDIT_DB: { prepare } as unknown as D1Database,
			OAUTH_ISSUER: 'https://example.com',
		} as TestEnv;

		expect((await send({ Authorization: `Bearer ${TENANT_TOOL_KEY}`, 'X-Tenant': 'tenant_123' }, customEnv)).status).toBe(400);
		expect(
			(await send({ Authorization: `Bearer ${TENANT_TOOL_KEY}`, 'X-Tenant': 'tenant_123', 'X-Auth-Tier': 'owner' }, customEnv)).status,
		).toBe(400);
		expect(prepare).not.toHaveBeenCalled();
	});

	it('rejects tenant assertions made with the fleet-wide web bearer', async () => {
		const prepare = vi.fn();
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: WEB_KEY,
			BV_MCP_TOOL_DELEGATION_KEY: TENANT_TOOL_KEY,
			BRAND_AUDIT_DB: { prepare } as unknown as D1Database,
			OAUTH_ISSUER: 'https://example.com',
		} as TestEnv;

		const response = await send({ 'X-Tenant': 'victim_tenant', 'X-Auth-Tier': 'enterprise' }, customEnv);
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: 'tenant_context_not_allowed' });
		expect(prepare).not.toHaveBeenCalled();
	});

	it('fails closed when the tenant-tool capability collides with the fleet bearer', async () => {
		const shared = 'shared-capability-value-32-bytes-minimum';
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: shared,
			BV_MCP_TOOL_DELEGATION_KEY: shared,
			OAUTH_ISSUER: 'https://example.com',
		} as TestEnv;

		const response = await send({ Authorization: `Bearer ${shared}`, 'X-Tenant': 'victim_tenant', 'X-Auth-Tier': 'enterprise' }, customEnv);
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: 'Service authentication configuration invalid' });
		expect(response.headers.get('cache-control')).toBe('no-store');
	});

	it('fails closed when tool delegation aliases the owner API credential', async () => {
		const shared = 'owner-tool-alias-capability-32-bytes-minimum';
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: WEB_KEY,
			BV_MCP_TOOL_DELEGATION_KEY: shared,
			BV_API_KEY: shared,
			OAUTH_ISSUER: 'https://example.com',
		} as TestEnv;

		const response = await send({ Authorization: `Bearer ${shared}`, 'X-Tenant': 'victim_tenant', 'X-Auth-Tier': 'enterprise' }, customEnv);
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: 'Service authentication configuration invalid' });
		expect(response.headers.get('cache-control')).toBe('no-store');
	});

	it.each(['BV_WEB_INTERNAL_KEY', 'BV_MOBILE_INTERNAL_KEY', 'BV_MCP_TOOL_DELEGATION_KEY', 'BV_MCP_WATCH_CLEANUP_KEY'] as const)(
		'fails closed when %s aliases the Brand Drift sender capability',
		async (keyName) => {
			const shared = 'brand-webhook-alias-capability-32-bytes-minimum';
			const customEnv = {
				...env,
				BV_WEB_INTERNAL_KEY: WEB_KEY,
				BV_MCP_BRAND_WEBHOOK_KEY: shared,
				[keyName]: shared,
				OAUTH_ISSUER: 'https://example.com',
			} as TestEnv;

			const response = await send({ Authorization: `Bearer ${shared}` }, customEnv, {
				name: 'scan_domain',
				arguments: { domain: 'example.com' },
			});
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: 'Service authentication configuration invalid' });
			expect(response.headers.get('cache-control')).toBe('no-store');
		},
	);

	it('allows the delegation key only for the three Brand Watch lifecycle tools', async () => {
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: WEB_KEY,
			BV_MCP_TOOL_DELEGATION_KEY: TENANT_TOOL_KEY,
			OAUTH_ISSUER: 'https://example.com',
		} as TestEnv;
		const headers = {
			Authorization: `Bearer ${TENANT_TOOL_KEY}`,
			'X-Tenant': 'tenant_123',
			'X-Auth-Tier': 'enterprise',
		};

		const report = await send(headers, customEnv, {
			name: 'brand_audit_get_report',
			arguments: { auditId: 'audit-victim' },
		});
		expect(report.status).toBe(403);
		expect(await report.json()).toEqual({ error: 'tenant_tool_not_allowed' });

		const batch = await sendBatch(headers, customEnv);
		expect(batch.status).toBe(403);
		expect(await batch.json()).toEqual({ error: 'tenant_batch_not_allowed' });
	});

	it('limits the ops cleanup capability to list/delete and denies registration', async () => {
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: WEB_KEY,
			BV_MCP_WATCH_CLEANUP_KEY: WATCH_CLEANUP_KEY,
			OAUTH_ISSUER: 'https://example.com',
		} as TestEnv;
		const headers = {
			Authorization: `Bearer ${WATCH_CLEANUP_KEY}`,
			'X-Tenant': 'tenant_123',
			'X-Auth-Tier': 'developer',
		};

		const registration = await send(headers, customEnv);
		expect(registration.status).toBe(403);
		expect(await registration.json()).toEqual({ error: 'watch_cleanup_tool_not_allowed' });
		const batch = await sendBatch(headers, customEnv);
		expect(batch.status).toBe(403);
		expect(await batch.json()).toEqual({ error: 'tenant_batch_not_allowed' });
	});

	it('fails closed when tenant delegation has no pinned canonical issuer', async () => {
		const prepare = vi.fn();
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: WEB_KEY,
			BV_MCP_TOOL_DELEGATION_KEY: TENANT_TOOL_KEY,
			BRAND_AUDIT_DB: { prepare } as unknown as D1Database,
			OAUTH_ISSUER: undefined,
		} as TestEnv;

		const response = await send(
			{ Authorization: `Bearer ${TENANT_TOOL_KEY}`, 'X-Tenant': 'tenant_123', 'X-Auth-Tier': 'developer' },
			customEnv,
		);
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: 'oauth_issuer_not_configured' });
		expect(prepare).not.toHaveBeenCalled();
	});

	it('executes a repeated mutating Idempotency-Key only once', async () => {
		const reconFetch = vi.fn(
			async () =>
				new Response(JSON.stringify({ scanId: 'scan-idempotent-1', status: 'started' }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				}),
		);
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: WEB_KEY,
			BV_RECON: { fetch: reconFetch },
			BV_RECON_KEY: 'recon-key',
		} as unknown as TestEnv;
		const headers = {
			'Idempotency-Key': 'recon-start:stable-test-operation',
			'X-BV-Caller': 'recon-test',
		};
		const body = { name: 'scan_buckets_start', arguments: { target: 'example.com' } };

		const first = await send(headers, customEnv, body);
		const second = await send(headers, customEnv, body);
		expect(first.status).toBe(200);
		expect(second.status).toBe(200);
		expect(await second.json()).toEqual(await first.json());
		expect(reconFetch).toHaveBeenCalledTimes(1);
	});
});
