// Route tests for /internal/oauth/ema-tenants — the operator door that seeds the
// per-tenant trusted-issuer allowlist. Gated by BV_MCP_OAUTH_MINT_KEY (no new secret).
// Store semantics live in test/oauth/ema-tenants.spec.ts; this file owns the gate,
// request validation, issuer discovery and response contract.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src';
import { OAUTH_KV_PREFIX } from '../src/lib/config';
import { getEmaTenantByIssuer } from '../src/oauth/ema-tenants';
import { clearKvPrefix } from './helpers/kv';

const TEST_INTERNAL_KEY = 'ema-mint-capability-test-key-32-bytes-min';
const BASE = 'http://example.com/internal/oauth/ema-tenants';
const CLAUDE_WEB_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';

type TestEnv = typeof env & { BV_MCP_OAUTH_MINT_KEY?: string };

async function send(req: Request, customEnv: TestEnv = { ...env, BV_MCP_OAUTH_MINT_KEY: TEST_INTERNAL_KEY } as TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

function call(method: string, path = '', body?: unknown, headers: Record<string, string> = {}): Request {
	return new Request<unknown, IncomingRequestCfProperties>(`${BASE}${path}`, {
		method,
		headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${TEST_INTERNAL_KEY}`, ...headers },
		body: body === undefined ? undefined : JSON.stringify(body),
	});
}

function upsertBody(overrides: Record<string, unknown> = {}) {
	return {
		tenant_id: 'acme-corp',
		name: 'Acme Corp',
		issuer: 'https://idp.example.com/oauth2/default/',
		jwks_uri: 'https://idp.example.com/oauth2/v1/keys',
		tier: 'enterprise',
		enabled: true,
		...overrides,
	};
}

function discoveryResponse(doc: unknown, status = 200): Response {
	return new Response(JSON.stringify(doc), { status, headers: { 'Content-Type': 'application/json' } });
}

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
});
afterEach(async () => {
	vi.unstubAllGlobals();
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
});

describe('/internal/oauth/ema-tenants gate', () => {
	it('returns 503 when BV_MCP_OAUTH_MINT_KEY is not configured', async () => {
		const res = await send(call('GET'), { ...env, BV_MCP_OAUTH_MINT_KEY: undefined } as TestEnv);
		expect(res.status).toBe(503);
		expect(res.headers.get('cache-control')).toBe('no-store');
	});

	it.each([
		['PUT', ''],
		['GET', ''],
		['GET', '/acme-corp'],
		['DELETE', '/acme-corp'],
	])('returns 401 on %s %s without a bearer', async (method, path) => {
		const res = await send(call(method, path, method === 'PUT' ? upsertBody() : undefined, { Authorization: '' }));
		expect(res.status).toBe(401);
	});

	it('returns 401 with a wrong bearer', async () => {
		const res = await send(call('GET', '', undefined, { Authorization: 'Bearer wrong' }));
		expect(res.status).toBe(401);
	});

	it('returns 404 when cf-connecting-ip is present (public internet)', async () => {
		const res = await send(call('GET', '', undefined, { 'cf-connecting-ip': '203.0.113.9' }));
		expect(res.status).toBe(404);
	});

	it('does not accept a different capability key (revoke key) as the bearer', async () => {
		const customEnv = {
			...env,
			BV_MCP_OAUTH_MINT_KEY: TEST_INTERNAL_KEY,
			BV_MCP_OAUTH_REVOKE_KEY: 'revoke-capability-test-key-32-bytes-min',
		} as TestEnv;
		const res = await send(call('GET', '', undefined, { Authorization: 'Bearer revoke-capability-test-key-32-bytes-min' }), customEnv);
		expect(res.status).toBe(401);
	});
});

describe('PUT /internal/oauth/ema-tenants', () => {
	it('upserts with an explicit jwks_uri, normalizes the issuer and applies defaults', async () => {
		const fetchSpy = vi.fn();
		vi.stubGlobal('fetch', fetchSpy);
		const res = await send(call('PUT', '', upsertBody()));
		expect(res.status).toBe(200);
		expect(res.headers.get('cache-control')).toBe('no-store');
		const stored = (await res.json()) as Record<string, unknown>;
		expect(stored).toMatchObject({
			tenant_id: 'acme-corp',
			issuer: 'https://idp.example.com/oauth2/default',
			jwks_uri: 'https://idp.example.com/oauth2/v1/keys',
			allowed_client_ids: [CLAUDE_WEB_CLIENT_ID],
			tier: 'enterprise',
			enabled: true,
		});
		expect(typeof stored.created_at).toBe('number');
		expect(stored.created_at).toBe(stored.updated_at);
		// Explicit jwks_uri means no discovery fetch at all.
		expect(fetchSpy).not.toHaveBeenCalled();
		// The allowlist lookup the token grant will use now resolves the issuer.
		const resolved = await getEmaTenantByIssuer(env.SESSION_STORE!, 'https://idp.example.com/oauth2/default/');
		expect(resolved?.tenant_id).toBe('acme-corp');
	});

	it('resolves jwks_uri via issuer discovery when omitted', async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			expect(String(input)).toBe('https://idp.example.com/oauth2/default/.well-known/openid-configuration');
			expect(init?.redirect).toBe('manual');
			return discoveryResponse({ issuer: 'https://idp.example.com/oauth2/default', jwks_uri: 'https://idp.example.com/oauth2/v1/keys' });
		});
		vi.stubGlobal('fetch', fetchSpy);
		const res = await send(call('PUT', '', upsertBody({ jwks_uri: undefined })));
		expect(res.status).toBe(200);
		expect(((await res.json()) as { jwks_uri: string }).jwks_uri).toBe('https://idp.example.com/oauth2/v1/keys');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it('accepts a discovery issuer that differs only by trailing slash', async () => {
		vi.stubGlobal('fetch', async () => discoveryResponse({ issuer: 'https://idp.example.com/', jwks_uri: 'https://idp.example.com/keys' }));
		const res = await send(call('PUT', '', upsertBody({ issuer: 'https://idp.example.com', jwks_uri: undefined })));
		expect(res.status).toBe(200);
	});

	it.each([
		['issuer mismatch', () => discoveryResponse({ issuer: 'https://evil.example.net', jwks_uri: 'https://idp.example.com/keys' })],
		[
			'non-200',
			() => discoveryResponse({ issuer: 'https://idp.example.com/oauth2/default', jwks_uri: 'https://idp.example.com/keys' }, 404),
		],
		[
			'redirect',
			() => new Response(null, { status: 302, headers: { Location: 'https://evil.example.net/.well-known/openid-configuration' } }),
		],
		[
			'http jwks_uri',
			() => discoveryResponse({ issuer: 'https://idp.example.com/oauth2/default', jwks_uri: 'http://idp.example.com/keys' }),
		],
		['missing jwks_uri', () => discoveryResponse({ issuer: 'https://idp.example.com/oauth2/default' })],
		['malformed JSON', () => new Response('not json', { status: 200 })],
		['oversize body', () => new Response('x'.repeat(20 * 1024), { status: 200 })],
	])('discovery %s -> 400 issuer_discovery_failed and nothing stored', async (_label, respond) => {
		vi.stubGlobal('fetch', async () => respond());
		const res = await send(call('PUT', '', upsertBody({ jwks_uri: undefined })));
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'issuer_discovery_failed' });
		expect(await getEmaTenantByIssuer(env.SESSION_STORE!, 'https://idp.example.com/oauth2/default')).toBeNull();
	});

	it('discovery network failure -> 400 issuer_discovery_failed', async () => {
		vi.stubGlobal('fetch', async () => {
			throw new TypeError('network down');
		});
		const res = await send(call('PUT', '', upsertBody({ jwks_uri: undefined })));
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'issuer_discovery_failed' });
	});

	it('preserves created_at on update and bumps updated_at', async () => {
		await send(call('PUT', '', upsertBody()));
		const kv = env.SESSION_STORE!;
		const key = `${OAUTH_KV_PREFIX}ema-tenant:acme-corp`;
		const first = JSON.parse((await kv.get(key))!) as { created_at: number };
		// Backdate so the update is distinguishable from the create within the same second.
		await kv.put(key, JSON.stringify({ ...first, created_at: 1_000, updated_at: 1_000 }));
		const res = await send(call('PUT', '', upsertBody({ name: 'Acme Renamed', enabled: false })));
		expect(res.status).toBe(200);
		const updated = (await res.json()) as { created_at: number; updated_at: number; name: string; enabled: boolean };
		expect(updated.created_at).toBe(1_000);
		expect(updated.updated_at).toBeGreaterThan(1_000);
		expect(updated.name).toBe('Acme Renamed');
		expect(updated.enabled).toBe(false);
	});

	it('409 issuer_conflict when another tenant owns the issuer', async () => {
		await send(call('PUT', '', upsertBody()));
		const res = await send(call('PUT', '', upsertBody({ tenant_id: 'other-corp' })));
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'issuer_conflict' });
	});

	it.each([
		['bad tenant_id', { tenant_id: 'X' }, 'Invalid tenant_id'],
		['http issuer', { issuer: 'http://idp.example.com' }, 'Invalid issuer'],
		['bad tier', { tier: 'owner' }, 'Invalid tier'],
		['http jwks_uri', { jwks_uri: 'http://idp.example.com/keys' }, 'Invalid jwks_uri'],
		['empty clients', { allowed_client_ids: [] }, 'Invalid allowed_client_ids'],
	])('400 on %s using the zod issue-path convention', async (_label, patch, prefix) => {
		const res = await send(call('PUT', '', upsertBody(patch)));
		expect(res.status).toBe(400);
		expect(res.headers.get('cache-control')).toBe('no-store');
		expect(((await res.json()) as { error: string }).error.startsWith(prefix)).toBe(true);
	});

	it('400 on issuer with userinfo/query (normalizeIssuer rejection) without echoing it', async () => {
		const res = await send(call('PUT', '', upsertBody({ issuer: 'https://user:secret-pw@idp.example.com' })));
		expect(res.status).toBe(400);
		expect(JSON.stringify(await res.json())).not.toContain('secret-pw');
	});

	it('400 on an unknown field without echoing the field name', async () => {
		const res = await send(call('PUT', '', upsertBody({ 'attacker-chosen-key': 1 })));
		expect(res.status).toBe(400);
		expect(JSON.stringify(await res.json())).not.toContain('attacker-chosen-key');
	});

	it('400 on malformed JSON and 413 on an oversize body', async () => {
		const bad = new Request<unknown, IncomingRequestCfProperties>(BASE, {
			method: 'PUT',
			headers: { Authorization: `Bearer ${TEST_INTERNAL_KEY}` },
			body: '{not json',
		});
		expect((await send(bad)).status).toBe(400);
		const res = await send(call('PUT', '', upsertBody({ name: 'n'.repeat(20_000) })));
		expect(res.status).toBe(413);
	});

	it('500 session_store_not_configured when SESSION_STORE is unbound', async () => {
		const res = await send(call('PUT', '', upsertBody()), {
			...env,
			BV_MCP_OAUTH_MINT_KEY: TEST_INTERNAL_KEY,
			SESSION_STORE: undefined,
		} as unknown as TestEnv);
		expect(res.status).toBe(500);
		expect(await res.json()).toEqual({ error: 'session_store_not_configured' });
	});
});

describe('GET / DELETE /internal/oauth/ema-tenants', () => {
	it('lists, reads and deletes a tenant', async () => {
		await send(call('PUT', '', upsertBody()));
		await send(
			call(
				'PUT',
				'',
				upsertBody({ tenant_id: 'beta-corp', issuer: 'https://idp-b.example.com', jwks_uri: 'https://idp-b.example.com/keys' }),
			),
		);

		const list = await send(call('GET'));
		expect(list.status).toBe(200);
		expect(list.headers.get('cache-control')).toBe('no-store');
		const listed = (await list.json()) as { tenants: Array<{ tenant_id: string }>; total: number };
		expect(listed.total).toBe(2);
		expect(listed.tenants.map((t) => t.tenant_id).sort()).toEqual(['acme-corp', 'beta-corp']);

		const one = await send(call('GET', '/acme-corp'));
		expect(one.status).toBe(200);
		expect(((await one.json()) as { issuer: string }).issuer).toBe('https://idp.example.com/oauth2/default');

		const del = await send(call('DELETE', '/acme-corp'));
		expect(del.status).toBe(204);
		expect(del.headers.get('cache-control')).toBe('no-store');
		expect((await send(call('GET', '/acme-corp'))).status).toBe(404);
		expect(await getEmaTenantByIssuer(env.SESSION_STORE!, 'https://idp.example.com/oauth2/default')).toBeNull();
		expect((await getEmaTenantByIssuer(env.SESSION_STORE!, 'https://idp-b.example.com'))?.tenant_id).toBe('beta-corp');
	});

	it('404 not_found for an unknown or malformed tenant_id', async () => {
		const unknown = await send(call('GET', '/missing-tenant'));
		expect(unknown.status).toBe(404);
		expect(await unknown.json()).toEqual({ error: 'not_found' });
		expect((await send(call('GET', '/NOT_VALID'))).status).toBe(404);
		expect((await send(call('DELETE', '/NOT_VALID'))).status).toBe(404);
	});

	it('DELETE of a missing tenant is idempotent (204)', async () => {
		expect((await send(call('DELETE', '/missing-tenant'))).status).toBe(204);
	});
});
