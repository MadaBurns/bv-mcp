// Route tests for /internal/oauth/ema-tenants — the operator door that seeds the
// per-tenant trusted-issuer allowlist. Gated by the operator-only BV_MCP_EMA_ADMIN_KEY.
// Store semantics live in test/oauth/ema-tenants.spec.ts; this file owns the gate,
// request validation, issuer discovery and response contract.

import { env, createExecutionContext, runInDurableObject, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src';
import { OAUTH_KV_PREFIX } from '../src/lib/config';
import {
	effectiveApproval,
	emaIssuerStorageKey,
	emaRecordStorageKey,
	EMA_MIGRATED_STORAGE_KEY,
	getEmaTenant,
	getEmaTenantByIssuer,
	type EmaRegistry,
} from '../src/oauth/ema-tenants';
import { resetQuotaCoordinatorState, EMA_REGISTRY_INSTANCE_NAME, type QuotaCoordinator } from '../src/lib/quota-coordinator';
import type { EmaTenantRecord } from '../src/schemas/ema';
import { parseEnvelopeKey } from '../src/lib/kv-envelope';
import { clearKvPrefix } from './helpers/kv';

const TEST_INTERNAL_KEY = 'ema-admin-capability-test-key-32-bytes-min';
const BASE = 'http://example.com/internal/oauth/ema-tenants';
const CLAUDE_WEB_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
// 32 zero bytes, base64 — a valid KV_ENVELOPE_KEY. The upsert route refuses to run without one while OAuth is on.
const ENVELOPE_B64 = btoa(String.fromCharCode(...new Uint8Array(32)));
const ENVELOPE_KEY = parseEnvelopeKey(ENVELOPE_B64)!;

type TestEnv = typeof env & { BV_MCP_EMA_ADMIN_KEY?: string; KV_ENVELOPE_KEY?: string };

async function send(
	req: Request,
	customEnv: TestEnv = { ...env, BV_MCP_EMA_ADMIN_KEY: TEST_INTERNAL_KEY, KV_ENVELOPE_KEY: ENVELOPE_B64 } as TestEnv,
): Promise<Response> {
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
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});
afterEach(async () => {
	vi.unstubAllGlobals();
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('/internal/oauth/ema-tenants gate', () => {
	it('returns 503 when BV_MCP_EMA_ADMIN_KEY is not configured', async () => {
		const res = await send(call('GET'), { ...env, BV_MCP_EMA_ADMIN_KEY: undefined } as TestEnv);
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
			BV_MCP_EMA_ADMIN_KEY: TEST_INTERNAL_KEY,
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
		const resolved = await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/oauth2/default/');
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
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/oauth2/default')).toBeNull();
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
		const first = (await getEmaTenant(REGISTRY, 'acme-corp'))!;
		// Backdate so the update is distinguishable from the create within the same second.
		await putRegistryRecord({ ...first, created_at: 1_000, updated_at: 1_000 });
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
			BV_MCP_EMA_ADMIN_KEY: TEST_INTERNAL_KEY,
			KV_ENVELOPE_KEY: ENVELOPE_B64,
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
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/oauth2/default')).toBeNull();
		expect((await getEmaTenantByIssuer(REGISTRY, 'https://idp-b.example.com'))?.tenant_id).toBe('beta-corp');
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

describe('PUT jwks_uri outbound validation', () => {
	it.each([
		['userinfo', 'https://user:pw@idp.example.com/keys'],
		['localhost', 'https://localhost/keys'],
		['IPv4 literal', 'https://203.0.113.9/keys'],
		['IPv6 literal', 'https://[2001:db8::1]/keys'],
		['internal TLD', 'https://keys.internal/keys'],
	])('explicit %s jwks_uri -> 400, nothing stored, input not echoed', async (_label, jwksUri) => {
		const res = await send(call('PUT', '', upsertBody({ jwks_uri: jwksUri })));
		expect(res.status).toBe(400);
		expect(res.headers.get('cache-control')).toBe('no-store');
		const json = JSON.stringify(await res.json());
		expect(json.startsWith('{"error":"Invalid jwks_uri')).toBe(true);
		expect(json).not.toContain('pw@');
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/oauth2/default')).toBeNull();
	});

	it.each([
		['userinfo', 'https://user:pw@idp.example.com/keys'],
		['localhost', 'https://localhost/keys'],
		['IPv4 literal', 'https://203.0.113.9/keys'],
	])('discovered %s jwks_uri -> 400 issuer_discovery_failed and nothing stored', async (_label, jwksUri) => {
		vi.stubGlobal('fetch', async () => discoveryResponse({ issuer: 'https://idp.example.com/oauth2/default', jwks_uri: jwksUri }));
		const res = await send(call('PUT', '', upsertBody({ jwks_uri: undefined })));
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'issuer_discovery_failed' });
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/oauth2/default')).toBeNull();
	});
});

describe('PUT non-canonical issuer forms', () => {
	it('normalizes repeated trailing slashes once and fetches discovery from the stored issuer URL', async () => {
		const fetchSpy = vi.fn(async (input: RequestInfo | URL) => {
			expect(String(input)).toBe('https://idp.example.com/x/.well-known/openid-configuration');
			return discoveryResponse({ issuer: 'https://idp.example.com/x', jwks_uri: 'https://idp.example.com/x/keys' });
		});
		vi.stubGlobal('fetch', fetchSpy);
		const res = await send(call('PUT', '', upsertBody({ issuer: 'https://IDP.example.com/x//', jwks_uri: undefined })));
		expect(res.status).toBe(200);
		expect(((await res.json()) as { issuer: string }).issuer).toBe('https://idp.example.com/x');
		expect(fetchSpy).toHaveBeenCalledTimes(1);
		expect((await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/x'))?.tenant_id).toBe('acme-corp');
	});

	it('single-slash and double-slash spellings are the SAME issuer: re-PUT by the owner succeeds, another tenant gets 409', async () => {
		expect((await send(call('PUT', '', upsertBody({ issuer: 'https://idp.example.com/x//' })))).status).toBe(200);
		expect((await send(call('PUT', '', upsertBody({ issuer: 'https://idp.example.com/x/', name: 'Renamed' })))).status).toBe(200);
		const conflict = await send(call('PUT', '', upsertBody({ tenant_id: 'other-corp', issuer: 'https://IDP.example.com/x' })));
		expect(conflict.status).toBe(409);
		expect(await conflict.json()).toEqual({ error: 'issuer_conflict' });
	});
});

describe('PUT requires KV_ENVELOPE_KEY while OAuth is on', () => {
	const withoutKey = (overrides: Record<string, unknown> = {}) =>
		({ ...env, BV_MCP_EMA_ADMIN_KEY: TEST_INTERNAL_KEY, KV_ENVELOPE_KEY: undefined, ...overrides }) as unknown as TestEnv;
	const stored = () => getEmaTenant(REGISTRY, 'acme-corp');

	it('409 envelope_key_required and nothing written when the key is unset', async () => {
		const res = await send(call('PUT', '', upsertBody()), withoutKey());
		expect(res.status).toBe(409);
		expect(res.headers.get('cache-control')).toBe('no-store');
		expect(await res.json()).toEqual({ error: 'envelope_key_required' });
		expect(await stored()).toBeNull();
	});

	it('409s the same for an unparseable key (it would be ignored, so the record would be stored in plaintext)', async () => {
		const res = await send(call('PUT', '', upsertBody()), withoutKey({ KV_ENVELOPE_KEY: 'not-a-valid-key' }));
		expect(res.status).toBe(409);
		expect(await stored()).toBeNull();
	});

	it('does not apply when OAuth is off (the grant is unreachable, nothing can strand)', async () => {
		const res = await send(call('PUT', '', upsertBody()), withoutKey({ ENABLE_OAUTH: 'false' }));
		expect(res.status).toBe(200);
	});

	it('reads (GET list) are not gated by the key', async () => {
		expect((await send(call('GET'), withoutKey())).status).toBe(200);
	});
});

describe('PUT is one registry read and one registry write', () => {
	/** QUOTA_COORDINATOR wrapper that counts the EMA registry requests by kind; everything passes straight through. */
	function countingEnv(counts: Record<string, number>): TestEnv {
		const coordinator = {
			getByName: (name: string) => {
				const stub = env.QUOTA_COORDINATOR.getByName(name);
				return {
					dispatch: (request: { kind: string }) => {
						if (request.kind.startsWith('ema-')) counts[request.kind] = (counts[request.kind] ?? 0) + 1;
						return stub.dispatch(request as never);
					},
				};
			},
		} as unknown as DurableObjectNamespace<QuotaCoordinator>;
		return {
			...env,
			BV_MCP_EMA_ADMIN_KEY: TEST_INTERNAL_KEY,
			KV_ENVELOPE_KEY: ENVELOPE_B64,
			QUOTA_COORDINATOR: coordinator,
		} as unknown as TestEnv;
	}

	it('an update PUT is ONE registry write, decided on the fresh record (no separate read)', async () => {
		expect((await send(call('PUT', '', upsertBody()))).status).toBe(200);
		const counts: Record<string, number> = {};
		expect((await send(call('PUT', '', upsertBody({ name: 'Acme Renamed' })), countingEnv(counts))).status).toBe(200);
		expect(counts).toEqual({ 'ema-write': 1 });
	});

	it('the first PUT on an unmigrated registry is refused unserved, runs the one-time import, then writes once', async () => {
		const counts: Record<string, number> = {};
		expect((await send(call('PUT', '', upsertBody()), countingEnv(counts))).status).toBe(200);
		expect(counts).toEqual({ 'ema-write': 2, 'ema-migrate': 1 });
	});

	it('an issuer move releases the old index entry inside the same write', async () => {
		expect((await send(call('PUT', '', upsertBody()))).status).toBe(200);
		const moved = upsertBody({ issuer: 'https://idp-new.example.com', jwks_uri: 'https://idp-new.example.com/keys' });
		expect((await send(call('PUT', '', moved))).status).toBe(200);
		expect(await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/oauth2/default')).toBeNull();
		expect((await getEmaTenantByIssuer(REGISTRY, 'https://idp-new.example.com'))?.tenant_id).toBe('acme-corp');
	});
});

describe('PUT over an orphaned issuer index', () => {
	it('lets another tenant claim an issuer whose index points at a missing record', async () => {
		await send(call('PUT', '', upsertBody()));
		await runInDurableObject(registryShard(), (_instance, state) => state.storage.delete(emaRecordStorageKey('acme-corp')));
		const res = await send(call('PUT', '', upsertBody({ tenant_id: 'other-corp' })));
		expect(res.status).toBe(200);
		expect((await getEmaTenantByIssuer(REGISTRY, 'https://idp.example.com/oauth2/default'))?.tenant_id).toBe('other-corp');
	});
});

describe('registry or SESSION_STORE failure -> 503 ema_store_unavailable', () => {
	const boom = async () => {
		throw new Error('store unavailable');
	};
	const failingKv = () => ({ get: boom, put: boom, delete: boom, list: boom }) as unknown as KVNamespace;
	const failingCoordinator = () => ({ getByName: () => ({ dispatch: boom }) }) as unknown as DurableObjectNamespace<QuotaCoordinator>;
	const failingEnv = () =>
		({
			...env,
			BV_MCP_EMA_ADMIN_KEY: TEST_INTERNAL_KEY,
			KV_ENVELOPE_KEY: ENVELOPE_B64,
			SESSION_STORE: failingKv(),
			QUOTA_COORDINATOR: failingCoordinator(),
		}) as unknown as TestEnv;

	it.each([
		['PUT', '', upsertBody()],
		['GET', '', undefined],
		['GET', '/acme-corp', undefined],
		['DELETE', '/acme-corp', undefined],
	])('%s %s', async (method, path, body) => {
		const res = await send(call(method, path, body), failingEnv());
		expect(res.status).toBe(503);
		expect(res.headers.get('cache-control')).toBe('no-store');
		expect(res.headers.get('retry-after')).toBe('30');
		expect(await res.json()).toEqual({ error: 'ema_store_unavailable' });
	});
});

/** The registry as the Worker sees it (coordinator + the legacy-import KV and envelope key). */
const REGISTRY: EmaRegistry = { coordinator: env.QUOTA_COORDINATOR, kv: env.SESSION_STORE, kvEnvelopeKey: ENVELOPE_KEY };

const registryShard = () => env.QUOTA_COORDINATOR.getByName(EMA_REGISTRY_INSTANCE_NAME);

/** Overwrite one record directly in the registry shard (with its issuer index entry), bypassing every write rule. */
async function putRegistryRecord(rec: EmaTenantRecord): Promise<void> {
	await runInDurableObject(registryShard(), async (_instance, state) => {
		await state.storage.put(emaRecordStorageKey(rec.tenant_id), rec);
		await state.storage.put(EMA_MIGRATED_STORAGE_KEY, { at: 0, imported: 0 });
		if (effectiveApproval(rec) === 'approved') await state.storage.put(emaIssuerStorageKey(rec.issuer), rec.tenant_id);
	});
}
