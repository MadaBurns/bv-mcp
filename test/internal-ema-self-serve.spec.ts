// Route tests for the EMA self-serve seam (/internal/oauth/ema-self-serve/:tenant_id) that bv-web's
// settings page calls with the mint key, plus the operator side it depends on (admin key): approve
// (compare-and-set), reject, the ?approval filter, approval/source on the operator PUT, and the shared
// token-epoch rule. Token-path effects of approval live in test/oauth/ema-e2e.spec.ts; the shared-issuer
// table and the issuer-index rules in test/oauth/ema-tenants.spec.ts.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src';
import { OAUTH_KV_PREFIX } from '../src/lib/config';
import { getEmaTenant, getEmaTenantByIssuer, putEmaTenant } from '../src/oauth/ema-tenants';
import { parseEnvelopeKey } from '../src/lib/kv-envelope';
import type { EmaTenantRecord } from '../src/schemas/ema';
import { clearKvPrefix } from './helpers/kv';

const MINT_KEY = 'ema-mint-capability-test-key-32-bytes-min';
const ADMIN_KEY = 'ema-admin-capability-test-key-32-bytes-min';
const ORIGIN = 'http://example.com/internal/oauth';
const TENANT_ID = 'web-acme';
const ISSUER = 'https://idp.acme.example.com';
const JWKS_URI = 'https://idp.acme.example.com/keys';
const OTHER_ISSUER = 'https://idp-new.acme.example.com';
const OTHER_JWKS_URI = 'https://idp-new.acme.example.com/keys';
const CLAUDE_WEB_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const ENVELOPE_B64 = btoa(String.fromCharCode(...new Uint8Array(32)));
const ENVELOPE_KEY = parseEnvelopeKey(ENVELOPE_B64)!;
const DAY = 86_400;
const nowSeconds = () => Math.floor(Date.now() / 1000);

type TestEnv = typeof env & { BV_MCP_OAUTH_MINT_KEY?: string; BV_MCP_EMA_ADMIN_KEY?: string; KV_ENVELOPE_KEY?: string };
const baseEnv = (overrides: Record<string, unknown> = {}) =>
	({
		...env,
		BV_MCP_OAUTH_MINT_KEY: MINT_KEY,
		BV_MCP_EMA_ADMIN_KEY: ADMIN_KEY,
		KV_ENVELOPE_KEY: ENVELOPE_B64,
		...overrides,
	}) as unknown as TestEnv;

async function send(req: Request, customEnv: TestEnv = baseEnv()): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

/** A request on the door its path belongs to: self-serve with bv-web's mint key, operator routes with the admin key. */
function call(method: string, path: string, body?: unknown, headers: Record<string, string> = {}): Request {
	const bearer = path.startsWith('/ema-self-serve') ? MINT_KEY : ADMIN_KEY;
	return new Request<unknown, IncomingRequestCfProperties>(`${ORIGIN}${path}`, {
		method,
		headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}`, 'X-BV-Caller': 'ema-settings', ...headers },
		body: body === undefined || method === 'GET' || method === 'DELETE' ? undefined : JSON.stringify(body),
	});
}

const selfServePath = (tenantId = TENANT_ID) => `/ema-self-serve/${tenantId}`;

function selfServeBody(overrides: Record<string, unknown> = {}) {
	return {
		name: 'Acme Corp',
		issuer: `${ISSUER}/`,
		enabled: true,
		tier: 'enterprise',
		entitlement_expires_at: nowSeconds() + 30 * DAY,
		...overrides,
	};
}

const putSelfServe = (overrides: Record<string, unknown> = {}, tenantId = TENANT_ID) =>
	send(call('PUT', selfServePath(tenantId), selfServeBody(overrides)));

/** Operator upsert with an explicit jwks_uri (no discovery). */
const putOperator = (overrides: Record<string, unknown> = {}) =>
	send(
		call('PUT', '/ema-tenants', {
			tenant_id: 'acme-operator',
			name: 'Acme Operator',
			issuer: 'https://idp.operator.example.com',
			jwks_uri: 'https://idp.operator.example.com/keys',
			tier: 'enterprise',
			enabled: true,
			...overrides,
		}),
	);

const stored = async (tenantId = TENANT_ID): Promise<EmaTenantRecord | null> => getEmaTenant(env.SESSION_STORE!, tenantId, ENVELOPE_KEY);

/** The snapshot an operator reviews before approving. */
const reviewed = (rec: EmaTenantRecord) => ({ issuer: rec.issuer, jwks_uri: rec.jwks_uri, updated_at: rec.updated_at });

async function approve(tenantId = TENANT_ID, overrides: Record<string, unknown> = {}): Promise<Response> {
	return send(call('POST', `/ema-tenants/${tenantId}/approve`, { ...reviewed((await stored(tenantId))!), ...overrides }));
}

const reject = (tenantId = TENANT_ID) => send(call('POST', `/ema-tenants/${tenantId}/reject`));

/** Rewrite the stored record with backdated timestamps/epoch so a later change is distinguishable within one tick. */
async function backdate(tenantId = TENANT_ID): Promise<EmaTenantRecord> {
	const rec = { ...(await stored(tenantId))!, updated_at: 1_000, token_epoch: 1 };
	await putEmaTenant(env.SESSION_STORE!, rec, ENVELOPE_KEY);
	return rec;
}

/** Serves OIDC discovery for the test issuers (jwks overridable per issuer); records every fetch. */
let fetches: string[];
let discovery: Record<string, string>;
beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
	fetches = [];
	discovery = { [ISSUER]: JWKS_URI, [OTHER_ISSUER]: OTHER_JWKS_URI };
	vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
		const url = String(input);
		fetches.push(url);
		const issuer = url.replace(/\/\.well-known\/openid-configuration$/, '');
		if (!(issuer in discovery)) return new Response('not found', { status: 404 });
		return new Response(JSON.stringify({ issuer, jwks_uri: discovery[issuer] }), {
			status: 200,
			headers: { 'Content-Type': 'application/json' },
		});
	});
});
afterEach(async () => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
});

describe('EMA route gates: self-serve on the mint key, operator routes on the admin key', () => {
	const selfServeRoutes: Array<[string, string]> = [
		['PUT', selfServePath()],
		['GET', selfServePath()],
		['DELETE', selfServePath()],
	];
	const operatorRoutes: Array<[string, string]> = [
		['POST', `/ema-tenants/${TENANT_ID}/approve`],
		['POST', `/ema-tenants/${TENANT_ID}/reject`],
		['GET', '/ema-tenants?approval=pending'],
	];

	it.each(selfServeRoutes)('%s %s -> 503 when BV_MCP_OAUTH_MINT_KEY is not configured', async (method, path) => {
		const res = await send(call(method, path, selfServeBody()), baseEnv({ BV_MCP_OAUTH_MINT_KEY: undefined }));
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual({ error: 'internal_auth_not_configured' });
	});

	it.each(operatorRoutes)('%s %s -> 503 internal_auth_not_configured when BV_MCP_EMA_ADMIN_KEY is not configured', async (method, path) => {
		const res = await send(call(method, path), baseEnv({ BV_MCP_EMA_ADMIN_KEY: undefined }));
		expect(res.status).toBe(503);
		expect(res.headers.get('cache-control')).toBe('no-store');
		expect(await res.json()).toEqual({ error: 'internal_auth_not_configured' });
	});

	it.each([...selfServeRoutes, ...operatorRoutes])('%s %s -> 401 without a bearer', async (method, path) => {
		expect((await send(call(method, path, selfServeBody(), { Authorization: '' }))).status).toBe(401);
	});

	it.each(operatorRoutes)("%s %s -> 401 with bv-web's mint key (bv-web can never approve)", async (method, path) => {
		await putSelfServe();
		const res = await send(call(method, path, reviewed((await stored())!), { Authorization: `Bearer ${MINT_KEY}` }));
		expect(res.status).toBe(401);
		expect((await stored())!.approval).toBe('pending');
	});

	it.each(selfServeRoutes)('%s %s -> 401 with the admin key (each door keeps its own capability)', async (method, path) => {
		expect((await send(call(method, path, selfServeBody(), { Authorization: `Bearer ${ADMIN_KEY}` }))).status).toBe(401);
		expect(await stored()).toBeNull();
	});

	it.each([...selfServeRoutes, ...operatorRoutes])(
		'%s %s -> 404 from the public internet (cf-connecting-ip present)',
		async (method, path) => {
			expect((await send(call(method, path, selfServeBody(), { 'cf-connecting-ip': '203.0.113.9' }))).status).toBe(404);
			expect(await stored()).toBeNull();
		},
	);
});

describe('PUT /internal/oauth/ema-self-serve/:tenant_id', () => {
	it('creates a pending, self-serve tenant with the discovered jwks_uri and the default client, and answers the redacted view', async () => {
		const before = Date.now();
		const expires = nowSeconds() + 30 * DAY;
		const res = await putSelfServe({ entitlement_expires_at: expires });
		expect(res.status).toBe(200);
		expect(res.headers.get('cache-control')).toBe('no-store');
		const view = (await res.json()) as Record<string, unknown>;
		expect(Object.keys(view).sort()).toEqual([
			'approval',
			'enabled',
			'entitlement_expires_at',
			'issuer',
			'name',
			'tenant_id',
			'tier',
			'updated_at',
		]);
		expect(view).toMatchObject({
			tenant_id: TENANT_ID,
			name: 'Acme Corp',
			issuer: ISSUER,
			enabled: true,
			approval: 'pending',
			tier: 'enterprise',
			entitlement_expires_at: expires,
		});
		expect(fetches).toEqual([`${ISSUER}/.well-known/openid-configuration`]);

		const record = (await stored())!;
		expect(record).toMatchObject({
			source: 'self-serve',
			approval: 'pending',
			jwks_uri: JWKS_URI,
			allowed_client_ids: [CLAUDE_WEB_CLIENT_ID],
		});
		expect(record.token_epoch).toBeGreaterThanOrEqual(before);
		// Pending: not indexed, so the token grant cannot resolve the issuer yet.
		expect(await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY)).toBeNull();
	});

	it.each([
		['jwks_uri', { jwks_uri: 'https://attacker.example/keys' }],
		['allowed_client_ids', { allowed_client_ids: ['https://attacker.example/client'] }],
		['approval', { approval: 'approved' }],
		['source', { source: 'operator' }],
		['token_epoch', { token_epoch: 1 }],
		['tenant_id', { tenant_id: 'someone-else' }],
		['created_at', { created_at: 1 }],
	])('400 on a body that sets server-decided %s: nothing stored, no discovery', async (field, patch) => {
		const res = await putSelfServe(patch);
		expect(res.status).toBe(400);
		const body = (await res.json()) as { error: string };
		expect(body).toEqual({ error: 'Invalid request body: unrecognized field' });
		expect(JSON.stringify(body)).not.toContain(field);
		expect(await stored()).toBeNull();
		expect(fetches).toEqual([]);
	});

	it.each([
		['owner tier', { tier: 'owner' }, 'Invalid tier'],
		['http issuer', { issuer: 'http://idp.acme.example.com' }, 'Invalid issuer'],
		['missing name', { name: undefined }, 'Invalid name'],
		['non-boolean enabled', { enabled: 'yes' }, 'Invalid enabled'],
		['missing entitlement', { entitlement_expires_at: undefined }, 'Invalid entitlement_expires_at'],
		['non-integer entitlement', { entitlement_expires_at: 1_900_000_000.5 }, 'Invalid entitlement_expires_at'],
		['entitlement past the 400-day horizon', { entitlement_expires_at: nowSeconds() + 401 * DAY }, 'Invalid entitlement_expires_at'],
	])('400 on %s using the zod issue-path convention', async (_label, patch, prefix) => {
		const res = await putSelfServe(patch);
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error.startsWith(prefix)).toBe(true);
		expect(await stored()).toBeNull();
	});

	it('accepts a past entitlement (bv-web revoking): stored, but the tenant is lapsed', async () => {
		const res = await putSelfServe({ entitlement_expires_at: nowSeconds() - DAY });
		expect(res.status).toBe(200);
	});

	it('400 issuer_discovery_failed when the issuer publishes no matching discovery document', async () => {
		const res = await putSelfServe({ issuer: 'https://unknown-idp.example' });
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'issuer_discovery_failed' });
		expect(await stored()).toBeNull();
	});

	it.each([
		'https://login.microsoftonline.com/common/v2.0',
		'https://login.windows.net/organizations/v2.0',
		'https://login.microsoftonline.com/{tenantid}/v2.0',
		'https://accounts.google.com',
		'https://login.live.com',
		'https://appleid.apple.com',
		'https://idp.xaa.dev',
		'https://token.actions.githubusercontent.com',
		'https://securetoken.google.com/a-project',
		'https://contoso.b2clogin.com/a-tenant/v2.0',
	])('400 issuer_not_allowed for the shared issuer %s, before any network call', async (issuer) => {
		const res = await putSelfServe({ issuer });
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'issuer_not_allowed' });
		expect(fetches).toEqual([]);
		expect(await stored()).toBeNull();
	});

	it('accepts a per-tenant Entra issuer (the near miss of the shared table)', async () => {
		const entra = 'https://login.microsoftonline.com/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/v2.0';
		discovery[entra] = 'https://login.microsoftonline.com/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee/discovery/v2.0/keys';
		const res = await putSelfServe({ issuer: entra });
		expect(res.status).toBe(200);
		expect(((await res.json()) as { approval: string }).approval).toBe('pending');
	});

	it('400 when the tenant_id is not a web- id the EMA pattern accepts, before reading the body', async () => {
		for (const bad of ['acme-corp', 'WEB-ACME', 'web', `web-${'x'.repeat(60)}`]) {
			const res = await putSelfServe({}, bad);
			expect(res.status).toBe(400);
			expect(((await res.json()) as { error: string }).error.startsWith('Invalid tenant_id')).toBe(true);
		}
		expect(fetches).toEqual([]);
	});

	it('409 envelope_key_required and nothing written while OAuth is on without KV_ENVELOPE_KEY', async () => {
		const res = await send(call('PUT', selfServePath(), selfServeBody()), baseEnv({ KV_ENVELOPE_KEY: undefined }));
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'envelope_key_required' });
		expect((await env.SESSION_STORE!.list({ prefix: `${OAUTH_KV_PREFIX}ema-` })).keys).toEqual([]);
	});

	it('a routine renewal (same issuer, same keys) keeps the approval and the token epoch, and applies the new fields', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		const { token_epoch: epoch } = await backdate();

		const res = await putSelfServe({
			name: 'Acme Renamed',
			tier: 'developer',
			issuer: 'https://IDP.acme.example.com//',
			entitlement_expires_at: nowSeconds() + 90 * DAY,
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ name: 'Acme Renamed', tier: 'developer', approval: 'approved' });
		expect((await stored())!.token_epoch).toBe(epoch);
		expect((await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY))?.tenant_id).toBe(TENANT_ID);
	});

	it('a still-pending tenant stays pending across an update', async () => {
		await putSelfServe();
		expect(((await (await putSelfServe({ enabled: false })).json()) as { approval: string }).approval).toBe('pending');
	});

	it('an issuer change returns an approved tenant to pending, moves the token epoch and releases the issuer', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		await backdate();

		const res = await putSelfServe({ issuer: OTHER_ISSUER });
		expect(await res.json()).toMatchObject({ issuer: OTHER_ISSUER, approval: 'pending' });
		const record = (await stored())!;
		expect(record.jwks_uri).toBe(OTHER_JWKS_URI);
		expect(record.token_epoch).toBeGreaterThan(1);
		expect(await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY)).toBeNull();
		expect(await getEmaTenantByIssuer(env.SESSION_STORE!, OTHER_ISSUER, ENVELOPE_KEY)).toBeNull();
	});

	it('changed keys on rediscovery return an approved tenant to pending and move the epoch', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		await backdate();
		discovery[ISSUER] = 'https://idp.acme.example.com/rotated-keys';

		expect(((await (await putSelfServe()).json()) as { approval: string }).approval).toBe('pending');
		const record = (await stored())!;
		expect(record.jwks_uri).toBe('https://idp.acme.example.com/rotated-keys');
		expect(record.token_epoch).toBeGreaterThan(1);
		expect(await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY)).toBeNull();
	});

	it('rejected is sticky on the same issuer (even with new keys) and returns to pending on a new issuer', async () => {
		await putSelfServe();
		expect((await reject()).status).toBe(200);
		expect(((await (await putSelfServe({ name: 'Try again' })).json()) as { approval: string }).approval).toBe('rejected');
		discovery[ISSUER] = 'https://idp.acme.example.com/rotated-keys';
		expect(((await (await putSelfServe()).json()) as { approval: string }).approval).toBe('rejected');
		expect(((await (await putSelfServe({ issuer: OTHER_ISSUER })).json()) as { approval: string }).approval).toBe('pending');
	});

	it('409 tenant_managed_by_operator on an operator-seeded tenant, and on a legacy record with no source; neither changes', async () => {
		expect((await putOperator({ tenant_id: TENANT_ID })).status).toBe(200);
		const operatorRecord = await stored();
		const res = await putSelfServe();
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'tenant_managed_by_operator' });
		expect(await stored()).toEqual(operatorRecord);

		const { source: _dropped, ...legacy } = operatorRecord!;
		await putEmaTenant(env.SESSION_STORE!, legacy, ENVELOPE_KEY);
		expect((await putSelfServe()).status).toBe(409);
		expect(await stored()).toEqual(legacy);
	});

	it('never answers issuer_conflict: pending claimants may share an issuer, even one an approved tenant holds', async () => {
		expect((await putOperator({ issuer: ISSUER, jwks_uri: JWKS_URI })).status).toBe(200);
		expect((await putSelfServe({}, 'web-first')).status).toBe(200);
		expect((await putSelfServe({}, 'web-second')).status).toBe(200);
		// The approved operator tenant still owns the issuer.
		expect((await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY))?.tenant_id).toBe('acme-operator');
	});

	it('503 ema_store_unavailable on an existing record it cannot read, and the record is not overwritten', async () => {
		const key = `${OAUTH_KV_PREFIX}ema-tenant:${TENANT_ID}`;
		await env.SESSION_STORE!.put(key, 'not-a-sealed-record');
		const res = await putSelfServe();
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual({ error: 'ema_store_unavailable' });
		expect(await env.SESSION_STORE!.get(key)).toBe('not-a-sealed-record');
	});
});

describe('GET /internal/oauth/ema-self-serve/:tenant_id', () => {
	it('answers the redacted view of a self-serve tenant', async () => {
		await putSelfServe();
		const res = await send(call('GET', selfServePath()));
		expect(res.status).toBe(200);
		expect(res.headers.get('cache-control')).toBe('no-store');
		const view = (await res.json()) as Record<string, unknown>;
		for (const hidden of ['jwks_uri', 'allowed_client_ids', 'token_epoch', 'source', 'created_at']) expect(view).not.toHaveProperty(hidden);
		expect(view).toMatchObject({ tenant_id: TENANT_ID, issuer: ISSUER, approval: 'pending' });
	});

	it('404 not_found when absent or operator-managed (never reveals an operator record); 400 on a non-web id', async () => {
		expect(await (await send(call('GET', selfServePath()))).json()).toEqual({ error: 'not_found' });
		expect((await send(call('GET', selfServePath('acme-corp')))).status).toBe(400);
		await putOperator({ tenant_id: TENANT_ID });
		const res = await send(call('GET', selfServePath()));
		expect(res.status).toBe(404);
		expect(await res.json()).toEqual({ error: 'not_found' });
	});
});

describe('DELETE /internal/oauth/ema-self-serve/:tenant_id', () => {
	it('removes a self-serve tenant and its issuer index, and is idempotent', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		const res = await send(call('DELETE', selfServePath()));
		expect(res.status).toBe(204);
		expect(res.headers.get('cache-control')).toBe('no-store');
		expect(await stored()).toBeNull();
		expect(await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY)).toBeNull();
		expect((await send(call('DELETE', selfServePath()))).status).toBe(204);
	});

	it('409 tenant_managed_by_operator on an operator-seeded tenant, which survives', async () => {
		await putOperator({ tenant_id: TENANT_ID });
		const res = await send(call('DELETE', selfServePath()));
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'tenant_managed_by_operator' });
		expect((await stored())?.tenant_id).toBe(TENANT_ID);
	});

	it('503 on a record it cannot read, which survives', async () => {
		const key = `${OAUTH_KV_PREFIX}ema-tenant:${TENANT_ID}`;
		await env.SESSION_STORE!.put(key, 'not-a-sealed-record');
		expect((await send(call('DELETE', selfServePath()))).status).toBe(503);
		expect(await env.SESSION_STORE!.get(key)).toBe('not-a-sealed-record');
	});
});

describe('POST /internal/oauth/ema-tenants/:tenant_id/approve and /reject', () => {
	it('approve sets approved, claims the issuer, answers the full record, and leaves the token epoch alone', async () => {
		await putSelfServe();
		const epoch = (await stored())!.token_epoch;
		const res = await approve();
		expect(res.status).toBe(200);
		expect(res.headers.get('cache-control')).toBe('no-store');
		expect(await res.json()).toMatchObject({
			tenant_id: TENANT_ID,
			approval: 'approved',
			source: 'self-serve',
			jwks_uri: JWKS_URI,
			token_epoch: epoch,
		});
		expect((await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY))?.tenant_id).toBe(TENANT_ID);
		// Idempotent with a fresh snapshot.
		expect((await approve()).status).toBe(200);
	});

	it.each([
		['issuer', { issuer: OTHER_ISSUER }],
		['jwks_uri', { jwks_uri: 'https://idp.acme.example.com/other-keys' }],
		['updated_at', { updated_at: 1 }],
	])('409 approval_stale when the reviewed %s no longer matches; nothing changes', async (_label, drift) => {
		await putSelfServe();
		const before = await stored();
		const res = await approve(TENANT_ID, drift);
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'approval_stale' });
		expect(await stored()).toEqual(before);
	});

	it('an approval of a snapshot the customer has since changed is stale (review-then-swap)', async () => {
		await putSelfServe();
		const snapshot = reviewed((await stored())!);
		await putSelfServe({ issuer: OTHER_ISSUER });
		const res = await send(call('POST', `/ema-tenants/${TENANT_ID}/approve`, snapshot));
		expect(res.status).toBe(409);
		expect((await stored())!.approval).toBe('pending');
	});

	it.each([
		['no body', undefined],
		['a missing field', { issuer: ISSUER, jwks_uri: JWKS_URI }],
		['an extra field', { issuer: ISSUER, jwks_uri: JWKS_URI, updated_at: 1, approval: 'approved' }],
	])('400 on an approve with %s', async (_label, body) => {
		await putSelfServe();
		expect((await send(call('POST', `/ema-tenants/${TENANT_ID}/approve`, body))).status).toBe(400);
		expect((await stored())!.approval).toBe('pending');
	});

	it('409 issuer_conflict when another APPROVED tenant holds the issuer; approving after it leaves works', async () => {
		await putSelfServe({}, 'web-first');
		await putSelfServe({}, 'web-second');
		expect((await approve('web-first')).status).toBe(200);
		const res = await approve('web-second');
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'issuer_conflict' });
		expect((await stored('web-second'))!.approval).toBe('pending');

		expect((await reject('web-first')).status).toBe(200);
		expect((await approve('web-second')).status).toBe(200);
		expect((await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY))?.tenant_id).toBe('web-second');
	});

	it('reject is sticky, releases the issuer, and moves the epoch of an approved tenant', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		await backdate();
		const res = await reject();
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ approval: 'rejected' });
		expect((await stored())!.token_epoch).toBeGreaterThan(1);
		expect(await getEmaTenantByIssuer(env.SESSION_STORE!, ISSUER, ENVELOPE_KEY)).toBeNull();
	});

	it('404 not_found for an absent or malformed tenant', async () => {
		const missing = await send(call('POST', '/ema-tenants/missing-tenant/approve', { issuer: ISSUER, jwks_uri: JWKS_URI, updated_at: 1 }));
		expect(missing.status).toBe(404);
		expect(await missing.json()).toEqual({ error: 'not_found' });
		expect((await send(call('POST', '/ema-tenants/missing-tenant/reject'))).status).toBe(404);
		expect((await send(call('POST', '/ema-tenants/NOT_VALID/reject'))).status).toBe(404);
	});

	it('409 envelope_key_required while OAuth is on without KV_ENVELOPE_KEY (they are writes)', async () => {
		await putSelfServe();
		const snapshot = reviewed((await stored())!);
		const noKey = baseEnv({ KV_ENVELOPE_KEY: undefined });
		expect((await send(call('POST', `/ema-tenants/${TENANT_ID}/approve`, snapshot), noKey)).status).toBe(409);
		expect((await send(call('POST', `/ema-tenants/${TENANT_ID}/reject`), noKey)).status).toBe(409);
		expect((await stored())!.approval).toBe('pending');
	});
});

describe('GET /internal/oauth/ema-tenants?approval=', () => {
	beforeEach(async () => {
		await putSelfServe();
		await putSelfServe({ issuer: OTHER_ISSUER }, 'web-beta');
		await approve('web-beta');
		discovery['https://idp-c.acme.example.com'] = 'https://idp-c.acme.example.com/keys';
		await putSelfServe({ issuer: 'https://idp-c.acme.example.com' }, 'web-gamma');
		await reject('web-gamma');
		await putOperator();
	});

	const listed = async (query: string) => {
		const res = await send(call('GET', `/ema-tenants${query}`));
		expect(res.status).toBe(200);
		const body = (await res.json()) as { tenants: Array<{ tenant_id: string }>; total: number };
		return { ids: body.tenants.map((t) => t.tenant_id).sort(), total: body.total };
	};

	it('filters to the review queue, the approved set (records without approval count as approved) and the rejected set', async () => {
		expect(await listed('?approval=pending')).toEqual({ ids: [TENANT_ID], total: 1 });
		expect(await listed('?approval=approved')).toEqual({ ids: ['acme-operator', 'web-beta'], total: 2 });
		expect(await listed('?approval=rejected')).toEqual({ ids: ['web-gamma'], total: 1 });
		expect((await listed('')).total).toBe(4);
	});

	it('400 on an unknown approval value', async () => {
		const res = await send(call('GET', '/ema-tenants?approval=bogus'));
		expect(res.status).toBe(400);
		expect(((await res.json()) as { error: string }).error.startsWith('Invalid approval')).toBe(true);
	});
});

describe('operator PUT: approval, source and the shared token epoch', () => {
	it('a new operator tenant is source operator with no approval (reads as approved); an omitted approval keeps the stored one', async () => {
		const created = (await (await putOperator()).json()) as Record<string, unknown>;
		expect(created.source).toBe('operator');
		expect(created).not.toHaveProperty('approval');

		expect(((await (await putOperator({ approval: 'pending' })).json()) as { approval: string }).approval).toBe('pending');
		expect(((await (await putOperator({ name: 'Renamed' })).json()) as { approval: string }).approval).toBe('pending');
	});

	it('an operator edit of a self-serve tenant keeps it self-serve and keeps its approval', async () => {
		await putSelfServe();
		const res = await send(
			call('PUT', '/ema-tenants', {
				tenant_id: TENANT_ID,
				name: 'Fixed by ops',
				issuer: ISSUER,
				jwks_uri: JWKS_URI,
				tier: 'enterprise',
				enabled: true,
			}),
		);
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ source: 'self-serve', approval: 'pending', name: 'Fixed by ops' });
		expect((await putSelfServe()).status).toBe(200);
	});

	it('400 on an operator body that sets source (server-managed)', async () => {
		expect((await putOperator({ source: 'self-serve' })).status).toBe(400);
		expect(await stored('acme-operator')).toBeNull();
	});

	it.each([
		['issuer change', { issuer: 'https://idp2.operator.example.com', jwks_uri: 'https://idp2.operator.example.com/keys' }],
		['jwks_uri change', { jwks_uri: 'https://idp.operator.example.com/rotated' }],
		['approved -> pending', { approval: 'pending' }],
	])('moves the token epoch on an operator %s', async (_label, patch) => {
		expect((await putOperator()).status).toBe(200);
		await backdate('acme-operator');
		expect((await putOperator(patch)).status).toBe(200);
		expect((await stored('acme-operator'))!.token_epoch).toBeGreaterThan(1);
	});

	it('keeps the token epoch on an operator same-issuer, same-keys renewal', async () => {
		expect((await putOperator()).status).toBe(200);
		await backdate('acme-operator');
		expect((await putOperator({ entitlement_expires_at: nowSeconds() + 90 * DAY })).status).toBe(200);
		expect((await stored('acme-operator'))!.token_epoch).toBe(1);
	});
});

describe('ema_tenant_mutation log line', () => {
	function mutationDetails(spy: ReturnType<typeof vi.spyOn>): unknown[] {
		return spy.mock.calls
			.map((args: unknown[]) => JSON.parse(String(args[0])) as Record<string, unknown>)
			.filter((line: Record<string, unknown>) => line.result === 'ema_tenant_mutation')
			.map((line: Record<string, unknown>) => line.details);
	}

	it('logs one line per self-serve upsert and delete and per approve/reject, with ids and state but no issuer or key material', async () => {
		const spy = vi.spyOn(console, 'log');
		await putSelfServe();
		await approve();
		await reject();
		await send(call('DELETE', selfServePath()));
		expect(mutationDetails(spy)).toEqual([
			{ tenant_id: TENANT_ID, action: 'upsert', source: 'self-serve', approval: 'pending' },
			{ tenant_id: TENANT_ID, action: 'approve', source: 'self-serve', approval: 'approved' },
			{ tenant_id: TENANT_ID, action: 'reject', source: 'self-serve', approval: 'rejected' },
			{ tenant_id: TENANT_ID, action: 'delete', source: 'self-serve', approval: 'rejected' },
		]);
		const text = JSON.stringify(spy.mock.calls.filter((args: unknown[]) => String(args[0]).includes('ema_tenant_mutation')));
		for (const secret of ['idp.acme.example.com', JWKS_URI, MINT_KEY, ADMIN_KEY]) expect(text).not.toContain(secret);
	});

	it('does not log a refused mutation, and logs a delete of nothing with the id and action only', async () => {
		await putOperator({ tenant_id: TENANT_ID });
		const spy = vi.spyOn(console, 'log');
		await putSelfServe();
		expect(mutationDetails(spy)).toEqual([]);
		await send(call('DELETE', selfServePath('web-nobody')));
		expect(mutationDetails(spy)).toEqual([{ tenant_id: 'web-nobody', action: 'delete' }]);
	});
});

describe('SESSION_STORE failure -> 503 ema_store_unavailable', () => {
	const boom = async () => {
		throw new Error('KV unavailable');
	};
	const failingEnv = () => baseEnv({ SESSION_STORE: { get: boom, put: boom, delete: boom, list: boom } });

	it.each([
		['PUT', selfServePath(), selfServeBody()],
		['GET', selfServePath(), undefined],
		['DELETE', selfServePath(), undefined],
		['POST', `/ema-tenants/${TENANT_ID}/approve`, { issuer: ISSUER, jwks_uri: JWKS_URI, updated_at: 1 }],
		['POST', `/ema-tenants/${TENANT_ID}/reject`, undefined],
		['GET', '/ema-tenants?approval=pending', undefined],
	])('%s %s', async (method, path, body) => {
		const res = await send(call(method, path, body), failingEnv());
		expect(res.status).toBe(503);
		expect(res.headers.get('retry-after')).toBe('30');
		expect(await res.json()).toEqual({ error: 'ema_store_unavailable' });
	});

	it('500 session_store_not_configured when SESSION_STORE is unbound', async () => {
		const res = await send(call('GET', selfServePath()), baseEnv({ SESSION_STORE: undefined }));
		expect(res.status).toBe(500);
		expect(await res.json()).toEqual({ error: 'session_store_not_configured' });
	});
});
