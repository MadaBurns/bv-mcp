// Route tests for the EMA self-serve seam (/internal/oauth/ema-self-serve/:tenant_id) that bv-web's
// settings page calls with the mint key, plus the operator side it depends on (admin key): approve
// (compare-and-set), reject, the ?approval filter, approval/source on the operator PUT, and the shared
// token-epoch rule. Token-path effects of approval live in test/oauth/ema-e2e.spec.ts; the shared-issuer
// table and the issuer-index rules in test/oauth/ema-tenants.spec.ts.

import { env, createExecutionContext, runInDurableObject, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src';
import { OAUTH_KV_PREFIX } from '../src/lib/config';
import {
	EMA_REGISTRY_KEY,
	effectiveApproval,
	emaEpochFloorStorageKey,
	emaIssuerStorageKey,
	emaRecordStorageKey,
	getEmaTenant,
	getEmaTenantByIssuer,
	isEmaTokenLive,
	isTenantActive,
	issuerHash,
	tenantEpoch,
	type EmaRegistry,
} from '../src/oauth/ema-tenants';
import { resetQuotaCoordinatorState, securityStateShardNameForKey } from '../src/lib/quota-coordinator';
import { parseEnvelopeKey, sealKv } from '../src/lib/kv-envelope';
import type { EmaTenantRecord } from '../src/schemas/ema';
import { clearKvPrefix } from './helpers/kv';

const MINT_KEY = 'ema-mint-capability-test-key-32-bytes-min';
const ADMIN_KEY = 'ema-admin-capability-test-key-32-bytes-min';
const ORIGIN = 'http://example.com/internal/oauth';
const TENANT_ID = 'web-acme-corp-0001';
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

const sendSelfServe = (method: 'GET' | 'DELETE', tenantId = TENANT_ID) => send(call(method, selfServePath(tenantId)));

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

const stored = async (tenantId = TENANT_ID): Promise<EmaTenantRecord | null> => getEmaTenant(REGISTRY, tenantId);

/** The snapshot an operator reviews before approving. */
const reviewed = (rec: EmaTenantRecord) => ({ issuer: rec.issuer, jwks_uri: rec.jwks_uri, updated_at: rec.updated_at });

async function approve(tenantId = TENANT_ID, overrides: Record<string, unknown> = {}): Promise<Response> {
	return send(call('POST', `/ema-tenants/${tenantId}/approve`, { ...reviewed((await stored(tenantId))!), ...overrides }));
}

const reject = (tenantId = TENANT_ID) => send(call('POST', `/ema-tenants/${tenantId}/reject`));

/** Rewrite the stored record with a backdated updated_at so a later change is distinguishable within one tick. */
async function backdate(tenantId = TENANT_ID): Promise<EmaTenantRecord> {
	const rec = { ...(await stored(tenantId))!, updated_at: 1_000 };
	await putRegistryRecord(rec);
	return rec;
}

/**
 * The epoch a token for the tenant must carry right now: the registry record's own, or, for a deleted id, the
 * one a re-created tenant would start at (one past the id's epoch floor), which no earlier token carries.
 */
async function epoch(tenantId = TENANT_ID): Promise<number> {
	const rec = await stored(tenantId);
	if (rec) return tenantEpoch(rec);
	return runInDurableObject(registryShard(), async (_instance, state) => {
		const floor = await state.storage.get<{ value: number }>(emaEpochFloorStorageKey(tenantId));
		return (floor?.value ?? 0) + 1;
	});
}

/** Whether a token minted at `tep` still stands for `tenantId` (liveness, as the bearer path runs it). */
const tokenLive = (tep: number, tenantId = TENANT_ID, tier = 'enterprise'): Promise<boolean> =>
	isEmaTokenLive(REGISTRY, { sub: `ema:${tenantId}:${'0'.repeat(32)}`, tier, tep }, nowSeconds());

/** Hold every outbound fetch (discovery) open until released, then serve it from the stub installed by beforeEach. */
function holdDiscovery(): { release: () => void; started: () => number } {
	const served = globalThis.fetch;
	let release!: () => void;
	let started = 0;
	const gate = new Promise<void>((resolve) => (release = resolve));
	vi.stubGlobal('fetch', async (input: RequestInfo | URL) => {
		started++;
		await gate;
		return served(input);
	});
	return { release, started: () => started };
}

/** Serves OIDC discovery for the test issuers (jwks overridable per issuer); records every fetch. */
let fetches: string[];
let discovery: Record<string, string>;
beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, OAUTH_KV_PREFIX);
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
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
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
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
		expect(record.token_epoch).toBe(await epoch());
		// Pending: not indexed, so the token grant cannot resolve the issuer yet.
		expect(await getEmaTenantByIssuer(REGISTRY, ISSUER)).toBeNull();
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
		'https://gitlab.com',
		'https://login.microsoftonline.com',
		'https://login.microsoftonline.com/%2Fcommon/v2.0',
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

	it('needs at least 8 characters after web- (7 is a 400 on every self-serve verb, 8 is accepted)', async () => {
		for (const attempt of [
			() => putSelfServe({}, 'web-1234567'),
			() => sendSelfServe('GET', 'web-1234567'),
			() => sendSelfServe('DELETE', 'web-1234567'),
		]) {
			expect((await attempt()).status).toBe(400);
		}
		expect(await stored('web-1234567')).toBeNull();
		expect((await putSelfServe({}, 'web-12345678')).status).toBe(200);
	});

	it('409 envelope_key_required and nothing written while OAuth is on without KV_ENVELOPE_KEY', async () => {
		const res = await send(call('PUT', selfServePath(), selfServeBody()), baseEnv({ KV_ENVELOPE_KEY: undefined }));
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'envelope_key_required' });
		expect(await stored()).toBeNull();
	});

	it('a routine renewal (same issuer, same keys) keeps the approval and the token epoch, and applies the new fields', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		await backdate();
		const before = await epoch();

		const res = await putSelfServe({
			name: 'Acme Renamed',
			issuer: 'https://IDP.acme.example.com//',
			entitlement_expires_at: nowSeconds() + 90 * DAY,
		});
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ name: 'Acme Renamed', tier: 'enterprise', approval: 'approved' });
		expect(await epoch()).toBe(before);
		expect((await getEmaTenantByIssuer(REGISTRY, ISSUER))?.tenant_id).toBe(TENANT_ID);
		// A tier change, even a downgrade, revokes (SQ-467 F2): the epoch moves, so no round trip can revive a token.
		expect((await putSelfServe({ tier: 'developer', entitlement_expires_at: nowSeconds() + 90 * DAY })).status).toBe(200);
		expect(await epoch()).toBeGreaterThan(before);
	});

	it('a still-pending tenant stays pending across an update', async () => {
		await putSelfServe();
		expect(((await (await putSelfServe({ enabled: false })).json()) as { approval: string }).approval).toBe('pending');
	});

	it('an issuer change returns an approved tenant to pending, moves the token epoch and releases the issuer', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		await backdate();
		const before = await epoch();

		const res = await putSelfServe({ issuer: OTHER_ISSUER });
		expect(await res.json()).toMatchObject({ issuer: OTHER_ISSUER, approval: 'pending' });
		const record = (await stored())!;
		expect(record.jwks_uri).toBe(OTHER_JWKS_URI);
		expect(await epoch()).toBeGreaterThan(before);
		expect(record.token_epoch).toBe(await epoch());
		expect(await getEmaTenantByIssuer(REGISTRY, ISSUER)).toBeNull();
		expect(await getEmaTenantByIssuer(REGISTRY, OTHER_ISSUER)).toBeNull();
	});

	it('changed keys on rediscovery return an approved tenant to pending and move the epoch', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		await backdate();
		const before = await epoch();
		discovery[ISSUER] = 'https://idp.acme.example.com/rotated-keys';

		expect(((await (await putSelfServe()).json()) as { approval: string }).approval).toBe('pending');
		const record = (await stored())!;
		expect(record.jwks_uri).toBe('https://idp.acme.example.com/rotated-keys');
		expect(await epoch()).toBeGreaterThan(before);
		expect(record.token_epoch).toBe(await epoch());
		expect(await getEmaTenantByIssuer(REGISTRY, ISSUER)).toBeNull();
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
		// Refused before discovery: an issuer that publishes nothing still answers 409, and nothing was fetched.
		expect((await putSelfServe({ issuer: 'https://unknown-idp.example' })).status).toBe(409);
		expect(fetches).toEqual([]);

		const { source: _dropped, ...legacy } = operatorRecord!;
		await putRegistryRecord(legacy);
		expect((await putSelfServe()).status).toBe(409);
		expect(await stored()).toEqual(legacy);
	});

	it('never answers issuer_conflict: pending claimants may share an issuer, even one an approved tenant holds', async () => {
		expect((await putOperator({ issuer: ISSUER, jwks_uri: JWKS_URI })).status).toBe(200);
		expect((await putSelfServe({}, 'web-first-tenant')).status).toBe(200);
		expect((await putSelfServe({}, 'web-second-tenant')).status).toBe(200);
		// The approved operator tenant still owns the issuer.
		expect((await getEmaTenantByIssuer(REGISTRY, ISSUER))?.tenant_id).toBe('acme-operator');
	});

	it('503 ema_store_unavailable on an existing record it cannot read, and the record is not overwritten', async () => {
		const key = `${OAUTH_KV_PREFIX}ema-tenant:${TENANT_ID}`;
		const unreadable = await plantUnreadableLegacy(TENANT_ID);
		const res = await putSelfServe();
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual({ error: 'ema_store_unavailable' });
		expect(await env.SESSION_STORE!.get(key)).toBe(unreadable);
		// Refused before discovery.
		expect(fetches).toEqual([]);
	});
});

describe('a PUT that only lowers privilege needs no discovery (a revoke must land while the IdP is down)', () => {
	/** An approved, backdated tenant, then the issuer's discovery document disappears. */
	async function approvedWithDiscoveryGone(overrides: Record<string, unknown> = {}): Promise<EmaTenantRecord> {
		await putSelfServe(overrides);
		expect((await approve()).status).toBe(200);
		const before = await backdate();
		delete discovery[ISSUER];
		fetches.length = 0;
		return before;
	}
	const active = async () => isTenantActive((await stored())!, nowSeconds());

	it('enabled true -> false keeps the approval and the stored jwks_uri, moves the epoch, and is inactive at token exchange', async () => {
		await approvedWithDiscoveryGone();
		const before = await epoch();
		expect(await active()).toBe(true);
		const res = await putSelfServe({ enabled: false });
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ enabled: false, approval: 'approved' });
		expect(fetches).toEqual([]);
		const record = (await stored())!;
		expect(record.jwks_uri).toBe(JWKS_URI);
		expect(await epoch()).toBeGreaterThan(before);
		expect(record.token_epoch).toBe(await epoch());
		expect(await active()).toBe(false);
		// The token path resolves the tenant by issuer, then refuses it as inactive.
		expect(isTenantActive((await getEmaTenantByIssuer(REGISTRY, ISSUER))!, nowSeconds())).toBe(false);
	});

	it('a past entitlement_expires_at is stored the same way and lapses the tenant', async () => {
		await approvedWithDiscoveryGone();
		const res = await putSelfServe({ entitlement_expires_at: nowSeconds() - DAY });
		expect(res.status).toBe(200);
		expect(fetches).toEqual([]);
		expect((await stored())!.jwks_uri).toBe(JWKS_URI);
		expect(await active()).toBe(false);
	});

	it('an earlier (still future) expiry is lowering too, and repeating a revoke is idempotent', async () => {
		await approvedWithDiscoveryGone();
		const soon = nowSeconds() + DAY;
		expect((await putSelfServe({ entitlement_expires_at: soon })).status).toBe(200);
		expect(await active()).toBe(true);
		expect((await putSelfServe({ enabled: false, entitlement_expires_at: soon })).status).toBe(200);
		expect((await putSelfServe({ enabled: false, entitlement_expires_at: soon })).status).toBe(200);
		expect(fetches).toEqual([]);
		expect(await active()).toBe(false);
	});

	it.each([
		['the discovery document is gone', (): void => void delete discovery[ISSUER]],
		['discovery serves rotated keys', (): void => void (discovery[ISSUER] = 'https://idp.acme.example.com/rotated-keys')],
	])(
		'a disable is lowering WHATEVER expiry rides along (bv-web recomputes a LATER one): no discovery, no re-pend, epoch moves (%s)',
		async (_label, breakDiscovery) => {
			await putSelfServe();
			expect((await approve()).status).toBe(200);
			const approved = (await stored())!;
			const before = await epoch();
			breakDiscovery();
			fetches.length = 0;

			const res = await putSelfServe({ enabled: false, entitlement_expires_at: approved.entitlement_expires_at! + 5 * DAY });
			expect(res.status).toBe(200);
			expect(await res.json()).toMatchObject({ enabled: false, approval: 'approved' });
			expect(fetches).toEqual([]);
			const record = (await stored())!;
			expect(record.jwks_uri).toBe(JWKS_URI);
			expect(record.entitlement_expires_at).toBe(approved.entitlement_expires_at! + 5 * DAY);
			expect(await active()).toBe(false);
			expect(await epoch()).toBeGreaterThan(before);
			expect(record.token_epoch).toBe(await epoch());
		},
	);

	it('a re-enable still needs discovery: 400 issuer_discovery_failed, and the tenant stays disabled', async () => {
		await approvedWithDiscoveryGone();
		expect((await putSelfServe({ enabled: false })).status).toBe(200);
		const res = await putSelfServe({ enabled: true });
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'issuer_discovery_failed' });
		expect((await stored())!.enabled).toBe(false);
	});

	it.each([
		['a tier increase', { tier: 'enterprise' }, 'developer'],
		['an expiry extension', { entitlement_expires_at: nowSeconds() + 60 * DAY }, 'enterprise'],
		['a renewal that changes nothing', {}, 'enterprise'],
		['a different issuer, even while disabling', { enabled: false, issuer: OTHER_ISSUER }, 'enterprise'],
	])('%s still needs discovery', async (_label, change, tier) => {
		const before = await approvedWithDiscoveryGone({ tier });
		delete discovery[OTHER_ISSUER];
		const res = await putSelfServe(change);
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'issuer_discovery_failed' });
		expect(fetches.length).toBeGreaterThan(0);
		expect(await stored()).toEqual(before);
	});

	it('creating a tenant still needs discovery', async () => {
		delete discovery[ISSUER];
		const res = await putSelfServe({ enabled: false });
		expect(res.status).toBe(400);
		expect(await stored()).toBeNull();
	});

	it('moved keys re-pend through discovery even on a write that would otherwise be lowering', async () => {
		await approvedWithDiscoveryGone();
		discovery[ISSUER] = 'https://idp.acme.example.com/rotated-keys';
		// A renewal at the same expiry is not lowering, so it rediscovers and the changed keys re-pend.
		expect(
			((await (await putSelfServe({ entitlement_expires_at: (await stored())!.entitlement_expires_at })).json()) as { approval: string })
				.approval,
		).toBe('pending');
		expect((await stored())!.jwks_uri).toBe('https://idp.acme.example.com/rotated-keys');
	});
});

describe('the coordinator version, not the KV record, decides which tokens stand (SQ-465 B1)', () => {
	it('a raise that read the record before a concurrent revoke cannot revive the tokens the revoke killed', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		const beforeRevoke = (await stored())!;
		const tep = await epoch();
		expect(await tokenLive(tep)).toBe(true);

		// A raise (a later expiry needs discovery) reads the record, then waits on the IdP.
		const hold = holdDiscovery();
		fetches.length = 0;
		const raise = putSelfServe({ entitlement_expires_at: nowSeconds() + 60 * DAY });
		await vi.waitFor(() => expect(hold.started()).toBeGreaterThan(0));

		// Meanwhile bv-web's revoke lands: a disable needs no discovery.
		expect((await putSelfServe({ enabled: false })).status).toBe(200);
		expect(await tokenLive(tep)).toBe(false);
		const revoked = await epoch();
		expect(revoked).toBeGreaterThan(tep);

		hold.release();
		expect((await raise).status).toBe(200);
		// The raise re-enabled the tenant (a request bv-web really sent), but what it wrote mirrors the
		// version the revoke set, and the token minted before the revoke stays dead.
		expect((await stored())!.enabled).toBe(true);
		expect((await stored())!.token_epoch).toBe(revoked);
		expect(await epoch()).toBe(revoked);
		expect(await tokenLive(tep)).toBe(false);
		expect(await tokenLive(revoked)).toBe(true);

		// The pre-revoke snapshot was approved and enabled: the write was still decided on the fresh record.
		expect(beforeRevoke.token_epoch).toBe(tep);
	});

	it('re-reads the record after discovery: a reject that lands while discovery is held still applies', async () => {
		await putSelfServe();
		const hold = holdDiscovery();
		fetches.length = 0;
		const second = putSelfServe({ name: 'Acme again' });
		await vi.waitFor(() => expect(hold.started()).toBeGreaterThan(0));

		expect((await reject()).status).toBe(200);
		hold.release();
		const res = await second;
		expect(res.status).toBe(200);
		// Decided on what is stored now (rejected), not on the pending record read before the IdP answered.
		expect(await res.json()).toMatchObject({ name: 'Acme again', approval: 'rejected' });
		expect((await stored())!.approval).toBe('rejected');
	});

	it('a self-serve delete bumps the epoch first, so the tokens of a deleted tenant die with it', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		const tep = await epoch();
		expect(await tokenLive(tep)).toBe(true);
		expect((await sendSelfServe('DELETE')).status).toBe(204);
		expect(await stored()).toBeNull();
		expect(await epoch()).toBeGreaterThan(tep);
		expect(await tokenLive(tep)).toBe(false);
	});

	it('the operator DELETE retires the epoch too, even for a registry record it cannot read', async () => {
		await putOperator();
		const tep = await epoch('acme-operator');
		await runInDurableObject(registryShard(), (_instance, state) => state.storage.put(emaRecordStorageKey('acme-operator'), { corrupt: true }));
		expect((await send(call('DELETE', '/ema-tenants/acme-operator'))).status).toBe(204);
		expect(await epoch('acme-operator')).toBeGreaterThan(tep);
	});
});

describe('rejected issuers are remembered per tenant (SQ-465 B3)', () => {
	const hashOf = (issuer: string) => issuerHash(issuer);

	it('reject records the issuer; the tenant moves away and back, and the issuer is still rejected', async () => {
		await putSelfServe();
		expect((await reject()).status).toBe(200);
		expect((await stored())!.rejected_issuer_hashes).toEqual([await hashOf(ISSUER)]);

		expect(((await (await putSelfServe({ issuer: OTHER_ISSUER })).json()) as { approval: string }).approval).toBe('pending');
		expect((await stored())!.rejected_issuer_hashes).toEqual([await hashOf(ISSUER)]);
		// Back to the rejected issuer: the stored record is pending on another issuer, yet the ban holds.
		expect(((await (await putSelfServe({ issuer: `${ISSUER}/` })).json()) as { approval: string }).approval).toBe('rejected');
		expect(((await (await putSelfServe({ issuer: ISSUER })).json()) as { approval: string }).approval).toBe('rejected');
	});

	it('is never part of the self-serve view', async () => {
		await putSelfServe();
		expect((await reject()).status).toBe(200);
		const view = (await (await sendSelfServe('GET')).json()) as Record<string, unknown>;
		expect(view).not.toHaveProperty('rejected_issuer_hashes');
		expect(view).toMatchObject({ approval: 'rejected' });
		expect(await (await putSelfServe()).json()).not.toHaveProperty('rejected_issuer_hashes');
	});

	it('keeps at most 16, dropping the oldest', async () => {
		await putSelfServe();
		const filler = Array.from({ length: 16 }, (_, i) => i.toString(16).padStart(2, '0').repeat(32));
		await putRegistryRecord({ ...(await stored())!, rejected_issuer_hashes: filler });
		expect((await reject()).status).toBe(200);
		const history = (await stored())!.rejected_issuer_hashes!;
		expect(history).toHaveLength(16);
		expect(history).not.toContain(filler[0]);
		expect(history[15]).toBe(await hashOf(ISSUER));
		expect(history.slice(0, 15)).toEqual(filler.slice(1));
	});

	it('the operator approving that issuer removes it from the history', async () => {
		await putSelfServe();
		expect((await reject()).status).toBe(200);
		expect((await approve()).status).toBe(200);
		expect((await stored())!.rejected_issuer_hashes).toBeUndefined();
		expect(((await (await putSelfServe({ name: 'Back in' })).json()) as { approval: string }).approval).toBe('approved');
	});

	it('a self-serve DELETE keeps a tombstone while any rejected issuer is remembered, and the operator DELETE clears it all', async () => {
		await putSelfServe();
		expect((await reject()).status).toBe(200);
		// Moved to another issuer (pending now): rejected itself no longer, but its history is.
		expect((await putSelfServe({ issuer: OTHER_ISSUER })).status).toBe(200);
		expect((await sendSelfServe('DELETE')).status).toBe(204);
		const tombstone = (await stored())!;
		expect(tombstone).toMatchObject({ enabled: false, source: 'self-serve', issuer: OTHER_ISSUER });
		expect(tombstone.rejected_issuer_hashes).toEqual([await hashOf(ISSUER)]);
		expect(((await (await putSelfServe()).json()) as { approval: string }).approval).toBe('rejected');

		expect((await send(call('DELETE', `/ema-tenants/${TENANT_ID}`))).status).toBe(204);
		expect(await stored()).toBeNull();
		expect(((await (await putSelfServe()).json()) as { approval: string }).approval).toBe('pending');
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
		expect(await getEmaTenantByIssuer(REGISTRY, ISSUER)).toBeNull();
		expect((await send(call('DELETE', selfServePath()))).status).toBe(204);
	});

	it('a rejected tenant keeps a tombstone: 204, disabled and lapsed, still rejected, and the ban survives a re-create on the same issuer', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		expect((await reject()).status).toBe(200);
		await backdate();

		const res = await sendSelfServe('DELETE');
		expect(res.status).toBe(204);
		expect(res.headers.get('cache-control')).toBe('no-store');
		const tombstone = (await stored())!;
		expect(tombstone).toMatchObject({ enabled: false, approval: 'rejected', issuer: ISSUER, source: 'self-serve' });
		expect(tombstone.entitlement_expires_at).toBeLessThanOrEqual(nowSeconds());
		expect(tombstone.token_epoch).toBe(await epoch());
		expect(await getEmaTenantByIssuer(REGISTRY, ISSUER)).toBeNull();
		expect(await (await sendSelfServe('GET')).json()).toMatchObject({ approval: 'rejected', enabled: false });

		// Idempotent, and the same issuer stays rejected whatever the body says; another issuer starts over.
		expect((await sendSelfServe('DELETE')).status).toBe(204);
		expect(((await (await putSelfServe()).json()) as { approval: string }).approval).toBe('rejected');
		expect(((await (await putSelfServe({ issuer: OTHER_ISSUER })).json()) as { approval: string }).approval).toBe('pending');
	});

	it("the operator's own DELETE removes a rejected tenant (and its tombstone) completely", async () => {
		await putSelfServe();
		expect((await reject()).status).toBe(200);
		expect((await sendSelfServe('DELETE')).status).toBe(204);
		expect(await stored()).not.toBeNull();
		expect((await send(call('DELETE', `/ema-tenants/${TENANT_ID}`))).status).toBe(204);
		expect(await stored()).toBeNull();
		expect(((await (await putSelfServe()).json()) as { approval: string }).approval).toBe('pending');
	});

	it('409 tenant_managed_by_operator on an operator-seeded tenant, which survives', async () => {
		await putOperator({ tenant_id: TENANT_ID });
		const res = await send(call('DELETE', selfServePath()));
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'tenant_managed_by_operator' });
		expect((await stored())?.tenant_id).toBe(TENANT_ID);
	});

	it('409 envelope_key_required and nothing changed while OAuth is on without KV_ENVELOPE_KEY (a rejected delete is a write)', async () => {
		await putSelfServe();
		expect((await reject()).status).toBe(200);
		const before = await stored();
		const tep = await epoch();
		const res = await send(call('DELETE', selfServePath()), baseEnv({ KV_ENVELOPE_KEY: undefined }));
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'envelope_key_required' });
		expect(await stored()).toEqual(before);
		expect(await epoch()).toBe(tep);
	});

	it('503 on a record it cannot read, which survives', async () => {
		const key = `${OAUTH_KV_PREFIX}ema-tenant:${TENANT_ID}`;
		const unreadable = await plantUnreadableLegacy(TENANT_ID);
		expect((await send(call('DELETE', selfServePath()))).status).toBe(503);
		expect(await env.SESSION_STORE!.get(key)).toBe(unreadable);
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
		expect((await getEmaTenantByIssuer(REGISTRY, ISSUER))?.tenant_id).toBe(TENANT_ID);
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
		await putSelfServe({}, 'web-first-tenant');
		await putSelfServe({}, 'web-second-tenant');
		expect((await approve('web-first-tenant')).status).toBe(200);
		const res = await approve('web-second-tenant');
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'issuer_conflict' });
		expect((await stored('web-second-tenant'))!.approval).toBe('pending');

		expect((await reject('web-first-tenant')).status).toBe(200);
		expect((await approve('web-second-tenant')).status).toBe(200);
		expect((await getEmaTenantByIssuer(REGISTRY, ISSUER))?.tenant_id).toBe('web-second-tenant');
	});

	it('reject is sticky, releases the issuer, and moves the epoch of an approved tenant', async () => {
		await putSelfServe();
		expect((await approve()).status).toBe(200);
		await backdate();
		const before = await epoch();
		const res = await reject();
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ approval: 'rejected' });
		expect(await epoch()).toBeGreaterThan(before);
		expect((await stored())!.token_epoch).toBe(await epoch());
		expect(await getEmaTenantByIssuer(REGISTRY, ISSUER)).toBeNull();
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
		await putSelfServe({ issuer: OTHER_ISSUER }, 'web-beta-tenant');
		await approve('web-beta-tenant');
		discovery['https://idp-c.acme.example.com'] = 'https://idp-c.acme.example.com/keys';
		await putSelfServe({ issuer: 'https://idp-c.acme.example.com' }, 'web-gamma-tenant');
		await reject('web-gamma-tenant');
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
		expect(await listed('?approval=approved')).toEqual({ ids: ['acme-operator', 'web-beta-tenant'], total: 2 });
		expect(await listed('?approval=rejected')).toEqual({ ids: ['web-gamma-tenant'], total: 1 });
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
		const before = await epoch('acme-operator');
		expect((await putOperator(patch)).status).toBe(200);
		expect(await epoch('acme-operator')).toBeGreaterThan(before);
		expect((await stored('acme-operator'))!.token_epoch).toBe(await epoch('acme-operator'));
	});

	it('keeps the token epoch on an operator same-issuer, same-keys renewal, and moves it when a dated entitlement is cut short', async () => {
		expect((await putOperator({ entitlement_expires_at: nowSeconds() + 30 * DAY })).status).toBe(200);
		await backdate('acme-operator');
		const before = await epoch('acme-operator');
		expect((await putOperator({ entitlement_expires_at: nowSeconds() + 90 * DAY })).status).toBe(200);
		expect(await epoch('acme-operator')).toBe(before);
		expect((await stored('acme-operator'))!.token_epoch).toBe(before);

		// Moving the end earlier (or dating an open-ended tenant) revokes what was minted under the longer one.
		expect((await putOperator({ entitlement_expires_at: nowSeconds() + 10 * DAY })).status).toBe(200);
		expect(await epoch('acme-operator')).toBeGreaterThan(before);
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
		await send(call('DELETE', selfServePath('web-nobody-here')));
		expect(mutationDetails(spy)).toEqual([{ tenant_id: 'web-nobody-here', action: 'delete' }]);
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

/** The registry as the Worker sees it (coordinator + the legacy-import KV and envelope key). */
const REGISTRY: EmaRegistry = { coordinator: env.QUOTA_COORDINATOR, kv: env.SESSION_STORE!, kvEnvelopeKey: ENVELOPE_KEY };

const registryShard = () => env.QUOTA_COORDINATOR.getByName(securityStateShardNameForKey(EMA_REGISTRY_KEY));

/** Overwrite one record directly in the registry shard (with its issuer index entry), bypassing every write rule. */
async function putRegistryRecord(rec: EmaTenantRecord): Promise<void> {
	await runInDurableObject(registryShard(), async (_instance, state) => {
		await state.storage.put(emaRecordStorageKey(rec.tenant_id), rec);
		if (effectiveApproval(rec) === 'approved') await state.storage.put(emaIssuerStorageKey(rec.issuer), rec.tenant_id);
	});
}

/** A legacy KV tenant record sealed under a key this deployment does not hold: it exists but cannot be read. */
async function plantUnreadableLegacy(tenantId: string): Promise<string> {
	const foreignKey = new Uint8Array(32).fill(7);
	const sealed = await sealKv(JSON.stringify({ tenant_id: tenantId }), foreignKey);
	await env.SESSION_STORE!.put(`${OAUTH_KV_PREFIX}ema-tenant:${tenantId}`, sealed);
	return sealed;
}
