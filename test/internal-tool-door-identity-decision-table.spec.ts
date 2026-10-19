// SPDX-License-Identifier: BUSL-1.1

/**
 * Decision tables for the two helpers every `POST /internal/tools/call` passes through before a
 * tool runs: `resolveToolDoorIdentity` (who is the storage/quota owner?) and
 * `reconcileTrustedTenantBrandOwner` (adopt legacy brand-audit rows for a trusted tenant).
 * Neither is exported, so the tables drive the real route and observe the response plus the
 * two collaborators that are mocked at the module boundary:
 *   - `reconcileLegacyBrandAuditOwner` / `adoptAnonymousBrandAuditWatchInternal` (D1 work)
 *   - `handleToolsCall` (the tool dispatcher; its options carry the resolved identity)
 *
 * Fail-closed is the invariant: any reconciliation fault or malformed proof ends in a refusal
 * and the tool dispatcher is never reached.
 *
 * resolveToolDoorIdentity
 *   principal            headers                              -> result
 *   tenant-tool / watch-cleanup
 *                        X-Tenant or X-Auth-Tier missing      -> 400 incomplete_tenant_context
 *                        X-Tenant fails ^[A-Za-z0-9][\w-]{0,127}$ -> 400 invalid_tenant_context
 *                        X-Auth-Tier not developer|enterprise -> 400 invalid_auth_tier
 *                        OAUTH_ISSUER unset                   -> 503 oauth_issuer_not_configured
 *                        OAUTH_ISSUER not https               -> 503 oauth_issuer_invalid
 *                        valid                                -> canonical principal + the asserted tier
 *   web / mobile / network
 *                        X-Tenant or X-Auth-Tier present      -> 403 tenant_context_not_allowed
 *                        web, valid X-BV-Caller               -> system:web:<caller>, owner
 *                        web, missing/invalid X-BV-Caller     -> system:web:default, owner
 *                        mobile / network                     -> system:<principal>, free
 *
 * reconcileTrustedTenantBrandOwner (tenant-tool / watch-cleanup, owner-scoped brand tool)
 *   no BRAND_AUDIT_DB                                          -> skipped, tool runs
 *   reconcile throws                                           -> 503 brand_owner_reconciliation_unavailable
 *   register_*                                                 -> reconcile only, tool runs
 *   list/delete, no proof                                      -> reconcile only, tool runs
 *   list/delete, proof not a string                            -> 400 invalid_legacy_watch_proof
 *   delete, watchId not a string                               -> 400 invalid_legacy_watch_id
 *   proof ok                                                   -> adopt; ambiguous -> 409 legacy_watch_ambiguous
 *   adopt throws                                               -> 503 brand_owner_reconciliation_unavailable
 */
import { createExecutionContext, env as workerEnv, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const reconcileMock = vi.fn();
const adoptMock = vi.fn();
const handleToolsCallMock = vi.fn();

vi.mock('../src/lib/brand-audit-owner-reconciliation', async (importOriginal) => ({
	...(await importOriginal<typeof import('../src/lib/brand-audit-owner-reconciliation')>()),
	reconcileLegacyBrandAuditOwner: (...args: unknown[]) => reconcileMock(...args),
	adoptAnonymousBrandAuditWatchInternal: (...args: unknown[]) => adoptMock(...args),
}));

vi.mock('../src/handlers/tools', async (importOriginal) => ({
	...(await importOriginal<typeof import('../src/handlers/tools')>()),
	handleToolsCall: (...args: unknown[]) => handleToolsCallMock(...args),
}));

const WEB_KEY = 'web-internal-capability-key-32-bytes-minimum';
const MOBILE_KEY = 'mobile-internal-capability-key-32-bytes-minimum';
const TENANT_TOOL_KEY = 'tenant-tool-delegation-key-32-bytes-minimum';
const WATCH_CLEANUP_KEY = 'watch-cleanup-capability-key-32-bytes-minimum';
const ISSUER = 'https://issuer.example';
const OWNER_ID = /^[0-9a-f]{64}$/;
const FINGERPRINT = 'f'.repeat(64);
const WATCH_ID = 'a'.repeat(32);

const db = {} as D1Database;
const ctx = { waitUntil: vi.fn(), passThroughOnException: vi.fn() } as unknown as ExecutionContext;

type Env = Record<string, unknown>;

function baseEnv(over: Env = {}): Env {
	return {
		BV_WEB_INTERNAL_KEY: WEB_KEY,
		BV_MOBILE_INTERNAL_KEY: MOBILE_KEY,
		BV_MCP_TOOL_DELEGATION_KEY: TENANT_TOOL_KEY,
		BV_MCP_WATCH_CLEANUP_KEY: WATCH_CLEANUP_KEY,
		OAUTH_ISSUER: ISSUER,
		BRAND_AUDIT_DB: db,
		...over,
	};
}

async function call(opts: {
	key?: string | null;
	headers?: Record<string, string>;
	name: string;
	args?: Record<string, unknown>;
	env?: Env;
}): Promise<Response> {
	const { internalRoutes } = await import('../src/internal');
	const headers: Record<string, string> = { 'content-type': 'application/json', ...opts.headers };
	if (opts.key !== null) headers.authorization = `Bearer ${opts.key ?? TENANT_TOOL_KEY}`;
	return internalRoutes.request(
		'/tools/call',
		{ method: 'POST', headers, body: JSON.stringify({ name: opts.name, arguments: opts.args ?? {} }) },
		opts.env ?? baseEnv(),
		ctx,
	);
}

/**
 * The mobile credential is only accepted on the exact public path `/internal/tools/call`, which the
 * gate selection reads from the full URL, so mobile rows must enter through the whole Worker.
 */
async function callViaWorker(opts: {
	key: string;
	headers?: Record<string, string>;
	name: string;
	args?: Record<string, unknown>;
}): Promise<Response> {
	const { default: worker } = await import('../src');
	const request = new Request('https://example.com/internal/tools/call', {
		method: 'POST',
		headers: { 'content-type': 'application/json', authorization: `Bearer ${opts.key}`, ...opts.headers },
		body: JSON.stringify({ name: opts.name, arguments: opts.args ?? {} }),
	});
	const executionCtx = createExecutionContext();
	const response = await worker.fetch(request, { ...workerEnv, ...baseEnv() } as never, executionCtx);
	await waitOnExecutionContext(executionCtx);
	return response;
}

const tenantHeaders = (tenant = 'tenant_123', tier = 'developer') => ({ 'x-tenant': tenant, 'x-auth-tier': tier });

async function ownerFor(tenant: string): Promise<string> {
	const { deriveCanonicalTenantPrincipal } = await import('../src/lib/auth-principal');
	return deriveCanonicalTenantPrincipal(ISSUER, tenant);
}

beforeEach(() => {
	reconcileMock.mockReset().mockResolvedValue(undefined);
	adoptMock.mockReset().mockResolvedValue({ status: 'no_match' });
	handleToolsCallMock.mockReset().mockResolvedValue({ content: [{ type: 'text', text: 'ok' }] });
});

afterEach(() => vi.restoreAllMocks());

describe('resolveToolDoorIdentity — tenant-delegated principals', () => {
	it.each([
		['both headers absent', {}, 'incomplete_tenant_context'],
		['X-Tenant only', { 'x-tenant': 'tenant_123' }, 'incomplete_tenant_context'],
		['X-Auth-Tier only', { 'x-auth-tier': 'developer' }, 'incomplete_tenant_context'],
		['X-Tenant present but empty', { 'x-tenant': '', 'x-auth-tier': 'developer' }, 'incomplete_tenant_context'],
		['tenant starting with a dash', tenantHeaders('-tenant'), 'invalid_tenant_context'],
		['tenant with a space', tenantHeaders('ten ant'), 'invalid_tenant_context'],
		['tenant with a dot', tenantHeaders('tenant.one'), 'invalid_tenant_context'],
		['tenant with a colon', tenantHeaders('tenant:one'), 'invalid_tenant_context'],
		['tenant longer than 128 chars', tenantHeaders('a'.repeat(129)), 'invalid_tenant_context'],
		['tier owner', tenantHeaders('tenant_123', 'owner'), 'invalid_auth_tier'],
		['tier free', tenantHeaders('tenant_123', 'free'), 'invalid_auth_tier'],
		['tier mixed case', tenantHeaders('tenant_123', 'Developer'), 'invalid_auth_tier'],
	])('%s -> 400 %s (never reaches reconciliation or the dispatcher)', async (_label, headers, error) => {
		for (const key of [TENANT_TOOL_KEY, WATCH_CLEANUP_KEY]) {
			const res = await call({ key, headers, name: 'list_brand_audit_watches' });
			expect(res.status).toBe(400);
			expect(await res.json()).toEqual({ error });
			expect(res.headers.get('cache-control')).toBe('no-store');
		}
		expect(reconcileMock).not.toHaveBeenCalled();
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it('invalid tenant outranks invalid tier, and invalid tier outranks a missing issuer', async () => {
		const both = await call({ headers: tenantHeaders('-bad', 'owner'), name: 'list_brand_audit_watches' });
		expect(await both.json()).toEqual({ error: 'invalid_tenant_context' });
		const tierAndIssuer = await call({
			headers: tenantHeaders('tenant_123', 'owner'),
			name: 'list_brand_audit_watches',
			env: baseEnv({ OAUTH_ISSUER: undefined }),
		});
		expect(await tierAndIssuer.json()).toEqual({ error: 'invalid_auth_tier' });
	});

	it.each([
		['unset', undefined],
		['empty', ''],
	])('an %s OAUTH_ISSUER -> 503 oauth_issuer_not_configured', async (_label, issuer) => {
		const res = await call({ headers: tenantHeaders(), name: 'list_brand_audit_watches', env: baseEnv({ OAUTH_ISSUER: issuer }) });
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual({ error: 'oauth_issuer_not_configured' });
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it.each([['http://issuer.example'], ['not a url'], ['https://user:pw@issuer.example'], ['https://issuer.example/?q=1']])(
		'issuer %j that cannot be canonicalised -> 503 oauth_issuer_invalid',
		async (issuer) => {
			const res = await call({ headers: tenantHeaders(), name: 'list_brand_audit_watches', env: baseEnv({ OAUTH_ISSUER: issuer }) });
			expect(res.status).toBe(503);
			expect(await res.json()).toEqual({ error: 'oauth_issuer_invalid' });
			expect(reconcileMock).not.toHaveBeenCalled();
			expect(handleToolsCallMock).not.toHaveBeenCalled();
		},
	);

	it.each([
		['tenant-tool', TENANT_TOOL_KEY, 'developer'],
		['tenant-tool', TENANT_TOOL_KEY, 'enterprise'],
		['watch-cleanup', WATCH_CLEANUP_KEY, 'developer'],
		['watch-cleanup', WATCH_CLEANUP_KEY, 'enterprise'],
	])('%s with a valid assertion binds the canonical tenant principal and the asserted %s tier', async (_principal, key, tier) => {
		const res = await call({ key, headers: tenantHeaders('tenant_123', tier), name: 'list_brand_audit_watches' });
		expect(res.status).toBe(200);
		const options = handleToolsCallMock.mock.calls[0][2] as { principalId: string; authTier: string };
		expect(options.principalId).toMatch(OWNER_ID);
		expect(options.principalId).toBe(await ownerFor('tenant_123'));
		expect(options.authTier).toBe(tier);
	});

	it('accepts the 128-character tenant boundary', async () => {
		const tenant = 'a'.repeat(128);
		const res = await call({ headers: tenantHeaders(tenant), name: 'list_brand_audit_watches' });
		expect(res.status).toBe(200);
		expect((handleToolsCallMock.mock.calls[0][2] as { principalId: string }).principalId).toBe(await ownerFor(tenant));
	});
});

describe('resolveToolDoorIdentity — system principals', () => {
	it.each([
		['web + X-Tenant only', WEB_KEY, { 'x-tenant': 'victim' }],
		['web + X-Auth-Tier only', WEB_KEY, { 'x-auth-tier': 'enterprise' }],
		['web + both', WEB_KEY, tenantHeaders('victim', 'enterprise')],
	])('%s -> 403 tenant_context_not_allowed', async (_label, key, headers) => {
		const res = await call({ key, headers, name: 'scan_domain', args: { domain: 'example.com' } });
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({ error: 'tenant_context_not_allowed' });
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it('mobile + tenant context -> 403 tenant_context_not_allowed', async () => {
		const res = await callViaWorker({
			key: MOBILE_KEY,
			headers: tenantHeaders('victim', 'enterprise'),
			name: 'scan_domain',
			args: { domain: 'example.com' },
		});
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({ error: 'tenant_context_not_allowed' });
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it('network principal (REQUIRE_INTERNAL_AUTH=false) + tenant context -> 403', async () => {
		const res = await call({
			key: null,
			headers: tenantHeaders(),
			name: 'scan_domain',
			args: { domain: 'example.com' },
			env: baseEnv({ REQUIRE_INTERNAL_AUTH: 'false' }),
		});
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({ error: 'tenant_context_not_allowed' });
	});

	it.each([
		['recon-sweep', 'system:web:recon-sweep'],
		['a', 'system:web:a'],
		['0lead_digit-ok', 'system:web:0lead_digit-ok'],
		['a'.repeat(64), `system:web:${'a'.repeat(64)}`],
		['a'.repeat(65), 'system:web:default'],
		['Upper', 'system:web:default'],
		['-leading-dash', 'system:web:default'],
		['has space', 'system:web:default'],
		['semi;colon', 'system:web:default'],
	])('web caller header %j -> principal %s with the owner tier', async (caller, principalId) => {
		const res = await call({ key: WEB_KEY, headers: { 'x-bv-caller': caller }, name: 'scan_domain', args: { domain: 'example.com' } });
		expect(res.status).toBe(200);
		const options = handleToolsCallMock.mock.calls[0][2] as { principalId: string; authTier: string };
		expect(options.principalId).toBe(principalId);
		expect(options.authTier).toBe('owner');
	});

	it('web with no caller header -> system:web:default / owner', async () => {
		const res = await call({ key: WEB_KEY, name: 'scan_domain', args: { domain: 'example.com' } });
		expect(res.status).toBe(200);
		const options = handleToolsCallMock.mock.calls[0][2] as { principalId: string; authTier: string };
		expect(options).toMatchObject({ principalId: 'system:web:default', authTier: 'owner' });
	});

	it('mobile -> system:mobile / free, regardless of the caller header', async () => {
		const res = await callViaWorker({
			key: MOBILE_KEY,
			headers: { 'x-bv-caller': 'recon-sweep' },
			name: 'scan_domain',
			args: { domain: 'example.com' },
		});
		expect(res.status).toBe(200);
		expect(handleToolsCallMock.mock.calls[0][2]).toMatchObject({ principalId: 'system:mobile', authTier: 'free' });
	});

	it('network (REQUIRE_INTERNAL_AUTH=false) -> system:network / free', async () => {
		const res = await call({
			key: null,
			name: 'scan_domain',
			args: { domain: 'example.com' },
			env: baseEnv({ REQUIRE_INTERNAL_AUTH: 'false' }),
		});
		expect(res.status).toBe(200);
		expect(handleToolsCallMock.mock.calls[0][2]).toMatchObject({ principalId: 'system:network', authTier: 'free' });
	});
});

describe('reconcileTrustedTenantBrandOwner', () => {
	const REFUSED = { error: 'brand_owner_reconciliation_unavailable' };

	it('is skipped entirely when BRAND_AUDIT_DB is not bound', async () => {
		const res = await call({
			headers: tenantHeaders(),
			name: 'register_brand_audit_watch',
			args: { domain: 'example.com' },
			env: baseEnv({ BRAND_AUDIT_DB: undefined }),
		});
		expect(res.status).toBe(200);
		expect(reconcileMock).not.toHaveBeenCalled();
		expect(adoptMock).not.toHaveBeenCalled();
		expect(handleToolsCallMock).toHaveBeenCalledTimes(1);
	});

	it('reconciles the legacy owner under tenant:<id> -> canonical owner, then lets register_brand_audit_watch run', async () => {
		const res = await call({ headers: tenantHeaders('tenant_9'), name: 'register_brand_audit_watch', args: { domain: 'example.com' } });
		expect(res.status).toBe(200);
		expect(reconcileMock).toHaveBeenCalledTimes(1);
		expect(reconcileMock).toHaveBeenCalledWith(db, 'tenant:tenant_9', await ownerFor('tenant_9'));
		expect(adoptMock).not.toHaveBeenCalled();
		expect(handleToolsCallMock).toHaveBeenCalledTimes(1);
	});

	it('the watch-cleanup principal reconciles the same way', async () => {
		const res = await call({ key: WATCH_CLEANUP_KEY, headers: tenantHeaders('tenant_9'), name: 'list_brand_audit_watches' });
		expect(res.status).toBe(200);
		expect(reconcileMock).toHaveBeenCalledWith(db, 'tenant:tenant_9', await ownerFor('tenant_9'));
	});

	it.each([
		['an Error', new Error('d1 down')],
		['a non-Error value', 'boom'],
	])('a reconcile fault (%s) fails closed with 503 and the dispatcher is never reached', async (_label, fault) => {
		reconcileMock.mockRejectedValueOnce(fault);
		const res = await call({ headers: tenantHeaders(), name: 'register_brand_audit_watch', args: { domain: 'example.com' } });
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual(REFUSED);
		expect(res.headers.get('cache-control')).toBe('no-store');
		expect(adoptMock).not.toHaveBeenCalled();
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it.each(['list_brand_audit_watches', 'delete_brand_audit_watch'])('%s without a legacy proof only reconciles', async (name) => {
		const res = await call({ headers: tenantHeaders(), name, args: name === 'delete_brand_audit_watch' ? { watchId: WATCH_ID } : {} });
		expect(res.status).toBe(200);
		expect(reconcileMock).toHaveBeenCalledTimes(1);
		expect(adoptMock).not.toHaveBeenCalled();
	});

	it.each([
		['a number', 123],
		['null', null],
		['an object', { a: 1 }],
		['a boolean', false],
	])('%s as the legacy proof -> 400 invalid_legacy_watch_proof (after the owner reconcile ran)', async (_label, proof) => {
		for (const name of ['list_brand_audit_watches', 'delete_brand_audit_watch']) {
			const res = await call({ headers: tenantHeaders(), name, args: { legacyWebhookTokenFingerprint: proof } });
			expect(res.status).toBe(400);
			expect(await res.json()).toEqual({ error: 'invalid_legacy_watch_proof' });
		}
		expect(reconcileMock).toHaveBeenCalledTimes(2);
		expect(adoptMock).not.toHaveBeenCalled();
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it.each([
		['a number', 7],
		['null', null],
		['an object', { id: 1 }],
	])('delete with %s as watchId -> 400 invalid_legacy_watch_id', async (_label, watchId) => {
		const res = await call({
			headers: tenantHeaders(),
			name: 'delete_brand_audit_watch',
			args: { legacyWebhookTokenFingerprint: FINGERPRINT, watchId },
		});
		expect(res.status).toBe(400);
		expect(await res.json()).toEqual({ error: 'invalid_legacy_watch_id' });
		expect(adoptMock).not.toHaveBeenCalled();
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it('the bad-proof check outranks the bad-watchId check', async () => {
		const res = await call({
			headers: tenantHeaders(),
			name: 'delete_brand_audit_watch',
			args: { legacyWebhookTokenFingerprint: 5, watchId: 7 },
		});
		expect(await res.json()).toEqual({ error: 'invalid_legacy_watch_proof' });
	});

	it('list adopts by proof alone and ignores any watchId argument', async () => {
		const res = await call({
			headers: tenantHeaders('tenant_9'),
			name: 'list_brand_audit_watches',
			args: { legacyWebhookTokenFingerprint: FINGERPRINT, watchId: WATCH_ID },
		});
		expect(res.status).toBe(200);
		expect(adoptMock).toHaveBeenCalledTimes(1);
		const [dbArg, input] = adoptMock.mock.calls[0];
		expect(dbArg).toBe(db);
		expect(input).toEqual({ canonicalOwnerId: await ownerFor('tenant_9'), webhookTokenFingerprint: FINGERPRINT });
		expect('watchId' in (input as object)).toBe(false);
	});

	it('delete adopts the named watch when the proof and watchId are both strings', async () => {
		const res = await call({
			headers: tenantHeaders('tenant_9'),
			name: 'delete_brand_audit_watch',
			args: { legacyWebhookTokenFingerprint: FINGERPRINT, watchId: WATCH_ID },
		});
		expect(res.status).toBe(200);
		expect(adoptMock.mock.calls[0][1]).toEqual({
			canonicalOwnerId: await ownerFor('tenant_9'),
			webhookTokenFingerprint: FINGERPRINT,
			watchId: WATCH_ID,
		});
		expect(handleToolsCallMock).toHaveBeenCalledTimes(1);
	});

	it('delete with a proof but no watchId adopts without a watchId key', async () => {
		const res = await call({
			headers: tenantHeaders(),
			name: 'delete_brand_audit_watch',
			args: { legacyWebhookTokenFingerprint: FINGERPRINT },
		});
		expect(res.status).toBe(200);
		expect('watchId' in (adoptMock.mock.calls[0][1] as object)).toBe(false);
	});

	it.each([
		['reconciled', { status: 'reconciled', watchId: WATCH_ID }],
		['no_match', { status: 'no_match' }],
	])('an adoption outcome of %s lets the tool run', async (_label, outcome) => {
		adoptMock.mockResolvedValueOnce(outcome);
		const res = await call({
			headers: tenantHeaders(),
			name: 'list_brand_audit_watches',
			args: { legacyWebhookTokenFingerprint: FINGERPRINT },
		});
		expect(res.status).toBe(200);
		expect(handleToolsCallMock).toHaveBeenCalledTimes(1);
	});

	it('an ambiguous adoption -> 409 legacy_watch_ambiguous and the tool does not run', async () => {
		adoptMock.mockResolvedValueOnce({ status: 'ambiguous' });
		const res = await call({
			headers: tenantHeaders(),
			name: 'delete_brand_audit_watch',
			args: { legacyWebhookTokenFingerprint: FINGERPRINT, watchId: WATCH_ID },
		});
		expect(res.status).toBe(409);
		expect(await res.json()).toEqual({ error: 'legacy_watch_ambiguous' });
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});

	it('an adoption fault fails closed with 503', async () => {
		adoptMock.mockRejectedValueOnce(new TypeError('Invalid brand-audit watch ID'));
		const res = await call({
			headers: tenantHeaders(),
			name: 'delete_brand_audit_watch',
			args: { legacyWebhookTokenFingerprint: FINGERPRINT, watchId: 'bad id' },
		});
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual(REFUSED);
		expect(handleToolsCallMock).not.toHaveBeenCalled();
	});
});
