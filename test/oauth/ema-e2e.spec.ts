import { env, createExecutionContext, runInDurableObject, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../../src/index';
import { resetQuotaCoordinatorState, EMA_REGISTRY_INSTANCE_NAME } from '../../src/lib/quota-coordinator';
import { parseEnvelopeKey, sealKv } from '../../src/lib/kv-envelope';
import {
	effectiveApproval,
	emaIssuerStorageKey,
	emaRecordStorageKey,
	EMA_MIGRATED_STORAGE_KEY,
	getEmaTenant,
	tenantEpoch,
	type EmaRegistry,
} from '../../src/oauth/ema-tenants';
import { sha256Hex } from '../../src/oauth/jwks';
import { signJwt } from '../../src/oauth/jwt';
import type { EmaTenantRecord } from '../../src/schemas/ema';
import { clearKvPrefix } from '../helpers/kv';

// US-14 Enterprise Managed Auth, end to end through the real Worker:
//   operator seeds a tenant (PUT /internal/oauth/ema-tenants, jwks_uri from OIDC discovery)
//   → Claude exchanges an IdP-signed ID-JAG (POST /oauth/token, jwt-bearer)
//   → the minted bearer calls a paid-only tool on /mcp at the TENANT's tier
//   → /internal/oauth/revoke-subject on the ema subject kills that bearer.
// Only the IdP (discovery + JWKS) and Claude's CIMD document are stubbed, at global fetch.
// Further cases: an ES256 IdP, the enterprise tier, per-tenant replay scoping, tenant-wide
// revocation of already-minted tokens (SQ-435), and the upsert route's token epoch.

const ISSUER = 'https://example.com';
const IDP_ISSUER = 'https://acme.okta.com';
const JWKS_URI = 'https://acme.okta.com/oauth2/v1/keys';
const OTHER_IDP_ISSUER = 'https://globex.okta.com';
const OTHER_JWKS_URI = 'https://globex.okta.com/oauth2/v1/keys';
const WEB_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const MINT_KEY = 'mint-capability-test-key-32-bytes-minimum';
const REVOKE_KEY = 'revoke-capability-test-key-32-bytes-minimum';
const ADMIN_KEY = 'ema-admin-capability-test-key-32-bytes-minimum';

// 32 zero bytes, base64. The tenant upsert route refuses to run without KV_ENVELOPE_KEY while OAuth is on,
// so tenant records are sealed here and the raw-KV helpers below go through the store (which opens/seals).
const ENVELOPE_B64 = btoa(String.fromCharCode(...new Uint8Array(32)));
const ENVELOPE_KEY = parseEnvelopeKey(ENVELOPE_B64)!;

type TestEnv = typeof env & {
	OAUTH_SIGNING_SECRET?: string;
	OAUTH_ISSUER?: string;
	BV_MCP_OAUTH_MINT_KEY?: string;
	BV_MCP_OAUTH_REVOKE_KEY?: string;
	BV_MCP_EMA_ADMIN_KEY?: string;
	KV_ENVELOPE_KEY?: string;
};
const e2eEnv = {
	...env,
	OAUTH_SIGNING_SECRET: 'a'.repeat(32),
	OAUTH_ISSUER: ISSUER,
	BV_MCP_OAUTH_MINT_KEY: MINT_KEY,
	BV_MCP_OAUTH_REVOKE_KEY: REVOKE_KEY,
	BV_MCP_EMA_ADMIN_KEY: ADMIN_KEY,
	KV_ENVELOPE_KEY: ENVELOPE_B64,
} as TestEnv;

const encoder = new TextEncoder();

function b64url(bytes: ArrayBuffer | Uint8Array): string {
	let binary = '';
	for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const b64urlJson = (value: unknown) => b64url(encoder.encode(JSON.stringify(value)));

function jsonResponse(body: unknown): Response {
	return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
}

async function send(request: Request<unknown, IncomingRequestCfProperties>): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, e2eEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

/** Internal routes are reached over the service binding, i.e. WITHOUT a public cf-connecting-ip. */
function internalRequest(method: string, path: string, bearer: string, body: unknown): Request<unknown, IncomingRequestCfProperties> {
	return new Request<unknown, IncomingRequestCfProperties>(`${ISSUER}/internal${path}`, {
		method,
		headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${bearer}` },
		body: JSON.stringify(body),
	});
}

function mcpRequest(token: string, body: unknown, sessionId?: string): Request<unknown, IncomingRequestCfProperties> {
	return new Request<unknown, IncomingRequestCfProperties>(`${ISSUER}/mcp`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${token}`,
			...(sessionId ? { 'Mcp-Session-Id': sessionId } : {}),
		},
		body: JSON.stringify(body),
	});
}

const batchStatusCall = {
	jsonrpc: '2.0',
	id: 2,
	method: 'tools/call',
	params: { name: 'batch_scan_status', arguments: { job_id: `bs_${'0'.repeat(40)}` } },
};

interface IdpKey {
	alg: 'RS256' | 'ES256';
	kid: string;
	privateKey: CryptoKey;
	publicJwk: JsonWebKey & { kid: string };
}

async function makeIdpKey(alg: 'RS256' | 'ES256', kid: string): Promise<IdpKey> {
	const algorithm =
		alg === 'RS256'
			? { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }
			: { name: 'ECDSA', namedCurve: 'P-256' };
	const pair = (await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])) as CryptoKeyPair;
	const pub = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
	return { alg, kid, privateKey: pair.privateKey, publicJwk: { ...pub, kid, use: 'sig', alg } };
}

/** What the stubbed network serves: the IdPs' discovery documents and JWKS, and Claude's CIMD document. */
let documents: Record<string, unknown>;
let idp: IdpKey;
let otherIdp: IdpKey;

function serveIdp(issuer: string, jwksUri: string, key: IdpKey): void {
	documents[`${issuer}/.well-known/openid-configuration`] = { issuer, jwks_uri: jwksUri };
	documents[jwksUri] = { keys: [key.publicJwk] };
}

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
	idp = await makeIdpKey('RS256', 'okta-1');
	otherIdp = await makeIdpKey('RS256', 'okta-2');
	documents = {
		[WEB_CLIENT_ID]: {
			client_id: WEB_CLIENT_ID,
			client_name: 'Claude',
			redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
			token_endpoint_auth_method: 'none',
		},
	};
	serveIdp(IDP_ISSUER, JWKS_URI, idp);
	serveIdp(OTHER_IDP_ISSUER, OTHER_JWKS_URI, otherIdp);
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : (input as Request).url;
			return url in documents ? jsonResponse(documents[url]) : new Response('not found', { status: 404 });
		}),
	);
});

afterEach(async () => {
	vi.unstubAllGlobals();
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

async function signIdJag(key: IdpKey = idp, overrides: Record<string, unknown> = {}): Promise<string> {
	const now = Math.floor(Date.now() / 1000);
	const claims = {
		iss: key === otherIdp ? OTHER_IDP_ISSUER : IDP_ISSUER,
		sub: '00u-okta-user-42',
		aud: ISSUER,
		client_id: WEB_CLIENT_ID,
		jti: crypto.randomUUID(),
		iat: now,
		exp: now + 300,
		resource: `${ISSUER}/mcp`,
		scope: 'mcp',
		...overrides,
	};
	const signingInput = `${b64urlJson({ alg: key.alg, typ: 'oauth-id-jag+jwt', kid: key.kid })}.${b64urlJson(claims)}`;
	// WebCrypto ECDSA emits the raw r||s form JWS ES256 requires (not DER).
	const algorithm = key.alg === 'RS256' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: 'SHA-256' };
	const signature = await crypto.subtle.sign(algorithm, key.privateKey, encoder.encode(signingInput));
	return `${signingInput}.${b64url(signature)}`;
}

/** Operator upsert of an EMA tenant over the internal route; the jwks_uri comes from the IdP's discovery document. */
async function seedTenant(overrides: Record<string, unknown> = {}): Promise<Response> {
	return send(
		internalRequest('PUT', '/oauth/ema-tenants', ADMIN_KEY, {
			tenant_id: 'acme-corp',
			name: 'Acme Corp',
			issuer: IDP_ISSUER,
			tier: 'developer',
			enabled: true,
			...overrides,
		}),
	);
}

/** The jwt-bearer token request Claude sends (public client, no IP header: the service-binding-free test door). */
function exchange(assertion: string): Promise<Response> {
	return send(
		new Request<unknown, IncomingRequestCfProperties>(`${ISSUER}/oauth/token`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
				assertion,
				client_id: WEB_CLIENT_ID,
				resource: `${ISSUER}/mcp`,
				scope: 'mcp',
			}).toString(),
		}),
	);
}

/** An access token's payload, decoded without verification. */
function decodeClaims(token: string): Record<string, unknown> {
	return JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
}

async function mintToken(assertion: string): Promise<string> {
	const response = await exchange(assertion);
	expect(response.status).toBe(200);
	const body = (await response.json()) as { access_token: string; resource?: string; scope?: string };
	// The granted resource and scope are echoed; a jwt-bearer exchange never carries a refresh_token.
	expect(body).toMatchObject({ resource: `${ISSUER}/mcp`, scope: 'mcp' });
	expect(body).not.toHaveProperty('refresh_token');
	return body.access_token;
}

/** Open an MCP session with the bearer and call a paid-only tool. */
async function callPaidTool(token: string): Promise<{ status: number; tier: string | null; sessionId: string | undefined }> {
	const init = await send(mcpRequest(token, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }));
	const sessionId = init.headers.get('mcp-session-id') ?? undefined;
	const call = await send(mcpRequest(token, batchStatusCall, sessionId));
	return { status: call.status, tier: call.headers.get('x-quota-tier'), sessionId };
}

describe('Enterprise Managed Auth end to end', () => {
	it('seeds a tenant, exchanges an ID-JAG, calls a paid tool at the tenant tier, and revokes the subject', async () => {
		// 1. Operator seeds the tenant; jwks_uri is resolved from the IdP's discovery document.
		const seeded = await seedTenant();
		expect(seeded.status).toBe(200);
		expect(((await seeded.json()) as Record<string, unknown>).jwks_uri).toBe(JWKS_URI);

		// 2. Claude exchanges the IdP-issued ID-JAG at the token endpoint.
		const accessToken = await mintToken(await signIdJag());
		const subject = (JSON.parse(atob(accessToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))) as { sub: string }).sub;
		expect(subject).toMatch(/^ema:acme-corp:[0-9a-f]{32}$/);

		// 3. The bearer opens an MCP session and reaches a paid-only tool at the tenant's tier.
		const init = await send(mcpRequest(accessToken, { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }));
		expect(init.status).toBe(200);
		const sessionId = init.headers.get('mcp-session-id') ?? undefined;
		expect(sessionId).toBeTruthy();

		const call = await send(mcpRequest(accessToken, batchStatusCall, sessionId));
		expect(call.status).toBe(200);
		expect(call.headers.get('x-quota-tier')).toBe('developer');
		const callBody = (await call.json()) as { result?: { content?: Array<{ text?: string }> }; error?: unknown };
		// Dispatched past the paid-only gate: the tool itself answers (a JSON-RPC result, not the -32003 gate error).
		expect(callBody.error).toBeUndefined();
		expect(callBody.result?.content?.[0]?.text).toMatch(/batch scan/i);

		// Control: the same call without the bearer is stopped at the paid-only gate.
		const anonymous = await send(
			new Request<unknown, IncomingRequestCfProperties>(`${ISSUER}/mcp`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(batchStatusCall),
			}),
		);
		expect(anonymous.status).toBe(401);
		expect(anonymous.headers.get('www-authenticate')).toContain('resource_metadata=');

		// 4. Revoking the ema subject invalidates the bearer before its natural expiry.
		const revoked = await send(internalRequest('POST', '/oauth/revoke-subject', REVOKE_KEY, { sub: subject }));
		expect(revoked.status).toBe(200);
		const afterRevoke = await send(mcpRequest(accessToken, batchStatusCall, sessionId));
		expect(afterRevoke.status).toBe(401);
	});

	it('accepts an ES256-signed assertion from an EC-keyed IdP', async () => {
		const ecKey = await makeIdpKey('ES256', 'okta-ec');
		serveIdp(IDP_ISSUER, JWKS_URI, ecKey);
		expect((await seedTenant()).status).toBe(200);

		const token = await mintToken(await signIdJag(ecKey));

		const call = await callPaidTool(token);
		expect(call.status).toBe(200);
		expect(call.tier).toBe('developer');
	});

	it('resolves an enterprise tenant to the enterprise quota tier on /mcp', async () => {
		expect((await seedTenant({ tier: 'enterprise' })).status).toBe(200);

		const token = await mintToken(await signIdJag());

		const call = await callPaidTool(token);
		expect(call.status).toBe(200);
		expect(call.tier).toBe('enterprise');
	});

	it('scopes replay protection per tenant: one jti is accepted once under EACH tenant, never twice under the same one', async () => {
		expect((await seedTenant()).status).toBe(200);
		expect((await seedTenant({ tenant_id: 'globex', name: 'Globex', issuer: OTHER_IDP_ISSUER })).status).toBe(200);
		const jti = crypto.randomUUID();
		const acme = await signIdJag(idp, { jti });
		const globex = await signIdJag(otherIdp, { jti });

		expect((await exchange(acme)).status).toBe(200);
		// The same jti under a different tenant (its own issuer and JWKS) is a different assertion, not a replay.
		expect((await exchange(globex)).status).toBe(200);

		const replayAcme = await exchange(acme);
		expect(replayAcme.status).toBe(400);
		expect(await replayAcme.json()).toEqual({ error: 'invalid_grant', error_description: 'Assertion has already been used' });
		expect((await exchange(globex)).status).toBe(400);
	});
});

// SQ-435 tenant-wide revocation: every /mcp request with an `ema:` bearer re-reads the tenant, so
// suspending, deleting, re-creating, lapsing or re-tiering a tenant cuts off tokens it already issued.
describe('Enterprise Managed Auth tenant-wide revocation', () => {
	/** A tools/call with the bearer on an open session; returns the response so the 401 challenge can be read. */
	function paidCall(token: string, sessionId: string | undefined): Promise<Response> {
		return send(mcpRequest(token, batchStatusCall, sessionId));
	}

	async function expectCutOff(token: string, sessionId: string | undefined): Promise<void> {
		const response = await paidCall(token, sessionId);
		expect(response.status).toBe(401);
		// The ordinary bad-bearer challenge, so Claude silently re-exchanges a fresh assertion.
		expect(response.headers.get('www-authenticate')).toContain('Bearer');
	}

	it('mints the tenant epoch as tep, stops minting AND cuts off issued tokens on disable, and re-enabling does not revive them', async () => {
		const seeded = (await (await seedTenant()).json()) as { token_epoch: number };
		expect(Number.isInteger(seeded.token_epoch)).toBe(true);
		const token = await mintToken(await signIdJag());
		expect(decodeClaims(token).tep).toBe(seeded.token_epoch);
		// The token carries the registry record's own epoch.
		expect(decodeClaims(token).tep).toBe(tenantEpoch((await getEmaTenant(REGISTRY, 'acme-corp'))!));
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);

		expect((await seedTenant({ enabled: false })).status).toBe(200);

		const rejected = await exchange(await signIdJag());
		expect(rejected.status).toBe(400);
		expect(await rejected.json()).toEqual({ error: 'invalid_grant', error_description: 'Assertion not accepted' });
		// Previously the minted bearer kept resolving until its TTL; now the suspension reaches it.
		await expectCutOff(token, before.sessionId);

		expect((await seedTenant({ enabled: true })).status).toBe(200);
		await expectCutOff(token, before.sessionId);
		// A fresh exchange after the re-enable works: only tokens minted before the suspension are dead.
		const fresh = await callPaidTool(await mintToken(await signIdJag()));
		expect(fresh.status).toBe(200);
		expect(fresh.tier).toBe('developer');
	});

	it('cuts off issued tokens when the tenant is deleted, and a re-created tenant does not revive them', async () => {
		expect((await seedTenant()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);

		expect((await send(internalRequest('DELETE', '/oauth/ema-tenants/acme-corp', ADMIN_KEY, undefined))).status).toBe(204);
		await expectCutOff(token, before.sessionId);

		expect((await seedTenant()).status).toBe(200);
		await expectCutOff(token, before.sessionId);
		const fresh = await callPaidTool(await mintToken(await signIdJag()));
		expect(fresh.status).toBe(200);
	});

	it('cuts off issued tokens once the tenant entitlement has passed', async () => {
		const now = Math.floor(Date.now() / 1000);
		expect((await seedTenant({ entitlement_expires_at: now + 600 })).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);

		// Still enabled: the lapsed entitlement rejects (and the earlier expiry moved the epoch too).
		expect((await seedTenant({ entitlement_expires_at: now - 10 })).status).toBe(200);
		await expectCutOff(token, before.sessionId);
	});

	it('cuts off issued tokens when the tenant tier changes', async () => {
		expect((await seedTenant()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.tier).toBe('developer');

		expect((await seedTenant({ tier: 'enterprise' })).status).toBe(200);
		await expectCutOff(token, before.sessionId);
		const fresh = await callPaidTool(await mintToken(await signIdJag()));
		expect(fresh.status).toBe(200);
		expect(fresh.tier).toBe('enterprise');
	});

	it('rejects an ema: bearer whose tep does not match the tenant epoch, and one with no tep at all', async () => {
		const seeded = (await (await seedTenant()).json()) as { token_epoch: number };
		const token = await mintToken(await signIdJag());
		const sub = decodeClaims(token).sub as string;
		const forge = (claims: Record<string, unknown>) =>
			signJwt(
				{ sub, jti: crypto.randomUUID(), tier: 'developer', client_id: WEB_CLIENT_ID, entitlementGeneration: 1, ...claims },
				{ secret: e2eEnv.OAUTH_SIGNING_SECRET!, ttlSeconds: 600, issuer: ISSUER, audience: `${ISSUER}/mcp` },
			);
		// Control: a correctly signed token on the current epoch resolves.
		expect((await callPaidTool(await forge({ tep: seeded.token_epoch }))).status).toBe(200);
		await expectCutOff(await forge({ tep: seeded.token_epoch - 1 }), undefined);
		await expectCutOff(await forge({}), undefined);
	});
});

describe('EMA self-serve tenants and operator approval', () => {
	const TENANT = 'web-acme-corp-0001';
	const NOT_ACCEPTED = { error: 'invalid_grant', error_description: 'Assertion not accepted' };

	/** bv-web's settings save over the self-serve seam (mint key). */
	function selfServe(overrides: Record<string, unknown> = {}): Promise<Response> {
		return send(
			internalRequest('PUT', `/oauth/ema-self-serve/${TENANT}`, MINT_KEY, {
				name: 'Acme Corp',
				issuer: IDP_ISSUER,
				enabled: true,
				tier: 'developer',
				entitlement_expires_at: Math.floor(Date.now() / 1000) + 86_400,
				...overrides,
			}),
		);
	}

	/** Operator approval with the reviewed snapshot (admin key). */
	async function approve(): Promise<Response> {
		const record = (await getEmaTenant(REGISTRY, TENANT))!;
		const reviewed = { issuer: record.issuer, jwks_uri: record.jwks_uri, rev: record.rev ?? 0 };
		return send(internalRequest('POST', `/oauth/ema-tenants/${TENANT}/approve`, ADMIN_KEY, reviewed));
	}

	async function expectCutOff(token: string, sessionId: string | undefined): Promise<void> {
		expect((await send(mcpRequest(token, batchStatusCall, sessionId))).status).toBe(401);
	}

	it('a pending tenant is refused exactly like a disabled one; approval lets it mint at its tier', async () => {
		expect((await selfServe()).status).toBe(200);
		const pending = await exchange(await signIdJag());
		expect(pending.status).toBe(400);
		expect(await pending.json()).toEqual(NOT_ACCEPTED);

		expect((await approve()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		expect(decodeClaims(token).sub).toMatch(/^ema:web-acme-corp-0001:[0-9a-f]{32}$/);
		const call = await callPaidTool(token);
		expect(call.status).toBe(200);
		expect(call.tier).toBe('developer');
	});

	it('an issuer change returns the tenant to pending and kills its tokens; re-approval does not revive them', async () => {
		expect((await selfServe()).status).toBe(200);
		expect((await approve()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);

		const moved = await selfServe({ issuer: OTHER_IDP_ISSUER });
		expect(((await moved.json()) as { approval: string }).approval).toBe('pending');
		await expectCutOff(token, before.sessionId);
		// Neither the old issuer (released) nor the new one (pending) mints.
		expect(await (await exchange(await signIdJag())).json()).toEqual(NOT_ACCEPTED);
		expect(await (await exchange(await signIdJag(otherIdp))).json()).toEqual(NOT_ACCEPTED);

		expect((await approve()).status).toBe(200);
		await expectCutOff(token, before.sessionId);
		expect((await callPaidTool(await mintToken(await signIdJag(otherIdp)))).status).toBe(200);
	});

	it('a routine same-issuer renewal keeps the approval and the live tokens', async () => {
		expect((await selfServe()).status).toBe(200);
		expect((await approve()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);

		const renewed = await selfServe({ entitlement_expires_at: Math.floor(Date.now() / 1000) + 30 * 86_400 });
		expect(((await renewed.json()) as { approval: string }).approval).toBe('approved');
		expect((await send(mcpRequest(token, batchStatusCall, before.sessionId))).status).toBe(200);
	});

	it('a revoke from bv-web lands while the IdP discovery document is gone: live tokens are cut off and nothing mints', async () => {
		expect((await selfServe()).status).toBe(200);
		expect((await approve()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);

		delete documents[`${IDP_ISSUER}/.well-known/openid-configuration`];
		const revoked = await selfServe({ enabled: false });
		expect(revoked.status).toBe(200);
		expect(((await revoked.json()) as { approval: string }).approval).toBe('approved');
		await expectCutOff(token, before.sessionId);
		expect(await (await exchange(await signIdJag())).json()).toEqual(NOT_ACCEPTED);
	});

	it('a rejected tenant mints nothing, and a same-issuer re-save stays rejected', async () => {
		expect((await selfServe()).status).toBe(200);
		expect((await approve()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		expect((await send(internalRequest('POST', `/oauth/ema-tenants/${TENANT}/reject`, ADMIN_KEY, undefined))).status).toBe(200);
		await expectCutOff(token, undefined);
		expect(await (await exchange(await signIdJag())).json()).toEqual(NOT_ACCEPTED);
		expect(((await (await selfServe({ name: 'Acme again' })).json()) as { approval: string }).approval).toBe('rejected');
	});

	it('F3 stale snapshot: a self-serve save whose pre-read predates the reject cannot reverse it', async () => {
		expect((await selfServe()).status).toBe(200);
		expect((await approve()).status).toBe(200);
		const preReject = (await getEmaTenant(REGISTRY, TENANT))!;
		expect((await send(internalRequest('POST', `/oauth/ema-tenants/${TENANT}/reject`, ADMIN_KEY, undefined))).status).toBe(200);

		// The route's own read answers the approved, pre-reject record; the write is decided inside the registry.
		const staleRead = interceptCoordinator(['ema-get'], async () => ({ status: 'ok', record: preReject }));
		const saved = await swapBinding('QUOTA_COORDINATOR', staleRead, () => selfServe({ name: 'Acme renamed' }));
		expect(saved.status).toBe(200);
		expect(((await saved.json()) as { approval: string }).approval).toBe('rejected');
		const stored = (await getEmaTenant(REGISTRY, TENANT))!;
		expect(stored.approval).toBe('rejected');
		expect(stored.rejected_issuer_hashes).toHaveLength(1);
		expect(await (await exchange(await signIdJag())).json()).toEqual(NOT_ACCEPTED);
	});

	it('pending is checked per request too: an issued token stops resolving while its tenant is pending', async () => {
		expect((await seedTenant()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);
		// Same epoch, approval alone flipped, so only the approval check can reject.
		const record = (await getEmaTenant(REGISTRY, 'acme-corp'))!;
		await putRegistryRecord({ ...record, approval: 'pending' });
		await expectCutOff(token, before.sessionId);
		await putRegistryRecord({ ...record, approval: 'approved' });
		expect((await send(mcpRequest(token, batchStatusCall, before.sessionId))).status).toBe(200);
	});

	it('a legacy operator record with neither approval nor source still exchanges and resolves', async () => {
		expect((await seedTenant()).status).toBe(200);
		const { approval: _approval, source: _source, ...legacy } = (await getEmaTenant(REGISTRY, 'acme-corp'))!;
		await putRegistryRecord(legacy);
		expect(await getEmaTenant(REGISTRY, 'acme-corp')).not.toHaveProperty('source');
		expect((await callPaidTool(await mintToken(await signIdJag()))).status).toBe(200);
	});
});

describe('EMA tenant token epoch on the upsert route', () => {
	async function storedRecord() {
		return (await getEmaTenant(REGISTRY, 'acme-corp'))!;
	}

	/** The authority: the epoch inside the registry record. */
	const currentEpoch = async () => tenantEpoch(await storedRecord());

	/** A coordinator that fails ONLY the given EMA registry kinds, so the rest of the mint and the call still run. */
	function coordinatorFailing(kinds: string[]): unknown {
		return interceptCoordinator(kinds, async () => {
			throw new Error('coordinator unavailable');
		});
	}

	it('settles the epoch in the registry record: set on create, kept on an enabled update and a re-enable, bumped on enabled true -> false', async () => {
		const seeded = (await (await seedTenant()).json()) as { token_epoch: number };
		const created = await currentEpoch();
		expect(created).toBeGreaterThanOrEqual(1);
		expect(seeded.token_epoch).toBe(created);

		expect((await seedTenant({ name: 'Acme Renamed' })).status).toBe(200);
		expect(await currentEpoch()).toBe(created);

		expect((await seedTenant({ enabled: false })).status).toBe(200);
		const suspended = await currentEpoch();
		expect(suspended).toBeGreaterThan(created);

		expect((await seedTenant({ enabled: false, name: 'Still suspended' })).status).toBe(200);
		expect(await currentEpoch()).toBe(suspended);
		expect((await seedTenant({ enabled: true })).status).toBe(200);
		expect(await currentEpoch()).toBe(suspended);
	});

	it('moves the epoch when the entitlement moves earlier, and keeps it on a later one', async () => {
		const now = Math.floor(Date.now() / 1000);
		expect((await seedTenant({ entitlement_expires_at: now + 3600 })).status).toBe(200);
		const created = await currentEpoch();
		expect((await seedTenant({ entitlement_expires_at: now + 7200 })).status).toBe(200);
		expect(await currentEpoch()).toBe(created);
		expect((await seedTenant({ entitlement_expires_at: now + 1800 })).status).toBe(200);
		expect(await currentEpoch()).toBeGreaterThan(created);
	});

	it('M3: dropping an allowed client kills the tokens minted before it, and adding it back does not revive them', async () => {
		const OTHER_CLIENT = 'https://other.example.com/client.json';
		expect((await seedTenant()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		// Adding a client keeps the epoch: the standing token still works.
		expect((await seedTenant({ allowed_client_ids: [WEB_CLIENT_ID, OTHER_CLIENT] })).status).toBe(200);
		const kept = await callPaidTool(token);
		expect(kept.status).toBe(200);
		expect((await seedTenant({ allowed_client_ids: [OTHER_CLIENT] })).status).toBe(200);
		expect((await seedTenant({ allowed_client_ids: [WEB_CLIENT_ID, OTHER_CLIENT] })).status).toBe(200);
		expect((await send(mcpRequest(token, batchStatusCall, kept.sessionId))).status).toBe(401);
	});

	it('M5: a sealed legacy KV tenant is imported on first use and exchanges; KV keeps its copy but is never read or written again', async () => {
		const legacy = { ...legacyTenant(), token_epoch: 7 };
		await putLegacyKvTenant(legacy);
		const sealed = await env.SESSION_STORE.get('oauth:ema-tenant:acme-corp');
		const token = await mintToken(await signIdJag());
		expect(decodeClaims(token).tep).toBe(7);
		expect((await callPaidTool(token)).status).toBe(200);
		expect((await storedRecord()).token_epoch).toBe(7);
		// Later writes go to the registry only. The KV copy stays byte-identical (one release of rollback), and
		// the still-enabled copy never speaks again: the disabled registry record alone decides the exchange.
		expect((await seedTenant({ enabled: false })).status).toBe(200);
		expect(await env.SESSION_STORE.get('oauth:ema-tenant:acme-corp')).toBe(sealed);
		expect(await env.SESSION_STORE.get(`oauth:ema-issuer:${await sha256Hex(IDP_ISSUER)}`)).toBe('acme-corp');
		expect((await exchange(await signIdJag())).status).toBe(400);
	});

	it('a token minted under a legacy record (tep = created_at) stays valid across the import until the first revoke', async () => {
		const legacy = legacyTenant();
		await putLegacyKvTenant(legacy);
		const forge = () =>
			signJwt(
				{
					sub: `ema:acme-corp:${'0'.repeat(32)}`,
					jti: crypto.randomUUID(),
					tier: 'developer',
					client_id: WEB_CLIENT_ID,
					entitlementGeneration: 1,
					tep: legacy.created_at,
				},
				{ secret: e2eEnv.OAUTH_SIGNING_SECRET!, ttlSeconds: 600, issuer: ISSUER, audience: `${ISSUER}/mcp` },
			);
		const before = await callPaidTool(await forge());
		expect(before.status).toBe(200);
		expect(await env.SESSION_STORE.get('oauth:ema-tenant:acme-corp')).not.toBeNull();

		expect((await seedTenant({ enabled: false })).status).toBe(200);
		expect((await seedTenant({ enabled: true })).status).toBe(200);
		expect((await send(mcpRequest(await forge(), batchStatusCall, before.sessionId))).status).toBe(401);
	});

	it('a sealed legacy record with no envelope key configured is a 503 at mint, never an unknown issuer', async () => {
		await putLegacyKvTenant(legacyTenant());
		const outage = await swapBinding('KV_ENVELOPE_KEY', undefined, async () => exchange(await signIdJag()));
		expect(outage.status).toBe(503);
		expect(await env.SESSION_STORE.get('oauth:ema-tenant:acme-corp')).not.toBeNull();
	});

	it('an unreachable registry is a retryable 503 at mint, before the assertion is consumed (never a 401, never a token)', async () => {
		expect((await seedTenant()).status).toBe(200);
		const assertion = await signIdJag();
		const outage = await swapBinding('QUOTA_COORDINATOR', coordinatorFailing(['ema-resolve-issuer']), () => exchange(assertion));
		expect(outage.status).toBe(503);
		expect((await callPaidTool(await mintToken(assertion))).status).toBe(200);
	});

	it('an unreachable registry is a 503 on a bearer request, never a 401 that would make the client re-exchange', async () => {
		expect((await seedTenant()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		const outage = await swapBinding('QUOTA_COORDINATOR', coordinatorFailing(['ema-get']), () =>
			send(mcpRequest(token, batchStatusCall, before.sessionId)),
		);
		expect(outage.status).toBe(503);
	});

	it('a revoking write the registry cannot apply is a 503 and changes nothing', async () => {
		expect((await seedTenant()).status).toBe(200);
		const before = await storedRecord();
		const outage = await swapBinding('QUOTA_COORDINATOR', coordinatorFailing(['ema-write']), () => seedTenant({ enabled: false }));
		expect(outage.status).toBe(503);
		expect(await storedRecord()).toEqual(before);
	});

	it('rejects a PUT body that tries to set token_epoch (server-managed)', async () => {
		expect((await seedTenant({ token_epoch: 1 })).status).toBe(400);
		expect(await getEmaTenant(REGISTRY, 'acme-corp')).toBeNull();
	});
});

describe('EMA registry regressions (SQ-467 F1 and F2, contract A11)', () => {
	const ROTATED_JWKS_URI = 'https://acme.okta.com/oauth2/v1/keys-rotated';

	/**
	 * A mint whose registry read (ema-resolve-issuer) completed BEFORE `write` landed, and which issues its
	 * token after it: the window in which the KV-backed store minted a token that outlived the revoke.
	 */
	async function mintAcross(write: () => Promise<Response>): Promise<string> {
		let fired = false;
		const racing = interceptCoordinator(['ema-resolve-issuer'], async (real, request) => {
			const before = await real(request);
			if (!fired) {
				fired = true;
				expect([200, 204]).toContain((await write()).status);
			}
			return before;
		});
		const assertion = await signIdJag();
		return swapBinding('QUOTA_COORDINATOR', racing, () => mintToken(assertion));
	}

	it('F1 key rotation: a token minted against the pre-rotation record dies once the rotation lands', async () => {
		expect((await seedTenant()).status).toBe(200);
		const rotated = await makeIdpKey('RS256', 'okta-rotated');
		documents[ROTATED_JWKS_URI] = { keys: [rotated.publicJwk] };

		const gapToken = await mintAcross(() => seedTenant({ jwks_uri: ROTATED_JWKS_URI }));
		expect((await callPaidTool(gapToken)).status).toBe(401);
		// The old key no longer mints; the rotated one does.
		expect((await exchange(await signIdJag())).status).toBe(400);
		expect((await callPaidTool(await mintToken(await signIdJag(rotated)))).status).toBe(200);
	});

	it('F1 re-enable: a token minted against the pre-disable record stays dead after the tenant is re-enabled', async () => {
		expect((await seedTenant()).status).toBe(200);
		const gapToken = await mintAcross(() => seedTenant({ enabled: false }));
		expect((await callPaidTool(gapToken)).status).toBe(401);

		expect((await seedTenant({ enabled: true })).status).toBe(200);
		expect((await callPaidTool(gapToken)).status).toBe(401);
		expect((await callPaidTool(await mintToken(await signIdJag()))).status).toBe(200);
	});

	it('F2 tier round trip: developer -> enterprise -> developer never revives a developer token', async () => {
		expect((await seedTenant()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);
		expect(before.tier).toBe('developer');

		expect((await seedTenant({ tier: 'enterprise' })).status).toBe(200);
		expect((await send(mcpRequest(token, batchStatusCall, before.sessionId))).status).toBe(401);
		expect((await seedTenant({ tier: 'developer' })).status).toBe(200);
		expect((await send(mcpRequest(token, batchStatusCall, before.sessionId))).status).toBe(401);
		expect((await callPaidTool(await mintToken(await signIdJag()))).status).toBe(200);
	});

	it('delete then re-create of the same tenant_id: a token minted in the delete window never validates', async () => {
		expect((await seedTenant()).status).toBe(200);
		const gapToken = await mintAcross(() => send(internalRequest('DELETE', '/oauth/ema-tenants/acme-corp', ADMIN_KEY, undefined)));
		expect((await callPaidTool(gapToken)).status).toBe(401);
		expect((await seedTenant()).status).toBe(200);
		expect((await callPaidTool(gapToken)).status).toBe(401);
		expect((await callPaidTool(await mintToken(await signIdJag()))).status).toBe(200);
	});
});

/** The registry as the Worker sees it (coordinator + the legacy-import KV and envelope key). */
const REGISTRY: EmaRegistry = { coordinator: env.QUOTA_COORDINATOR, kv: env.SESSION_STORE, kvEnvelopeKey: ENVELOPE_KEY };

/** Run with one worker binding swapped, restoring it afterwards. */
async function swapBinding<T>(
	name: 'QUOTA_COORDINATOR' | 'SESSION_STORE' | 'KV_ENVELOPE_KEY',
	replacement: unknown,
	run: () => Promise<T>,
): Promise<T> {
	const bindings = e2eEnv as unknown as Record<string, unknown>;
	const original = bindings[name];
	bindings[name] = replacement;
	try {
		return await run();
	} finally {
		bindings[name] = original;
	}
}

type CoordinatorRequest = { kind: string };
type RealDispatch = (request: CoordinatorRequest) => Promise<unknown>;

/** A coordinator binding that hands the given request kinds to `intercept` (with the real dispatch) and passes everything else through. */
function interceptCoordinator(kinds: string[], intercept: (real: RealDispatch, request: CoordinatorRequest) => Promise<unknown>): unknown {
	return {
		getByName: (name: string) => {
			const stub = env.QUOTA_COORDINATOR.getByName(name);
			const real: RealDispatch = (request) => stub.dispatch(request as never);
			return { dispatch: (request: CoordinatorRequest) => (kinds.includes(request.kind) ? intercept(real, request) : real(request)) };
		},
	};
}

/** A tenant record as the pre-registry store held it (no approval, no source, no token_epoch). */
function legacyTenant(): EmaTenantRecord {
	return {
		tenant_id: 'acme-corp',
		name: 'Acme Corp',
		issuer: IDP_ISSUER,
		jwks_uri: JWKS_URI,
		allowed_client_ids: [WEB_CLIENT_ID],
		tier: 'developer',
		enabled: true,
		created_at: 1_700_000_000,
		updated_at: 1_700_000_000,
	};
}

/** Write a tenant the way the pre-registry KV store did: sealed record plus the sha256 issuer index. */
async function putLegacyKvTenant(rec: EmaTenantRecord): Promise<void> {
	await env.SESSION_STORE.put(`oauth:ema-tenant:${rec.tenant_id}`, await sealKv(JSON.stringify(rec), ENVELOPE_KEY));
	await env.SESSION_STORE.put(`oauth:ema-issuer:${await sha256Hex(rec.issuer)}`, rec.tenant_id);
}

/** Overwrite one record directly in the registry shard (with its issuer index entry and epoch floor), bypassing every write rule. */
async function putRegistryRecord(rec: EmaTenantRecord): Promise<void> {
	await runInDurableObject(env.QUOTA_COORDINATOR.getByName(EMA_REGISTRY_INSTANCE_NAME), async (_instance, state) => {
		const indexKey = emaIssuerStorageKey(rec.issuer);
		await state.storage.put(emaRecordStorageKey(rec.tenant_id), rec);
		await state.storage.put(EMA_MIGRATED_STORAGE_KEY, { at: 0, imported: 0 });
		if (effectiveApproval(rec) === 'approved') await state.storage.put(indexKey, rec.tenant_id);
		else if ((await state.storage.get(indexKey)) === rec.tenant_id) await state.storage.delete(indexKey);
	});
}
