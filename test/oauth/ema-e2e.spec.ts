import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../../src/index';
import { resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';
import { clearKvPrefix } from '../helpers/kv';

// US-14 Enterprise Managed Auth, end to end through the real Worker:
//   operator seeds a tenant (PUT /internal/oauth/ema-tenants, jwks_uri from OIDC discovery)
//   → Claude exchanges an IdP-signed ID-JAG (POST /oauth/token, jwt-bearer)
//   → the minted bearer calls a paid-only tool on /mcp at the TENANT's tier
//   → /internal/oauth/revoke-subject on the ema subject kills that bearer.
// Only the IdP (discovery + JWKS) and Claude's CIMD document are stubbed, at global fetch.
// Further cases: an ES256 IdP, the enterprise tier, per-tenant replay scoping, and the effect of
// disabling a tenant after a token was minted.

const ISSUER = 'https://example.com';
const IDP_ISSUER = 'https://acme.okta.com';
const JWKS_URI = 'https://acme.okta.com/oauth2/v1/keys';
const OTHER_IDP_ISSUER = 'https://globex.okta.com';
const OTHER_JWKS_URI = 'https://globex.okta.com/oauth2/v1/keys';
const WEB_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const MINT_KEY = 'mint-capability-test-key-32-bytes-minimum';
const REVOKE_KEY = 'revoke-capability-test-key-32-bytes-minimum';

type TestEnv = typeof env & {
	OAUTH_SIGNING_SECRET?: string;
	OAUTH_ISSUER?: string;
	BV_MCP_OAUTH_MINT_KEY?: string;
	BV_MCP_OAUTH_REVOKE_KEY?: string;
};
const e2eEnv = {
	...env,
	OAUTH_SIGNING_SECRET: 'a'.repeat(32),
	OAUTH_ISSUER: ISSUER,
	BV_MCP_OAUTH_MINT_KEY: MINT_KEY,
	BV_MCP_OAUTH_REVOKE_KEY: REVOKE_KEY,
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
		internalRequest('PUT', '/oauth/ema-tenants', MINT_KEY, {
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

async function mintToken(assertion: string): Promise<string> {
	const response = await exchange(assertion);
	expect(response.status).toBe(200);
	return ((await response.json()) as { access_token: string }).access_token;
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

	it('stops minting once a tenant is disabled, while an already-minted token resolves until its own expiry', async () => {
		expect((await seedTenant()).status).toBe(200);
		const token = await mintToken(await signIdJag());
		const before = await callPaidTool(token);
		expect(before.status).toBe(200);

		expect((await seedTenant({ enabled: false })).status).toBe(200);

		const rejected = await exchange(await signIdJag());
		expect(rejected.status).toBe(400);
		expect(await rejected.json()).toEqual({ error: 'invalid_grant', error_description: 'Assertion not accepted' });
		// Documented gap, not a guarantee: disabling a tenant stops FUTURE exchanges only. The minted bearer
		// keeps resolving until its TTL (or a per-subject /internal/oauth/revoke-subject). SQ-434 tracks a
		// tenant-wide revoke; when it lands this assertion flips to 401 and this test must be updated.
		const after = await callPaidTool(token);
		expect(after.status).toBe(200);
		expect(after.tier).toBe('developer');
	});
});
