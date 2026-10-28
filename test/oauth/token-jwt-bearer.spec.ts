import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../../src/index';
import { resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';
import { OAUTH_JWT_TTL_SECONDS } from '../../src/lib/config';
import { putEmaTenant } from '../../src/oauth/ema-tenants';
import { sha256Hex } from '../../src/oauth/jwks';
import { verifyJwt } from '../../src/oauth/jwt';
import type { EmaTenantRecord } from '../../src/schemas/ema';
import { clearKvPrefix } from '../helpers/kv';
import { pinRateLimitWindow } from '../helpers/rate-limit-window';

// RFC 7523 jwt-bearer grant carrying an ID-JAG (US-14 Enterprise Managed Auth). Every case
// drives the real /oauth/token route; only the IdP JWKS and Claude's Client ID Metadata
// Document are stubbed at the global fetch boundary.

const GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const TYP = 'oauth-id-jag+jwt';
const ISSUER = 'https://example.com';
const MCP_RESOURCE = `${ISSUER}/mcp`;
const IDP_ISSUER = 'https://acme.okta.com';
const JWKS_URI = 'https://acme.okta.com/oauth2/v1/keys';
const WEB_CLIENT_ID = 'https://claude.ai/oauth/mcp-oauth-client-metadata';
const CODE_CLIENT_ID = 'https://claude.ai/oauth/claude-code-client-metadata';
const TEST_SIGNING_SECRET = 'a'.repeat(32);
const TENANT_NOT_ACCEPTED = 'Assertion not accepted';
const OTHER_IDP_ISSUER = 'https://globex.okta.com';
const OTHER_JWKS_URI = 'https://globex.okta.com/oauth2/v1/keys';

type TestEnv = typeof env & { OAUTH_SIGNING_SECRET?: string; OAUTH_ISSUER?: string };
const grantEnv = { ...env, OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET, OAUTH_ISSUER: ISSUER } as TestEnv;

interface Signer {
	kid: string;
	privateKey: CryptoKey;
	publicJwk: JsonWebKey & { kid: string };
}

const encoder = new TextEncoder();

function b64url(bytes: ArrayBuffer | Uint8Array): string {
	let binary = '';
	for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const b64urlJson = (value: unknown) => b64url(encoder.encode(JSON.stringify(value)));

function decodePayload(jwt: string): Record<string, unknown> {
	const payload = jwt.split('.')[1];
	return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>;
}

async function makeSigner(kid: string): Promise<Signer> {
	const pair = (await crypto.subtle.generateKey(
		{ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
		true,
		['sign', 'verify'],
	)) as CryptoKeyPair;
	const pub = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
	return { kid, privateKey: pair.privateKey, publicJwk: { kty: 'RSA', n: pub.n, e: pub.e, kid, use: 'sig', alg: 'RS256' } };
}

const nowSeconds = () => Math.floor(Date.now() / 1000);

function idJagClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	const now = nowSeconds();
	return {
		iss: IDP_ISSUER,
		sub: '00u1abcd2EFGH3ijk4l5',
		aud: ISSUER,
		client_id: WEB_CLIENT_ID,
		jti: crypto.randomUUID(),
		iat: now,
		exp: now + 300,
		resource: MCP_RESOURCE,
		scope: 'mcp',
		email: 'alice@acme.example',
		...overrides,
	};
}

async function signIdJag(
	signer: Signer,
	claims: Record<string, unknown> = idJagClaims(),
	header: Record<string, unknown> = {},
): Promise<string> {
	const signingInput = `${b64urlJson({ alg: 'RS256', typ: TYP, kid: signer.kid, ...header })}.${b64urlJson(claims)}`;
	const signature = await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, signer.privateKey, encoder.encode(signingInput));
	return `${signingInput}.${b64url(signature)}`;
}

/** A well-formed compact JWS with a junk signature: enough to be routed and counted, cheap to mint in bulk. */
function unsignedIdJag(claims: Record<string, unknown>): string {
	return `${b64urlJson({ alg: 'RS256', typ: TYP, kid: 'junk' })}.${b64urlJson(claims)}.${b64url(encoder.encode('junk'))}`;
}

function tenant(overrides: Partial<EmaTenantRecord> = {}): EmaTenantRecord {
	return {
		tenant_id: 'acme-corp',
		name: 'Acme Corp',
		issuer: IDP_ISSUER,
		jwks_uri: JWKS_URI,
		allowed_client_ids: [WEB_CLIENT_ID],
		tier: 'enterprise',
		enabled: true,
		created_at: 1_700_000_000,
		updated_at: 1_700_000_000,
		...overrides,
	};
}

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

function webCimdDocument(): Record<string, unknown> {
	return {
		client_id: WEB_CLIENT_ID,
		client_name: 'Claude',
		redirect_uris: ['https://claude.ai/api/mcp/auth_callback'],
		grant_types: ['authorization_code', 'refresh_token', GRANT_TYPE],
		token_endpoint_auth_method: 'none',
	};
}

/** What the stubbed network serves; tests mutate it before the request under test. */
let served: { jwksKeys: JsonWebKey[]; otherKeys: JsonWebKey[]; cimdStatus: number };
let jwksFetches: number;

function urlOf(input: RequestInfo | URL): string {
	if (typeof input === 'string') return input;
	return input instanceof URL ? input.href : input.url;
}

function stubNetwork(): void {
	vi.stubGlobal(
		'fetch',
		vi.fn(async (input: RequestInfo | URL) => {
			const url = urlOf(input);
			if (url === JWKS_URI) {
				jwksFetches++;
				return jsonResponse({ keys: served.jwksKeys });
			}
			if (url === OTHER_JWKS_URI) return jsonResponse({ keys: served.otherKeys });
			if (url === WEB_CLIENT_ID) return served.cimdStatus === 200 ? jsonResponse(webCimdDocument()) : new Response('nope', { status: 404 });
			return new Response('not found', { status: 404 });
		}),
	);
}

function uniqueIp(): string {
	const words = new Uint16Array(4);
	crypto.getRandomValues(words);
	return `2001:db8:0:0:${Array.from(words, (word) => word.toString(16)).join(':')}`;
}

async function postToken(params: Record<string, string>, customEnv: TestEnv = grantEnv, ip: string | null = uniqueIp()): Promise<Response> {
	const request = new Request<unknown, IncomingRequestCfProperties>(`${ISSUER}/oauth/token`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(ip === null ? {} : { 'cf-connecting-ip': ip }) },
		body: new URLSearchParams(params).toString(),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

function grantParams(assertion: string, extra: Record<string, string> = {}): Record<string, string> {
	return { grant_type: GRANT_TYPE, assertion, client_id: WEB_CLIENT_ID, ...extra };
}

async function expectError(response: Response, status: number, error: string): Promise<Record<string, unknown>> {
	expect(response.status).toBe(status);
	expect(response.headers.get('cache-control')).toContain('no-store');
	const body = (await response.json()) as Record<string, unknown>;
	expect(body.error).toBe(error);
	expect(typeof body.error_description).toBe('string');
	return body;
}

let signer: Signer;
let rogue: Signer;

beforeAll(async () => {
	signer = await makeSigner('k1');
	rogue = await makeSigner('k1');
});

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
	served = { jwksKeys: [signer.publicJwk], otherKeys: [], cimdStatus: 200 };
	jwksFetches = 0;
	stubNetwork();
	await putEmaTenant(env.SESSION_STORE, tenant());
});

afterEach(async () => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('POST /oauth/token grant_type=jwt-bearer (ID-JAG)', () => {
	it('mints a tenant-tier access token with scope mcp and no refresh_token', async () => {
		const response = await postToken(grantParams(await signIdJag(signer), { resource: MCP_RESOURCE, scope: 'mcp' }));

		expect(response.status).toBe(200);
		expect(response.headers.get('cache-control')).toContain('no-store');
		const body = (await response.json()) as Record<string, unknown>;
		expect(body).toEqual({ access_token: expect.any(String), token_type: 'Bearer', expires_in: OAUTH_JWT_TTL_SECONDS, scope: 'mcp' });
		expect(body).not.toHaveProperty('refresh_token');

		const claims = await verifyJwt(body.access_token as string, { secret: TEST_SIGNING_SECRET, issuer: ISSUER, audience: MCP_RESOURCE });
		expect(claims.sub).toMatch(/^ema:acme-corp:[0-9a-f]{32}$/);
		expect(claims.tier).toBe('enterprise');
		expect(claims.client_id).toBe(WEB_CLIENT_ID);
		expect(claims.entitlementGeneration).toBe(1);
		// The raw IdP subject and email never reach the token.
		expect(JSON.stringify(claims)).not.toContain('00u1abcd2EFGH3ijk4l5');
		expect(JSON.stringify(claims)).not.toContain('alice@acme.example');
	});

	it('logs one structured issuance line without the raw subject or email', async () => {
		const log = vi.spyOn(console, 'log').mockImplementation(() => {});
		expect((await postToken(grantParams(await signIdJag(signer)))).status).toBe(200);

		const lines = log.mock.calls.map(([line]) => String(line)).filter((line) => line.includes('ema_token_issued'));
		expect(lines).toHaveLength(1);
		const event = JSON.parse(lines[0]) as { severity: string; details: Record<string, unknown> };
		expect(event.severity).toBe('info');
		expect(event.details).toEqual({
			emaTenant: 'acme-corp',
			clientHost: 'claude.ai',
			subHashPrefix: expect.stringMatching(/^[0-9a-f]{12}$/),
		});
		expect(lines[0]).not.toContain('00u1abcd2EFGH3ijk4l5');
		expect(lines[0]).not.toContain('alice@acme.example');
	});

	it('derives one stable subject per IdP user across exchanges', async () => {
		const first = (await (await postToken(grantParams(await signIdJag(signer)))).json()) as { access_token: string };
		const second = (await (await postToken(grantParams(await signIdJag(signer)))).json()) as { access_token: string };
		expect(decodePayload(first.access_token).sub).toBe(decodePayload(second.access_token).sub);
	});

	it('accepts a one-element aud array and a request without resource', async () => {
		const response = await postToken(grantParams(await signIdJag(signer, idJagClaims({ aud: [ISSUER] }))));
		expect(response.status).toBe(200);
	});

	it('grants only mcp and ignores extra requested scopes', async () => {
		const response = await postToken(grantParams(await signIdJag(signer), { scope: 'openid profile email mcp offline_access' }));
		expect(response.status).toBe(200);
		expect(((await response.json()) as Record<string, unknown>).scope).toBe('mcp');
	});

	it('clamps the token lifetime to the tenant entitlement', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant({ entitlement_expires_at: nowSeconds() + 600 }));
		const response = await postToken(grantParams(await signIdJag(signer)));
		expect(response.status).toBe(200);
		const body = (await response.json()) as { expires_in: number };
		expect(body.expires_in).toBeGreaterThan(0);
		expect(body.expires_in).toBeLessThanOrEqual(600);
	});

	it('mints the developer tier for a developer tenant (never owner)', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant({ tier: 'developer' }));
		const body = (await (await postToken(grantParams(await signIdJag(signer)))).json()) as { access_token: string };
		expect(decodePayload(body.access_token).tier).toBe('developer');
	});

	it('refetches the JWKS once when the kid is unknown (IdP key rotation)', async () => {
		const rotated = await makeSigner('k2');
		// Prime the cache with the pre-rotation set, then rotate at the IdP.
		expect((await postToken(grantParams(await signIdJag(signer)))).status).toBe(200);
		served.jwksKeys = [signer.publicJwk, rotated.publicJwk];

		const response = await postToken(grantParams(await signIdJag(rotated)));

		expect(response.status).toBe(200);
		expect(jwksFetches).toBe(2);
	});

	it('rejects with unsupported_grant_type for an unknown grant', async () => {
		const response = await postToken({
			grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
			assertion: 'x',
			client_id: WEB_CLIENT_ID,
		});
		expect(response.status).toBe(400);
		expect(((await response.json()) as Record<string, unknown>).error).toBe('unsupported_grant_type');
	});

	it('rejects a request without an assertion as invalid_request', async () => {
		await expectError(await postToken({ grant_type: GRANT_TYPE, client_id: WEB_CLIENT_ID }), 400, 'invalid_request');
	});

	it('rejects a malformed assertion', async () => {
		await expectError(await postToken(grantParams('not-a-jwt')), 400, 'invalid_grant');
		await expectError(await postToken(grantParams('a.b.c')), 400, 'invalid_grant');
	});

	it('rejects an assertion whose typ is not oauth-id-jag+jwt', async () => {
		await expectError(await postToken(grantParams(await signIdJag(signer, idJagClaims(), { typ: 'JWT' }))), 400, 'invalid_grant');
	});

	it('rejects an issuer no tenant allowlists, even with a valid signature', async () => {
		const body = await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ iss: 'https://evil.okta.com' })))),
			400,
			'invalid_grant',
		);
		expect(body.error_description).toBe(TENANT_NOT_ACCEPTED);
		expect(jwksFetches).toBe(0);
	});

	it('rejects an assertion from a disabled tenant', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant({ enabled: false }));
		const body = await expectError(await postToken(grantParams(await signIdJag(signer))), 400, 'invalid_grant');
		expect(body.error_description).toBe(TENANT_NOT_ACCEPTED);
	});

	it('rejects an assertion once the tenant entitlement has expired', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant({ entitlement_expires_at: nowSeconds() - 10 }));
		const body = await expectError(await postToken(grantParams(await signIdJag(signer))), 400, 'invalid_grant');
		expect(body.error_description).toBe(TENANT_NOT_ACCEPTED);
	});

	it('rejects an issuer whose index entry points at a record that no longer lists it, with the same wording', async () => {
		// A stale index entry (issuer re-pointed at another tenant record) must not vouch for the issuer.
		const stale = 'https://stale.okta.com';
		await env.SESSION_STORE.put(`oauth:ema-issuer:${await sha256Hex(stale)}`, 'acme-corp');
		const body = await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ iss: stale })))),
			400,
			'invalid_grant',
		);
		expect(body.error_description).toBe(TENANT_NOT_ACCEPTED);
		expect(jwksFetches).toBe(0);
	});

	it('rejects a client the tenant does not allowlist with invalid_client', async () => {
		const assertion = await signIdJag(signer, idJagClaims({ client_id: CODE_CLIENT_ID }));
		await expectError(await postToken(grantParams(assertion, { client_id: CODE_CLIENT_ID })), 400, 'invalid_client');
	});

	it('rejects an allowlisted client whose metadata document cannot be resolved with invalid_client', async () => {
		served.cimdStatus = 404;
		await expectError(await postToken(grantParams(await signIdJag(signer))), 400, 'invalid_client');
	});

	it('rejects an assertion issued to a different client_id', async () => {
		await putEmaTenant(env.SESSION_STORE, tenant({ allowed_client_ids: [WEB_CLIENT_ID, CODE_CLIENT_ID] }));
		const assertion = await signIdJag(signer, idJagClaims({ client_id: CODE_CLIENT_ID }));
		await expectError(await postToken(grantParams(assertion)), 400, 'invalid_grant');
	});

	it('rejects a bad signature', async () => {
		await expectError(await postToken(grantParams(await signIdJag(rogue))), 400, 'invalid_grant');
	});

	it('rejects when the JWKS cannot be fetched', async () => {
		served.jwksKeys = [];
		await expectError(await postToken(grantParams(await signIdJag(signer))), 400, 'invalid_grant');
	});

	it('rejects an aud array with more than one element', async () => {
		await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ aud: [ISSUER, 'https://other.example'] })))),
			400,
			'invalid_grant',
		);
	});

	it('rejects an aud that names the token endpoint instead of the issuer', async () => {
		await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ aud: `${ISSUER}/oauth/token` })))),
			400,
			'invalid_grant',
		);
	});

	it('rejects an expired assertion', async () => {
		const now = nowSeconds();
		await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ iat: now - 400, exp: now - 60 })))),
			400,
			'invalid_grant',
		);
	});

	it('rejects an assertion issued in the future', async () => {
		const now = nowSeconds();
		await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ iat: now + 120, exp: now + 400 })))),
			400,
			'invalid_grant',
		);
	});

	it('rejects an assertion whose lifetime exceeds one hour', async () => {
		const now = nowSeconds();
		await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ iat: now, exp: now + 3601 })))),
			400,
			'invalid_grant',
		);
	});

	it('rejects non-integer exp/iat and a missing sub or jti', async () => {
		const now = nowSeconds();
		for (const overrides of [{ exp: `${now + 300}` }, { iat: now + 0.5 }, { sub: '' }, { jti: undefined }, { sub: 'x'.repeat(257) }]) {
			await expectError(await postToken(grantParams(await signIdJag(signer, idJagClaims(overrides)))), 400, 'invalid_grant');
		}
	});

	it('rejects a resource parameter that is not this MCP server with invalid_target', async () => {
		await expectError(
			await postToken(grantParams(await signIdJag(signer), { resource: 'https://other.example/mcp' })),
			400,
			'invalid_target',
		);
	});

	it('rejects a resource claim that is not this MCP server with invalid_target', async () => {
		await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ resource: 'https://other.example/mcp' })))),
			400,
			'invalid_target',
		);
	});

	it('rejects a replayed assertion (one-time jti)', async () => {
		const assertion = await signIdJag(signer);
		expect((await postToken(grantParams(assertion))).status).toBe(200);
		const body = await expectError(await postToken(grantParams(assertion)), 400, 'invalid_grant');
		expect(body.error_description).toBe('Assertion has already been used');
	});

	it('fails closed with 503 when the replay state is unavailable', async () => {
		// Without the coordinator the rate limit falls back to KV, but the one-time jti claim must not.
		const noCoordinatorEnv = { ...grantEnv, QUOTA_COORDINATOR: undefined } as unknown as TestEnv;
		const response = await postToken(grantParams(await signIdJag(signer)), noCoordinatorEnv);
		expect(response.status).toBe(503);
		expect(response.headers.get('cache-control')).toContain('no-store');
		expect(((await response.json()) as Record<string, unknown>).error).toBe('temporarily_unavailable');
	});

	it('fails closed with 503 when the tenant store cannot be read', async () => {
		const store = env.SESSION_STORE;
		// Only the issuer-index read fails; every other KV call reaches the real binding.
		const failingStore = new Proxy(store, {
			get(target, prop) {
				const value: unknown = Reflect.get(target, prop);
				if (prop !== 'get' || typeof value !== 'function') return typeof value === 'function' ? value.bind(target) : value;
				return (key: string, ...rest: unknown[]) =>
					key.startsWith('oauth:ema-issuer:') ? Promise.reject(new Error('kv outage')) : value.call(target, key, ...rest);
			},
		});
		const response = await postToken(grantParams(await signIdJag(signer)), { ...grantEnv, SESSION_STORE: failingStore } as TestEnv);
		expect(response.status).toBe(503);
		expect(((await response.json()) as Record<string, unknown>).error).toBe('temporarily_unavailable');
	});

	it('rejects a request on a Host that does not match the pinned issuer before any outbound fetch', async () => {
		const pinnedElsewhere = { ...grantEnv, OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com' } as TestEnv;
		await expectError(await postToken(grantParams(await signIdJag(signer)), pinnedElsewhere), 400, 'invalid_request');
		expect(jwksFetches).toBe(0);
	});

	it('does not gate jwt-bearer on the shared 30/min per-IP bucket (a known IP is limited per issuer instead)', async () => {
		pinRateLimitWindow();
		const ip = uniqueIp();
		for (let i = 0; i < 31; i++) {
			expect((await postToken({ grant_type: GRANT_TYPE, client_id: WEB_CLIENT_ID }, grantEnv, ip)).status).toBe(400);
		}
		expect((await postToken(grantParams(await signIdJag(signer)), grantEnv, ip)).status).toBe(200);
	});

	it('keeps the shared per-IP bucket for jwt-bearer when the client IP is unknown (never rejected outright)', async () => {
		pinRateLimitWindow();
		for (let i = 0; i < 30; i++) {
			expect((await postToken({ grant_type: GRANT_TYPE, client_id: WEB_CLIENT_ID }, grantEnv, null)).status).toBe(400);
		}
		const limited = await postToken(grantParams(await signIdJag(signer)), grantEnv, null);
		expect(limited.status).toBe(429);
		expect(((await limited.json()) as Record<string, unknown>).error).toBe('invalid_request');
	});

	it('limits jwt-bearer per (IP, issuer): the 121st exchange for one issuer is 429 while another issuer on that IP succeeds', async () => {
		pinRateLimitWindow();
		const ip = uniqueIp();
		// Exchanges from one claimed issuer, rejected cheaply (untrusted issuer: no JWKS or CIMD fetch) but each counted.
		const flood = unsignedIdJag(idJagClaims({ iss: 'https://flood.okta.com' }));
		for (let i = 0; i < 120; i++) {
			expect((await postToken(grantParams(flood), grantEnv, ip)).status).toBe(400);
		}
		const limited = await postToken(grantParams(flood), grantEnv, ip);
		expect(limited.status).toBe(429);
		expect(await limited.json()).toEqual({ error: 'invalid_request', error_description: 'Too many token requests' });

		// A second issuer from the SAME IP is unaffected.
		const other = await makeSigner('g1');
		await putEmaTenant(env.SESSION_STORE, tenant({ tenant_id: 'globex', issuer: OTHER_IDP_ISSUER, jwks_uri: OTHER_JWKS_URI }));
		served.otherKeys = [other.publicJwk];
		const accepted = await postToken(grantParams(await signIdJag(other, idJagClaims({ iss: OTHER_IDP_ISSUER }))), grantEnv, ip);
		expect(accepted.status).toBe(200);
		// The same IP's bucket for the first issuer stays closed.
		expect((await postToken(grantParams(flood), grantEnv, ip)).status).toBe(429);
	});

	it('keys the issuer bucket on the NORMALIZED issuer (trailing slash and host case cannot mint a fresh bucket)', async () => {
		pinRateLimitWindow();
		const ip = uniqueIp();
		const variants = ['https://flood.okta.com', 'https://flood.okta.com/', 'https://FLOOD.okta.com'];
		for (let i = 0; i < 120; i++) {
			const iss = variants[i % variants.length];
			expect((await postToken(grantParams(unsignedIdJag(idJagClaims({ iss }))), grantEnv, ip)).status).toBe(400);
		}
		expect((await postToken(grantParams(unsignedIdJag(idJagClaims({ iss: 'https://flood.okta.com/' }))), grantEnv, ip)).status).toBe(429);
	});

	it('caps one IP across issuers at 600/min (the per-IP abuse backstop)', async () => {
		pinRateLimitWindow();
		const ip = uniqueIp();
		const assertionFor = (n: number) => unsignedIdJag(idJagClaims({ iss: `https://tenant-${n}.okta.com` }));
		for (let i = 0; i < 600; i++) {
			expect((await postToken(grantParams(assertionFor(i)), grantEnv, ip)).status).toBe(400);
		}
		expect((await postToken(grantParams(assertionFor(600)), grantEnv, ip)).status).toBe(429);
	});

	it('answers 503 with Retry-After when the jwt-bearer limiter state is unavailable', async () => {
		pinRateLimitWindow();
		const brokenCoordinator = { idFromName: () => ({}), get: () => ({ fetch: () => Promise.reject(new Error('do down')) }) };
		const response = await postToken(grantParams(await signIdJag(signer)), {
			...grantEnv,
			QUOTA_COORDINATOR: brokenCoordinator,
		} as unknown as TestEnv);
		expect(response.status).toBe(503);
		expect(response.headers.get('retry-after')).toMatch(/^\d+$/);
		expect(((await response.json()) as Record<string, unknown>).error).toBe('temporarily_unavailable');
	});
});
