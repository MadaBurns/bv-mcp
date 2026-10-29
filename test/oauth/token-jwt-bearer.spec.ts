import { env, runInDurableObject, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../../src/index';
import { resetQuotaCoordinatorState, securityStateShardNameForKey, type QuotaCoordinator } from '../../src/lib/quota-coordinator';
import { MAX_REQUEST_BODY_BYTES, OAUTH_JWT_TTL_SECONDS } from '../../src/lib/config';
import { EMA_REGISTRY_KEY, effectiveApproval, emaIssuerStorageKey, emaRecordStorageKey } from '../../src/oauth/ema-tenants';
import { sha256Hex } from '../../src/oauth/jwks';
import { verifyJwt } from '../../src/oauth/jwt';
import type { EmaTenantRecord } from '../../src/schemas/ema';
import { clearKvPrefix } from '../helpers/kv';
import { pinRateLimitWindow } from '../helpers/rate-limit-window';

// Counts calls to the bounded body reader (the real reader still runs), so a test can show a
// request was rejected before its body was read.
const bodyReads = vi.hoisted(() => ({ count: 0 }));
vi.mock('../../src/lib/request-body', async (importOriginal) => {
	const actual = await importOriginal<typeof import('../../src/lib/request-body')>();
	return {
		...actual,
		readBoundedText: (...args: Parameters<typeof actual.readBoundedText>) => {
			bodyReads.count++;
			return actual.readBoundedText(...args);
		},
	};
});

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
let served: { jwksKeys: JsonWebKey[]; jwksStatus: number; otherKeys: JsonWebKey[]; cimdStatus: number };
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
				return jsonResponse({ keys: served.jwksKeys }, served.jwksStatus);
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
	served = { jwksKeys: [signer.publicJwk], jwksStatus: 200, otherKeys: [], cimdStatus: 200 };
	jwksFetches = 0;
	stubNetwork();
	await putRegistryRecord(tenant());
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
		expect(body).toEqual({
			access_token: expect.any(String),
			token_type: 'Bearer',
			expires_in: OAUTH_JWT_TTL_SECONDS,
			scope: 'mcp',
			resource: MCP_RESOURCE,
		});
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

	it('mints the registry record epoch as tep: token_epoch when set, created_at for a record written before it existed', async () => {
		const mintTep = async () => {
			const minted = (await (await postToken(grantParams(await signIdJag(signer)))).json()) as { access_token: string };
			return decodePayload(minted.access_token).tep;
		};
		expect(await mintTep()).toBe(1_700_000_000);

		// The record's own epoch, whatever it is: no other epoch source is read.
		await putRegistryRecord(tenant({ token_epoch: 1_800_000_000_123 }));
		expect(await mintTep()).toBe(1_800_000_000_123);
		await putRegistryRecord(tenant({ token_epoch: 1_800_000_000_124 }));
		expect(await mintTep()).toBe(1_800_000_000_124);
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
		await putRegistryRecord(tenant({ entitlement_expires_at: nowSeconds() + 600 }));
		const response = await postToken(grantParams(await signIdJag(signer)));
		expect(response.status).toBe(200);
		const body = (await response.json()) as { expires_in: number };
		expect(body.expires_in).toBeGreaterThan(0);
		expect(body.expires_in).toBeLessThanOrEqual(600);
	});

	it('mints the developer tier for a developer tenant (never owner)', async () => {
		await putRegistryRecord(tenant({ tier: 'developer' }));
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
		await putRegistryRecord(tenant({ enabled: false }));
		const body = await expectError(await postToken(grantParams(await signIdJag(signer))), 400, 'invalid_grant');
		expect(body.error_description).toBe(TENANT_NOT_ACCEPTED);
	});

	it('rejects an assertion once the tenant entitlement has expired', async () => {
		await putRegistryRecord(tenant({ entitlement_expires_at: nowSeconds() - 10 }));
		const body = await expectError(await postToken(grantParams(await signIdJag(signer))), 400, 'invalid_grant');
		expect(body.error_description).toBe(TENANT_NOT_ACCEPTED);
	});

	it('rejects an issuer whose index entry points at a record that no longer lists it, with the same wording', async () => {
		// A stale index entry (issuer re-pointed at another tenant record) must not vouch for the issuer.
		const stale = 'https://stale.okta.com';
		await runInDurableObject(env.QUOTA_COORDINATOR.getByName(securityStateShardNameForKey(EMA_REGISTRY_KEY)), (_instance, state) =>
			state.storage.put(emaIssuerStorageKey(stale), 'acme-corp'),
		);
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
		await putRegistryRecord(tenant({ allowed_client_ids: [WEB_CLIENT_ID, CODE_CLIENT_ID] }));
		const assertion = await signIdJag(signer, idJagClaims({ client_id: CODE_CLIENT_ID }));
		await expectError(await postToken(grantParams(assertion)), 400, 'invalid_grant');
	});

	it('rejects a bad signature', async () => {
		await expectError(await postToken(grantParams(await signIdJag(rogue))), 400, 'invalid_grant');
	});

	it('answers 503 temporarily_unavailable and logs the tenant once when the JWKS cannot be fetched', async () => {
		const failures: Array<[string, () => void]> = [
			['HTTP 500', () => (served.jwksStatus = 500)],
			['an unusable key set', () => (served.jwksKeys = [])],
		];
		for (const [failure, arrange] of failures) {
			served = { ...served, jwksKeys: [signer.publicJwk], jwksStatus: 200 };
			arrange();
			const log = vi.spyOn(console, 'log').mockImplementation(() => {});
			const response = await postToken(grantParams(await signIdJag(signer)));
			const lines = log.mock.calls.map(([line]) => String(line)).filter((line) => line.includes('ema_jwks_unavailable'));
			log.mockRestore();

			const body = await expectError(response, 503, 'temporarily_unavailable');
			expect(body.error_description, failure).toBe('Issuer signing keys are unavailable');
			expect(lines, failure).toHaveLength(1);
			const event = JSON.parse(lines[0]) as { severity: string; error: string; details: Record<string, unknown> };
			expect(event.severity).toBe('warn');
			expect(event.details).toEqual({ emaTenant: 'acme-corp' });
			expect(event.error).toMatch(/^JWKS fetch failed: /);
			expect(lines[0]).not.toContain(JWKS_URI);
		}
	});

	it('stays invalid_grant when the kid is absent from a successfully fetched set, even after the forced refetch', async () => {
		const unknownKid = await makeSigner('k9');
		const body = await expectError(await postToken(grantParams(await signIdJag(unknownKid))), 400, 'invalid_grant');
		expect(body.error_description).toBe('Assertion signature is not valid');
		expect(jwksFetches).toBe(2);
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

	it('accepts the MCP resource with one trailing slash in the request parameter, and echoes the canonical form', async () => {
		const response = await postToken(grantParams(await signIdJag(signer), { resource: `${MCP_RESOURCE}/` }));
		expect(response.status).toBe(200);
		expect(((await response.json()) as Record<string, unknown>).resource).toBe(MCP_RESOURCE);
	});

	it('accepts the MCP resource with one trailing slash in the claim (string or one-element array)', async () => {
		for (const resource of [`${MCP_RESOURCE}/`, [MCP_RESOURCE], [`${MCP_RESOURCE}/`]]) {
			const response = await postToken(grantParams(await signIdJag(signer, idJagClaims({ resource }))));
			expect(response.status, JSON.stringify(resource)).toBe(200);
			expect(((await response.json()) as Record<string, unknown>).resource).toBe(MCP_RESOURCE);
		}
	});

	it('rejects /mcpx and a double trailing slash in the request parameter and the claim with invalid_target', async () => {
		for (const bad of [`${MCP_RESOURCE}x`, `${MCP_RESOURCE}//`, `${MCP_RESOURCE}/x`]) {
			await expectError(await postToken(grantParams(await signIdJag(signer), { resource: bad })), 400, 'invalid_target');
			await expectError(await postToken(grantParams(await signIdJag(signer, idJagClaims({ resource: bad })))), 400, 'invalid_target');
		}
	});

	it('echoes no resource when none was requested or claimed, and never a refresh_token', async () => {
		const response = await postToken(grantParams(await signIdJag(signer, idJagClaims({ resource: undefined }))));
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body).not.toHaveProperty('resource');
		expect(body).not.toHaveProperty('refresh_token');
		expect(body.scope).toBe('mcp');
	});

	it('echoes the resource when only the request parameter names it', async () => {
		const response = await postToken(
			grantParams(await signIdJag(signer, idJagClaims({ resource: undefined })), { resource: MCP_RESOURCE }),
		);
		expect(response.status).toBe(200);
		expect(((await response.json()) as Record<string, unknown>).resource).toBe(MCP_RESOURCE);
	});

	it('rejects a nbf in the future beyond the clock skew, with the shared expired-or-not-yet-valid wording', async () => {
		const now = nowSeconds();
		const body = await expectError(
			await postToken(grantParams(await signIdJag(signer, idJagClaims({ nbf: now + 600 })))),
			400,
			'invalid_grant',
		);
		expect(body.error_description).toBe('Assertion is expired or not yet valid');
	});

	it('accepts a nbf in the past or at now, and rejects a non-integer nbf', async () => {
		const now = nowSeconds();
		for (const nbf of [now - 60, now]) {
			expect((await postToken(grantParams(await signIdJag(signer, idJagClaims({ nbf }))))).status, `nbf=${nbf}`).toBe(200);
		}
		for (const nbf of [`${now}`, now - 0.5, null]) {
			await expectError(await postToken(grantParams(await signIdJag(signer, idJagClaims({ nbf })))), 400, 'invalid_grant');
		}
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

	it('fails closed with 503 when the tenant registry cannot be read', async () => {
		// Only the registry's issuer resolution fails; every other coordinator call reaches the real binding.
		const failing = {
			getByName: (name: string) => {
				const stub = env.QUOTA_COORDINATOR.getByName(name);
				return {
					dispatch: (request: { kind: string }) =>
						request.kind === 'ema-resolve-issuer' ? Promise.reject(new Error('registry outage')) : stub.dispatch(request as never),
				};
			},
		} as unknown as DurableObjectNamespace<QuotaCoordinator>;
		const response = await postToken(grantParams(await signIdJag(signer)), { ...grantEnv, QUOTA_COORDINATOR: failing } as TestEnv);
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
		await putRegistryRecord(tenant({ tenant_id: 'globex', issuer: OTHER_IDP_ISSUER, jwks_uri: OTHER_JWKS_URI }));
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

/** A junk authorization_code request padded to exactly the body cap: the most a flood can make us read. */
function maxSizeCodeExchange(): Record<string, string> {
	const params = { grant_type: 'authorization_code', code: 'bogus', client_id: 'bogus', redirect_uri: 'https://x.example/cb', pad: '' };
	params.pad = 'a'.repeat(MAX_REQUEST_BODY_BYTES - new URLSearchParams(params).toString().length);
	return params;
}

describe('POST /oauth/token per-IP limits for every grant', () => {
	it('429s a known IP from the 31st request after the body read, and from the 601st before it', async () => {
		pinRateLimitWindow();
		const ip = uniqueIp();
		const params = maxSizeCodeExchange();
		expect(new URLSearchParams(params).toString()).toHaveLength(MAX_REQUEST_BODY_BYTES);
		for (let i = 0; i < 30; i++) {
			expect((await postToken(params, grantEnv, ip)).status).toBe(400);
		}

		// The shared 30/min bucket needs the grant type, so the 31st is limited after its body is read.
		bodyReads.count = 0;
		expect((await postToken(params, grantEnv, ip)).status).toBe(429);
		expect(bodyReads.count).toBe(1);
		for (let i = 31; i < 600; i++) {
			expect((await postToken(params, grantEnv, ip)).status).toBe(429);
		}

		// The per-IP ceiling runs before the read: the 601st body is never read.
		bodyReads.count = 0;
		const ceiling = await postToken(params, grantEnv, ip);
		expect(ceiling.status).toBe(429);
		expect(await ceiling.json()).toEqual({ error: 'invalid_request', error_description: 'Too many token requests' });
		expect(bodyReads.count).toBe(0);
	});

	it('never charges a jwt-bearer exchange from a known IP to the shared 30/min bucket', async () => {
		pinRateLimitWindow();
		const ip = uniqueIp();
		for (let i = 0; i < 31; i++) {
			expect((await postToken({ grant_type: GRANT_TYPE, client_id: WEB_CLIENT_ID }, grantEnv, ip)).status).toBe(400);
		}
		// The same IP's shared bucket is still empty, so a code exchange is not limited.
		expect((await postToken(maxSizeCodeExchange(), grantEnv, ip)).status).toBe(400);
	});
});

// A signed payload cannot differ from its own unverified decode, so the verified iss/client_id
// re-check is driven directly: routing picked tenant IDP_ISSUER for WEB_CLIENT_ID.
describe('validateIdJagClaims (verified payload re-checks the routing claims)', () => {
	const expected = { audience: ISSUER, tenantIssuer: IDP_ISSUER, clientId: WEB_CLIENT_ID };

	function thrownBy(run: () => unknown): unknown {
		try {
			run();
		} catch (error) {
			return error;
		}
		return undefined;
	}

	it('accepts verified claims whose iss normalizes to the routed tenant issuer', async () => {
		const { validateIdJagClaims } = await import('../../src/oauth/token');
		const claims = idJagClaims({ iss: 'https://ACME.okta.com/' });
		expect(validateIdJagClaims(claims, expected, nowSeconds())).toEqual({ sub: claims.sub, jti: claims.jti, exp: claims.exp });
	});

	it('rejects a verified iss or client_id that differs from the routing, with the uniform tenant wording', async () => {
		const { validateIdJagClaims } = await import('../../src/oauth/token');
		const mismatches: Array<Record<string, unknown>> = [
			{ iss: OTHER_IDP_ISSUER },
			{ iss: undefined },
			{ iss: 'not a url' },
			{ client_id: CODE_CLIENT_ID },
			{ client_id: undefined },
		];
		for (const overrides of mismatches) {
			const error = thrownBy(() => validateIdJagClaims(idJagClaims(overrides), expected, nowSeconds()));
			expect(error, JSON.stringify(overrides)).toMatchObject({ code: 'invalid_grant', message: TENANT_NOT_ACCEPTED });
		}
	});
});

/** Overwrite one record directly in the registry shard (with its issuer index entry), bypassing every write rule. */
async function putRegistryRecord(rec: EmaTenantRecord): Promise<void> {
	await runInDurableObject(env.QUOTA_COORDINATOR.getByName(securityStateShardNameForKey(EMA_REGISTRY_KEY)), async (_instance, state) => {
		await state.storage.put(emaRecordStorageKey(rec.tenant_id), rec);
		if (effectiveApproval(rec) === 'approved') await state.storage.put(emaIssuerStorageKey(rec.issuer), rec.tenant_id);
	});
}
