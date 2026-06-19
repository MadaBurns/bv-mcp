import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';
import { signJwt, newJti } from '../../src/oauth/jwt';
import { revokeJti } from '../../src/oauth/storage';
import { OAUTH_JWT_TTL_SECONDS } from '../../src/lib/config';

// Phase 8: /mcp must accept a valid OAuth 2.1 JWT issued by /oauth/token in the
// `Authorization: Bearer` header and resolve it as owner tier without re-running
// the OWNER_ALLOW_IPS gate (consent already enforced it — see Phase 6 amendment).
//
// These tests hit the real `/mcp` POST path with a minimal JSON-RPC `initialize`
// body so the auth middleware runs in isolation from DNS / tools dispatch.

const TEST_SIGNING_SECRET = 'a'.repeat(32);
const TEST_API_KEY = 'testkey';

type TestEnv = typeof env & { BV_API_KEY?: string; OAUTH_SIGNING_SECRET?: string; OAUTH_ISSUER?: string };

const jwtEnv = {
	...env,
	BV_API_KEY: TEST_API_KEY,
	OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET,
	OAUTH_ISSUER: 'https://example.com',
} as TestEnv;

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

async function mintOAuthJwt(opts?: {
	secret?: string;
	issuer?: string;
	audience?: string;
	jti?: string;
	sub?: string;
	tier?: 'owner' | 'developer' | 'enterprise' | 'agent';
}): Promise<{ token: string; jti: string }> {
	const issuer = opts?.issuer ?? 'https://example.com';
	const audience = opts?.audience ?? `${issuer}/mcp`;
	const jti = opts?.jti ?? newJti();
	const token = await signJwt(
		{ sub: opts?.sub ?? 'owner', jti, tier: opts?.tier ?? 'owner', client_id: 'test-client' },
		{ secret: opts?.secret ?? TEST_SIGNING_SECRET, ttlSeconds: OAUTH_JWT_TTL_SECONDS, issuer, audience },
	);
	return { token, jti };
}

const mintOwnerJwt = mintOAuthJwt;

function mcpInitRequest(token: string): Request<unknown, IncomingRequestCfProperties> {
	return new Request<unknown, IncomingRequestCfProperties>('https://example.com/mcp', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${token}`,
		},
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
	});
}

beforeEach(async () => {
	await clearPrefix('oauth:');
});
afterEach(async () => {
	await clearPrefix('oauth:');
});

describe('POST /mcp Bearer JWT acceptance', () => {
	it('valid OAuth JWT → authenticated (NOT 401)', async () => {
		const { token } = await mintOwnerJwt();
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), jwtEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).not.toBe(401);
	});

	it('JWT signed with wrong secret → 401', async () => {
		const { token } = await mintOwnerJwt({ secret: 'b'.repeat(32) });
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), jwtEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(401);
	});

	it('JWT with revoked jti → 401', async () => {
		const { token, jti } = await mintOwnerJwt();
		await revokeJti(env.SESSION_STORE, jti, 60);
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), jwtEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(401);
	});

	it('static BV_API_KEY still authenticates (self-hosted fallback preserved)', async () => {
		// Regression guard: adding the JWT branch must not break the existing BV_API_KEY path.
		const request = new Request<unknown, IncomingRequestCfProperties>('https://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_API_KEY}`,
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, jwtEnv, ctx);
		await waitOnExecutionContext(ctx);
		// Tighter than `not.toBe(401)` — prove we actually reached the MCP handler and got a
		// healthy JSON-RPC response, not some other non-401 error status.
		expect(res.status).toBe(200);
	});

	it('valid developer-tier OAuth JWT → authenticated (NOT 401)', async () => {
		const { token } = await mintOAuthJwt({ sub: 'user_123', tier: 'developer' });
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), jwtEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).not.toBe(401);
	});

	it('JWT with wrong audience → 401', async () => {
		const { token } = await mintOwnerJwt({ audience: 'https://example.com/wrong' });
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), jwtEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(401);
	});

	it('JWT with wrong issuer → 401', async () => {
		const { token } = await mintOwnerJwt({ issuer: 'https://evil.example' });
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), jwtEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(401);
	});

	// Backward-compat pin for BSL self-hosters who leave OAUTH_ISSUER unset.
	// In that deployment, sign AND verify both derive the issuer from the request
	// Host (resolveIssuer with no envIssuer → `${protocol}//${host}`). The two are
	// symmetric, so a Host-derived-iss token minted for a given Host must still
	// verify when presented to that same Host. This guards against a future change
	// that forces strict issuer-pinning (requiring OAUTH_ISSUER) and would silently
	// 401 every self-hosted OAuth token.
	it('OAUTH_ISSUER unset → Host-derived-iss JWT still authenticates', async () => {
		// No OAUTH_ISSUER → issuer resolves from the request Host (https://example.com).
		const unsetIssuerEnv = {
			...env,
			BV_API_KEY: TEST_API_KEY,
			OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET,
			// OAUTH_ISSUER intentionally omitted
		} as TestEnv;
		// Mint with the Host-derived issuer the verify path will recompute for this Host.
		const { token } = await mintOAuthJwt({ issuer: 'https://example.com' });
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), unsetIssuerEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).not.toBe(401);
	});

	it('OAUTH_ISSUER unset → JWT whose iss is a different Host → 401', async () => {
		// Symmetric counterpart: even with OAUTH_ISSUER unset, a token whose iss was
		// derived for a DIFFERENT Host must not verify against this Host.
		const unsetIssuerEnv = {
			...env,
			BV_API_KEY: TEST_API_KEY,
			OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET,
		} as TestEnv;
		const { token } = await mintOAuthJwt({ issuer: 'https://other.example' });
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), unsetIssuerEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(401);
	});

	it('expired JWT → 401', async () => {
		// ttlSeconds: -60 puts exp well past the clock-skew window, so verifyJwt throws
		// `token expired`. Control flow falls through to the static-key branch which also
		// rejects (token string != BV_API_KEY) → 401.
		const jti = newJti();
		const token = await signJwt(
			{ sub: 'owner', jti, tier: 'owner', client_id: 'test-client' },
			{ secret: TEST_SIGNING_SECRET, ttlSeconds: -60, issuer: 'https://example.com', audience: 'https://example.com/mcp' },
		);
		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), jwtEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(401);
	});
});
