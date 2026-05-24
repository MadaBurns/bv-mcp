// SPDX-License-Identifier: BUSL-1.1
/**
 * FIND-13: Token-version claim + per-subject revoke endpoint tests.
 *
 * Covers:
 *   A. A JWT with ver=1 is rejected when the stored version for the subject is 2
 *      (first-revoke path: KV absent → version 1, bump → 2, old tokens rejected).
 *   B. A JWT whose ver equals the stored version authenticates normally.
 *   C. A JWT with no `ver` claim (old token) is rejected after a revoke bumps
 *      the subject version above 1.
 *   D. POST /internal/oauth/revoke-subject increments the version counter.
 *   E. POST /internal/oauth/revoke-subject requires a valid bearer.
 */

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../src/index';
import { signJwt, newJti } from '../src/oauth/jwt';
import { OAUTH_JWT_TTL_SECONDS, OAUTH_KV_PREFIX } from '../src/lib/config';

const TEST_SIGNING_SECRET = 'a'.repeat(32);
const TEST_API_KEY = 'testkey';
const TEST_INTERNAL_KEY = 'internal-key-for-revoke-test';

// Issuer/audience must match what resolveTier computes: resolveIssuer(url) + '/mcp'
const ISSUER = 'https://example.com';
const AUDIENCE = `${ISSUER}/mcp`;

type TestEnv = typeof env & {
	BV_API_KEY?: string;
	OAUTH_SIGNING_SECRET?: string;
	OAUTH_ISSUER?: string;
	BV_WEB_INTERNAL_KEY?: string;
};

const baseEnv: TestEnv = {
	...env,
	BV_API_KEY: TEST_API_KEY,
	OAUTH_SIGNING_SECRET: TEST_SIGNING_SECRET,
	OAUTH_ISSUER: ISSUER,
	BV_WEB_INTERNAL_KEY: TEST_INTERNAL_KEY,
};

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

/**
 * Sign a test JWT with the given subject, version, and tier.
 * `ver` is optional — omit it to simulate a pre-FIND-13 token.
 */
async function mintJwt(opts: {
	sub?: string;
	tier?: 'owner' | 'developer' | 'enterprise';
	ver?: number;
	jti?: string;
}): Promise<string> {
	const sub = opts.sub ?? 'user_test';
	const tier = opts.tier ?? 'developer';
	const jti = opts.jti ?? newJti();
	const payload: { sub: string; jti: string; tier: string; ver?: number } = { sub, jti, tier };
	if (opts.ver !== undefined) payload.ver = opts.ver;
	return signJwt(payload, {
		secret: TEST_SIGNING_SECRET,
		ttlSeconds: OAUTH_JWT_TTL_SECONDS,
		issuer: ISSUER,
		audience: AUDIENCE,
	});
}

function mcpInitRequest(token: string): Request<unknown, IncomingRequestCfProperties> {
	// No cf-connecting-ip → satisfies the internal guard for the /mcp route
	return new Request<unknown, IncomingRequestCfProperties>('https://example.com/mcp', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			Authorization: `Bearer ${token}`,
		},
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
	});
}

async function postRevokeSubject(sub: string, authHeader?: string, extraHeaders: HeadersInit = {}): Promise<Response> {
	const headers: HeadersInit = {
		'Content-Type': 'application/json',
		Authorization: authHeader ?? `Bearer ${TEST_INTERNAL_KEY}`,
		// Deliberately no cf-connecting-ip so the internal network guard passes
		...extraHeaders,
	};
	const req = new Request<unknown, IncomingRequestCfProperties>('https://example.com/internal/oauth/revoke-subject', {
		method: 'POST',
		headers,
		body: JSON.stringify({ sub }),
	});
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, baseEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

beforeEach(async () => {
	await clearPrefix(OAUTH_KV_PREFIX);
});

afterEach(async () => {
	await clearPrefix(OAUTH_KV_PREFIX);
});

// ---------------------------------------------------------------------------
// A. Token with outdated ver is rejected
// ---------------------------------------------------------------------------
describe('FIND-13 — token version check', () => {
	it('A: JWT ver=1 rejected when stored version is 2 (post-revoke)', async () => {
		const sub = 'user_ver_test_a';

		// Simulate a prior revoke: stored version = 2
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}tokenver:${sub}`, '2', { expirationTtl: 60 });

		// Mint a JWT with ver=1 (the outdated version)
		const token = await mintJwt({ sub, tier: 'developer', ver: 1 });

		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), baseEnv, ctx);
		await waitOnExecutionContext(ctx);

		// Must be rejected — outdated version
		expect(res.status).toBe(401);
	});

	// ---------------------------------------------------------------------------
	// B. Token with current ver authenticates
	// ---------------------------------------------------------------------------
	it('B: JWT ver=2 accepted when stored version is also 2', async () => {
		const sub = 'user_ver_test_b';

		// Stored version is 2
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}tokenver:${sub}`, '2', { expirationTtl: 60 });

		// Mint a JWT with ver=2 (current)
		const token = await mintJwt({ sub, tier: 'developer', ver: 2 });

		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), baseEnv, ctx);
		await waitOnExecutionContext(ctx);

		// Must be accepted
		expect(res.status).not.toBe(401);
	});

	// ---------------------------------------------------------------------------
	// C. Token with no `ver` claim is rejected after first revoke (stored ver=2)
	// ---------------------------------------------------------------------------
	it('C: JWT with no ver claim (old token) rejected after revoke bumps version to 2', async () => {
		const sub = 'user_ver_test_c';

		// First revoke: version goes from 1 (absent) to 2
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}tokenver:${sub}`, '2', { expirationTtl: 60 });

		// Mint a JWT with NO ver claim (simulates a pre-FIND-13 token or ver=1)
		const token = await mintJwt({ sub, tier: 'developer' /* no ver */ });

		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), baseEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(401);
	});

	// ---------------------------------------------------------------------------
	// Existing tokens authenticate when no revoke has occurred (stored ver absent)
	// ---------------------------------------------------------------------------
	it('JWT with no ver claim (defaults to 1) accepted when no revoke has occurred (stored defaults to 1)', async () => {
		const sub = 'user_ver_test_norevoke';

		// No KV entry — stored defaults to 1, token defaults to 1 → equal → accepted
		const token = await mintJwt({ sub, tier: 'developer' /* no ver */ });

		const ctx = createExecutionContext();
		const res = await worker.fetch(mcpInitRequest(token), baseEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).not.toBe(401);
	});
});

// ---------------------------------------------------------------------------
// D. Revoke endpoint increments the version counter
// ---------------------------------------------------------------------------
describe('POST /internal/oauth/revoke-subject', () => {
	it('D: increments version from absent (1) to 2 on first call', async () => {
		const sub = 'user_revoke_d';
		const res = await postRevokeSubject(sub);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { ok: boolean; version: number };
		expect(body.ok).toBe(true);
		expect(body.version).toBe(2);

		// Confirm KV was written
		const stored = await env.SESSION_STORE.get(`${OAUTH_KV_PREFIX}tokenver:${sub}`);
		expect(stored).toBe('2');
	});

	it('D: increments version from 3 to 4 on subsequent call', async () => {
		const sub = 'user_revoke_d2';
		await env.SESSION_STORE.put(`${OAUTH_KV_PREFIX}tokenver:${sub}`, '3', { expirationTtl: 60 });
		const res = await postRevokeSubject(sub);
		expect(res.status).toBe(200);
		const body = (await res.json()) as { ok: boolean; version: number };
		expect(body.version).toBe(4);
	});

	// ---------------------------------------------------------------------------
	// E. Revoke endpoint enforces strict bearer gate
	// ---------------------------------------------------------------------------
	it('E: rejects missing Authorization header with 401', async () => {
		const res = await postRevokeSubject('user_revoke_e', 'Bearer wrong-key');
		expect(res.status).toBe(401);
	});

	it('E: rejects public internet requests (cf-connecting-ip present)', async () => {
		const req = new Request<unknown, IncomingRequestCfProperties>('https://example.com/internal/oauth/revoke-subject', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
				'cf-connecting-ip': '198.51.100.10',
			},
			body: JSON.stringify({ sub: 'user_revoke_e2' }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, baseEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(404);
	});

	it('E: rejects invalid body (missing sub) with 400', async () => {
		const req = new Request<unknown, IncomingRequestCfProperties>('https://example.com/internal/oauth/revoke-subject', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				Authorization: `Bearer ${TEST_INTERNAL_KEY}`,
			},
			body: JSON.stringify({ notSub: 'something' }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(req, baseEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(res.status).toBe(400);
	});

	it('E: end-to-end — revoke then verify token rejected', async () => {
		const sub = 'user_revoke_e2e';

		// Mint a token (ver will default to 1 since no stored version yet)
		const token = await mintJwt({ sub, tier: 'developer', ver: 1 });

		// Token should work before revoke
		const ctxBefore = createExecutionContext();
		const resBefore = await worker.fetch(mcpInitRequest(token), baseEnv, ctxBefore);
		await waitOnExecutionContext(ctxBefore);
		expect(resBefore.status).not.toBe(401);

		// Revoke the subject
		const revokeRes = await postRevokeSubject(sub);
		expect(revokeRes.status).toBe(200);

		// Same token should now be rejected
		const ctxAfter = createExecutionContext();
		const resAfter = await worker.fetch(mcpInitRequest(token), baseEnv, ctxAfter);
		await waitOnExecutionContext(ctxAfter);
		expect(resAfter.status).toBe(401);
	});
});
