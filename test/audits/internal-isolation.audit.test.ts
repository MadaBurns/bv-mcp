// SPDX-License-Identifier: BUSL-1.1
//
// Regression/characterization audit — pins EXISTING internal-route isolation controls.
// No production code changes. Tests must pass against the current codebase.
//
// Covers FIND-16: /internal/* routes must be unreachable from the public internet
// and credential-minting endpoints must fail-closed when unconfigured.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../../src';
import { isPublicInternetRequest } from '../../src/internal';

// ---------------------------------------------------------------------------
// Helper: send a request through the worker and return the response.
// ---------------------------------------------------------------------------
type TestEnv = typeof env & {
	BV_MCP_OAUTH_MINT_KEY?: string;
	BV_MCP_OAUTH_REVOKE_KEY?: string;
	BV_MCP_BRAND_WEBHOOK_KEY?: string;
	REQUIRE_INTERNAL_AUTH?: string;
};

async function send(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

// ---------------------------------------------------------------------------
// FIND-16 — network guard: /internal/* is invisible from the public internet
// ---------------------------------------------------------------------------
describe('FIND-16: /internal/* network guard — public internet requests return 404', () => {
	it('returns 404 for POST /internal/tools/call when cf-connecting-ip is present', async () => {
		// cf-connecting-ip is set by Cloudflare on every public-internet request.
		// Its presence triggers the network guard in internalRoutes middleware,
		// returning 404 to make the /internal/* path invisible.
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'cf-connecting-ip': '1.2.3.4',
			},
			body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
		});
		const res = await send(req, env as TestEnv);
		expect(res.status).toBe(404);
	});

	it('returns 404 for GET /internal/trial-keys when cf-connecting-ip is present', async () => {
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/trial-keys', {
			method: 'GET',
			headers: { 'cf-connecting-ip': '203.0.113.5' },
		});
		const res = await send(req, env as TestEnv);
		expect(res.status).toBe(404);
	});

	it('returns 404 for POST /internal/oauth/grants when cf-connecting-ip is present', async () => {
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/grants', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'cf-connecting-ip': '198.51.100.1',
			},
			body: JSON.stringify({}),
		});
		const res = await send(req, env as TestEnv);
		expect(res.status).toBe(404);
	});
});

// ---------------------------------------------------------------------------
// FIND-16 — fail-closed gate: credential-minting endpoints return 503 when
// the route-specific mint/revoke capability is not configured.
// ---------------------------------------------------------------------------
describe('FIND-16: OAuth administration routes fail closed when their capability is unset', () => {
	it('returns 503 for POST /internal/oauth/grants with no BV_MCP_OAUTH_MINT_KEY', async () => {
		// No cf-connecting-ip → clears the network guard (simulates service-binding call).
		// No grant key → the strict credential-minting gate fails closed with 503.
		const customEnv = { ...env, BV_MCP_OAUTH_MINT_KEY: undefined } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/grants', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({}),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(503);
	});

	it('a revoke-only capability cannot call the authorization-code mint route', async () => {
		const revokeKey = 'revoke-only-capability-test-key-32-bytes';
		const customEnv = {
			...env,
			BV_MCP_OAUTH_MINT_KEY: undefined,
			BV_MCP_OAUTH_REVOKE_KEY: revokeKey,
		} as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/grants', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${revokeKey}` },
			body: JSON.stringify({}),
		});
		expect((await send(req, customEnv)).status).toBe(503);
	});

	it('a mint-only capability cannot call the subject-revocation route', async () => {
		const mintKey = 'mint-only-capability-test-key-32-bytes-min';
		const customEnv = {
			...env,
			BV_MCP_OAUTH_MINT_KEY: mintKey,
			BV_MCP_OAUTH_REVOKE_KEY: undefined,
		} as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/revoke-subject', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${mintKey}` },
			body: JSON.stringify({ sub: 'victim' }),
		});
		expect((await send(req, customEnv)).status).toBe(503);
	});

	it('fails closed if mint and revoke capabilities are configured to the same value', async () => {
		const shared = 'oauth-shared-capability-test-key-32-bytes';
		const customEnv = {
			...env,
			BV_MCP_OAUTH_MINT_KEY: shared,
			BV_MCP_OAUTH_REVOKE_KEY: shared,
		} as TestEnv;
		const grant = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/grants', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${shared}` },
			body: JSON.stringify({}),
		});
		const revoke = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/revoke-subject', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${shared}` },
			body: JSON.stringify({ sub: 'victim' }),
		});
		expect((await send(grant, customEnv)).status).toBe(503);
		expect((await send(revoke, customEnv)).status).toBe(503);
	});

	it('fails closed if either OAuth capability aliases the Brand Drift sender key', async () => {
		const shared = 'brand-webhook-oauth-alias-key-32-bytes-minimum';
		const distinct = 'distinct-oauth-capability-key-32-bytes-minimum';
		const grant = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/grants', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${shared}` },
			body: JSON.stringify({}),
		});
		const revoke = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/revoke-subject', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${shared}` },
			body: JSON.stringify({ sub: 'victim' }),
		});

		expect(
			(
				await send(grant, {
					...env,
					BV_MCP_OAUTH_MINT_KEY: shared,
					BV_MCP_OAUTH_REVOKE_KEY: distinct,
					BV_MCP_BRAND_WEBHOOK_KEY: shared,
				} as TestEnv)
			).status,
		).toBe(503);
		expect(
			(
				await send(revoke, {
					...env,
					BV_MCP_OAUTH_MINT_KEY: distinct,
					BV_MCP_OAUTH_REVOKE_KEY: shared,
					BV_MCP_BRAND_WEBHOOK_KEY: shared,
				} as TestEnv)
			).status,
		).toBe(503);
	});

	it('returns 503 for POST /internal/oauth/revoke-subject with no BV_MCP_OAUTH_REVOKE_KEY', async () => {
		const customEnv = { ...env, BV_MCP_OAUTH_REVOKE_KEY: undefined } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/revoke-subject', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ sub: 'user-123' }),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(503);
	});

	it('returns 503 for POST /internal/trial-keys with no BV_MCP_OAUTH_MINT_KEY', async () => {
		// /internal/trial-keys also mints credentials — trialKeysAuthGate applies the same
		// fail-closed pattern as /oauth/grants.
		const customEnv = { ...env, BV_MCP_OAUTH_MINT_KEY: undefined } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/trial-keys', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ label: 'test-key' }),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(503);
	});
});

// ---------------------------------------------------------------------------
// FIND-16 — isPublicInternetRequest pure-function contract
// ---------------------------------------------------------------------------
describe('FIND-16: isPublicInternetRequest trusts only cf-connecting-ip', () => {
	it('returns false when cfConnectingIp is null (service-binding call)', () => {
		expect(isPublicInternetRequest({ cfConnectingIp: null, host: 'x' })).toBe(false);
	});

	it('returns true when cfConnectingIp is a real IP (public internet call)', () => {
		expect(isPublicInternetRequest({ cfConnectingIp: '1.2.3.4', host: 'x' })).toBe(true);
	});

	it('returns false when cfConnectingIp is null regardless of host header', () => {
		// host header is attacker-influenced and must not affect the decision.
		expect(isPublicInternetRequest({ cfConnectingIp: null, host: 'internal.dns-mcp.blackveilsecurity.com' })).toBe(false);
	});

	it('returns true when cfConnectingIp is present regardless of host header', () => {
		expect(isPublicInternetRequest({ cfConnectingIp: '10.0.0.1', host: 'localhost' })).toBe(true);
	});

	it('returns false when cfConnectingIp is an empty string (falsy — treated as absent)', () => {
		// Boolean('') is false, so an empty string is treated as absent.
		expect(isPublicInternetRequest({ cfConnectingIp: '', host: 'x' })).toBe(false);
	});
});
