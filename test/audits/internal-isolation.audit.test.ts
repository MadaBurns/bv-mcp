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
type TestEnv = typeof env & { BV_WEB_INTERNAL_KEY?: string; REQUIRE_INTERNAL_AUTH?: string };

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
// BV_WEB_INTERNAL_KEY is not configured (defense against mis-deployment).
// ---------------------------------------------------------------------------
describe('FIND-16: /internal/oauth/grants fail-closed when BV_WEB_INTERNAL_KEY unset', () => {
	it('returns 503 for POST /internal/oauth/grants with no BV_WEB_INTERNAL_KEY', async () => {
		// No cf-connecting-ip → clears the network guard (simulates service-binding call).
		// No BV_WEB_INTERNAL_KEY → the strict credential-minting gate fails closed with 503.
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/grants', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({}),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(503);
	});

	it('returns 503 for POST /internal/oauth/revoke-subject with no BV_WEB_INTERNAL_KEY', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/oauth/revoke-subject', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ sub: 'user-123' }),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(503);
	});

	it('returns 503 for POST /internal/trial-keys with no BV_WEB_INTERNAL_KEY', async () => {
		// /internal/trial-keys also mints credentials — trialKeysAuthGate applies the same
		// fail-closed pattern as /oauth/grants.
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined } as TestEnv;
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
