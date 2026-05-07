import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker from '../../src/index';

// Chaos: the 2026-05-08 production deploy was missing OAUTH_SIGNING_SECRET while
// ENABLE_OAUTH=true was advertised in /.well-known/oauth-authorization-server.
// Discovery, register, authorize, consent ALL succeeded — the flaw didn't surface
// until Claude Desktop POSTed /oauth/token after the user consented, at which
// point claude.ai showed "Couldn't connect" with no actionable diagnostic.
//
// v2.10.9 hardening: every OAuth route is now gated by `oauthAvailability`.
// `'misconfigured'` (ENABLE_OAUTH=true but signing secret missing/short) → 503.
// `'disabled'` (ENABLE_OAUTH!=true) → 404. The two states are semantically distinct.
//
// Hypothesis under test: a misconfigured deploy MUST fail-loud at the FIRST OAuth
// route a client hits, not after the user has consented. Tokens MUST never be
// issuable when the signing secret is unsuitable, even via /oauth/token directly.

const TEST_API_KEY = 'testkey';
type TestEnv = typeof env & { BV_API_KEY?: string; OAUTH_SIGNING_SECRET?: string; ENABLE_OAUTH?: string };

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

function probes() {
	return [
		{
			name: 'discovery (auth-server metadata)',
			req: () =>
				new Request<unknown, IncomingRequestCfProperties>(
					'https://example.com/.well-known/oauth-authorization-server',
				),
		},
		{
			name: 'discovery (protected-resource metadata)',
			req: () =>
				new Request<unknown, IncomingRequestCfProperties>(
					'https://example.com/.well-known/oauth-protected-resource',
				),
		},
		{
			name: 'register',
			req: () =>
				new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/register', {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] }),
				}),
		},
		{
			name: 'authorize GET',
			req: () =>
				new Request<unknown, IncomingRequestCfProperties>(
					'https://example.com/oauth/authorize?response_type=code&client_id=x&redirect_uri=https://claude.ai/cb&state=s',
				),
		},
		{
			name: 'authorize POST',
			req: () =>
				new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/authorize', {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: 'api_key=x&_q=client_id=x&redirect_uri=https://claude.ai/cb&state=s&response_type=code',
				}),
		},
		{
			name: 'token',
			req: () =>
				new Request<unknown, IncomingRequestCfProperties>('https://example.com/oauth/token', {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: 'grant_type=authorization_code&code=x&redirect_uri=https://claude.ai/cb&client_id=x&code_verifier=' + 'a'.repeat(43),
				}),
		},
	] as const;
}

beforeEach(async () => {
	await clearPrefix('oauth:');
});
afterEach(async () => {
	await clearPrefix('oauth:');
});

describe('OAuth misconfiguration chaos (v2.10.9 hardened)', () => {
	it('GIVEN OAUTH_SIGNING_SECRET unset AND ENABLE_OAUTH=true, every OAuth route returns 503 service_unavailable — fail-fast at first RTT', async () => {
		const brokenEnv = { ...env, BV_API_KEY: TEST_API_KEY, ENABLE_OAUTH: 'true', OAUTH_SIGNING_SECRET: undefined } as TestEnv;
		for (const probe of probes()) {
			const ctx = createExecutionContext();
			const res = await worker.fetch(probe.req(), brokenEnv, ctx);
			await waitOnExecutionContext(ctx);
			expect(res.status, `${probe.name} must 503 when signing secret is missing`).toBe(503);
			const body = (await res.json()) as Record<string, unknown>;
			expect(body.error, `${probe.name} body`).toBe('service_unavailable');
			// Degradation invariant: a misconfigured route never returns a token shape.
			expect(body.access_token).toBeUndefined();
			expect(body.token_type).toBeUndefined();
		}
	});

	it('GIVEN OAUTH_SIGNING_SECRET present but under 32 bytes, identical fail-fast behavior', async () => {
		const brokenEnv = {
			...env,
			BV_API_KEY: TEST_API_KEY,
			ENABLE_OAUTH: 'true',
			OAUTH_SIGNING_SECRET: 'tooshort',
		} as TestEnv;
		for (const probe of probes()) {
			const ctx = createExecutionContext();
			const res = await worker.fetch(probe.req(), brokenEnv, ctx);
			await waitOnExecutionContext(ctx);
			expect(res.status, `${probe.name} must 503 when signing secret is < 32 bytes`).toBe(503);
		}
	});

	it('GIVEN ENABLE_OAUTH=false, routes return 404 — semantically distinct from misconfigured', async () => {
		// 404 = "feature off"; 503 = "feature on but server can't issue tokens right now".
		// OAuth clients can render different UI for the two — claude.ai shows
		// "this server doesn't support OAuth" for 404 vs "service unavailable, retry"
		// for 503. The split was added in v2.10.9 specifically to give claude.ai a
		// breadcrumb other than "Couldn't connect".
		const offEnv = { ...env, BV_API_KEY: TEST_API_KEY, ENABLE_OAUTH: 'false' } as TestEnv;
		for (const probe of probes()) {
			const ctx = createExecutionContext();
			const res = await worker.fetch(probe.req(), offEnv, ctx);
			await waitOnExecutionContext(ctx);
			expect(res.status, `${probe.name} must 404 when feature off`).toBe(404);
		}
	});
});
