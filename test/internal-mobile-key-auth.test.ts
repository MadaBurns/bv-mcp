// Per-consumer credentials on the internal bearer gate.
//
// `BV_WEB_INTERNAL_KEY` is a BIDIRECTIONAL shared bearer between bv-mcp and bv-web-prod
// (bv-web-prod → /internal/tools/*, and bv-mcp → bv-web-prod's validate-key / get_domain_rank
// benchmark / M365 proxy). Handing that same value to a third consumer — the BizFit mobile
// Worker (`claude-proxy`), a lower-trust surface — would mean a leak there exposes
// bv-web-prod's credential in both directions, and that rotating for one consumer breaks the
// others.
//
// `BV_MOBILE_INTERNAL_KEY` is an INDEPENDENT slot accepted by the same gate, so the mobile
// Worker can be rotated or revoked on its own. This mirrors the established
// BV_INTERNAL_DEV_KEY / BV_INTERNAL_DEV_KEY_2 pattern in src/lib/tier-auth.ts, whose comment
// states the same rationale: "Lets a per-machine key be added without rotating
// BV_INTERNAL_DEV_KEY."
//
// The load-bearing invariants below: an absent BV_MOBILE_INTERNAL_KEY must change NOTHING for
// existing deployments (every current deploy has only BV_WEB_INTERNAL_KEY set), and the
// fail-closed 503 must still fire when NEITHER key is configured — not merely when the web key
// alone is missing.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import worker from '../src';

const WEB_KEY = 'web-internal-key-fixture';
const MOBILE_KEY = 'mobile-internal-key-fixture';

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	BV_MOBILE_INTERNAL_KEY?: string;
	REQUIRE_INTERNAL_AUTH?: string;
};

async function send(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

/** POST /internal/tools/call — the exact route the BizFit mobile Worker calls. */
function callRequest(bearer?: string): Request {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	if (bearer !== undefined) headers.Authorization = `Bearer ${bearer}`;
	return new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
		method: 'POST',
		headers,
		body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
	});
}

async function expectPassesGate(customEnv: TestEnv, bearer: string): Promise<void> {
	const { mockTxtRecords } = await import('./helpers/dns-mock');
	mockTxtRecords(['v=spf1 -all']);
	const res = await send(callRequest(bearer), customEnv);
	// Anything other than the gate's own two rejections means the gate let it through.
	expect(res.status).not.toBe(401);
	expect(res.status).not.toBe(503);
}

describe('internal auth gate: per-consumer BV_MOBILE_INTERNAL_KEY', () => {
	it('accepts a valid BV_MOBILE_INTERNAL_KEY bearer', async () => {
		await expectPassesGate({ ...env, BV_WEB_INTERNAL_KEY: WEB_KEY, BV_MOBILE_INTERNAL_KEY: MOBILE_KEY } as TestEnv, MOBILE_KEY);
	});

	it('still accepts a valid BV_WEB_INTERNAL_KEY bearer when both slots are configured', async () => {
		// Regression guard: adding the mobile slot must not displace the web key.
		await expectPassesGate({ ...env, BV_WEB_INTERNAL_KEY: WEB_KEY, BV_MOBILE_INTERNAL_KEY: MOBILE_KEY } as TestEnv, WEB_KEY);
	});

	it('rejects a bearer matching neither slot → 401', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: WEB_KEY, BV_MOBILE_INTERNAL_KEY: MOBILE_KEY } as TestEnv;
		const res = await send(callRequest('neither-of-them'), customEnv);
		expect(res.status).toBe(401);
	});

	it('accepts the mobile key when it is the ONLY key configured (no 503)', async () => {
		// The fail-closed 503 must key off "no credential configured at all", not off
		// BV_WEB_INTERNAL_KEY specifically — otherwise a mobile-only deployment is bricked.
		await expectPassesGate({ ...env, BV_WEB_INTERNAL_KEY: undefined, BV_MOBILE_INTERNAL_KEY: MOBILE_KEY } as TestEnv, MOBILE_KEY);
	});

	it('fails closed with 503 when NEITHER key is configured', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined, BV_MOBILE_INTERNAL_KEY: undefined } as TestEnv;
		const res = await send(callRequest(WEB_KEY), customEnv);
		expect(res.status).toBe(503);
	});

	it('does not widen access when BV_MOBILE_INTERNAL_KEY is unset (existing deployments unchanged)', async () => {
		// Every deployment today sets only BV_WEB_INTERNAL_KEY. A bearer that would be valid
		// as a mobile key must still be rejected while that slot is empty.
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: WEB_KEY, BV_MOBILE_INTERNAL_KEY: undefined } as TestEnv;
		const res = await send(callRequest(MOBILE_KEY), customEnv);
		expect(res.status).toBe(401);
	});

	it('an empty-string BV_MOBILE_INTERNAL_KEY is treated as unconfigured, not as a valid empty bearer', async () => {
		// `wrangler secret put` will happily store an empty value, and an empty expected token
		// must never authorize anything.
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: WEB_KEY, BV_MOBILE_INTERNAL_KEY: '' } as TestEnv;
		const res = await send(callRequest(''), customEnv);
		expect(res.status).toBe(401);
	});

	it('scopes the mobile key to /internal/tools/* — it must NOT unlock /internal/analytics/*', async () => {
		// Least privilege: the BizFit mobile Worker only ever calls /internal/tools/call. The
		// shared gate also fronts /analytics/* and /tenants/*, so the mobile slot is wired into
		// the tools gate ONLY. This is a standing guard against a future refactor collapsing the
		// three registrations back into one key list and silently granting the mobile Worker
		// tenant and analytics access.
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: WEB_KEY, BV_MOBILE_INTERNAL_KEY: MOBILE_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/analytics/tier-summary', {
			method: 'GET',
			headers: { Authorization: `Bearer ${MOBILE_KEY}` },
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('scopes the mobile key to /internal/tools/* — it must NOT unlock /internal/tenants/*', async () => {
		const customEnv = { ...env, BV_WEB_INTERNAL_KEY: WEB_KEY, BV_MOBILE_INTERNAL_KEY: MOBILE_KEY } as TestEnv;
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tenants', {
			method: 'GET',
			headers: { Authorization: `Bearer ${MOBILE_KEY}` },
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('honours the REQUIRE_INTERNAL_AUTH=false opt-out unchanged', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const customEnv = {
			...env,
			BV_WEB_INTERNAL_KEY: undefined,
			BV_MOBILE_INTERNAL_KEY: undefined,
			REQUIRE_INTERNAL_AUTH: 'false',
		} as TestEnv;
		const res = await send(callRequest(), customEnv);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(503);
	});
});
