// SPDX-License-Identifier: BUSL-1.1

// @ts-expect-error cloudflare:test exports are injected by the Workers Vitest pool at runtime.
import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import worker from '../src';

/**
 * SQ-67 — `/internal/tools/{call,batch}` now runs the SAME per-tool policy
 * chokepoint the public `/mcp` path does (`evaluateToolPolicy`), instead of
 * reaching `handleToolsCall` with none of the four gates applied.
 *
 * Both directions matter here. The door must deny what policy denies, AND the
 * legitimate internal callers — bv-web's fleet credential, the ops/load-test
 * network-guard-only mode, the batch path — must keep working, because a
 * tightening that breaks the seam is worse than the unenforced invariant it
 * replaces.
 */

type TestEnv = typeof env & {
	BV_WEB_INTERNAL_KEY?: string;
	REQUIRE_INTERNAL_AUTH?: string;
};

const WEB_KEY = 'sq67-web-internal-capability-key-32-bytes';

/** Operator opt-out: no capability key presented, cf-connecting-ip guard only. */
const networkEnv = { ...env, REQUIRE_INTERNAL_AUTH: 'false' } as TestEnv;

/** bv-web's fleet capability: the bearer gate is ACTIVE and the key matches. */
const webEnv = { ...env, REQUIRE_INTERNAL_AUTH: undefined, BV_WEB_INTERNAL_KEY: WEB_KEY } as TestEnv;

async function call(
	body: { name: string; arguments?: Record<string, unknown> },
	customEnv: TestEnv,
	headers: HeadersInit = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
	const request = new Request('https://example.com/internal/tools/call', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body: JSON.stringify(body),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

async function batch(
	body: { tool: string; domains: string[] },
	customEnv: TestEnv,
	headers: HeadersInit = {},
): Promise<{ status: number; body: Record<string, unknown> }> {
	const request = new Request('https://example.com/internal/tools/batch', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body: JSON.stringify(body),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return { status: response.status, body: (await response.json()) as Record<string, unknown> };
}

const webAuth = { Authorization: `Bearer ${WEB_KEY}` };

describe('/internal/tools/* per-tool policy (SQ-67)', () => {
	describe('auth-required (identity_secops M365 reads)', () => {
		it('denies query_signins when no capability key was presented (network-guard-only mode)', async () => {
			// Before SQ-67 this reached handleToolsCall and relied entirely on the
			// Layer-2 no-principal reject one level down. These four tools forward the
			// trusted internal bearer to bv-web's M365 proxy, so the door now requires
			// an actual capability key, not just the network guard.
			const { status, body } = await call({ name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } }, networkEnv);
			expect(status).toBe(403);
			expect(body).toEqual({ error: 'tool_policy_denied', policy: 'auth_required' });
		});

		it('lets bv-web through to the M365 layer with its capability key', async () => {
			// The only legitimate caller of these tools. Policy must not be what stops
			// it — the no-principal hard reject in handlers/tools.ts still applies.
			const { body } = await call({ name: 'query_signins', arguments: { ms_tenant_id: 'tenant-abc' } }, webEnv, webAuth);
			expect(body.error).not.toBe('tool_policy_denied');
		});
	});

	describe('internal-only tools stay callable on the internal path', () => {
		it('does not policy-deny map_registrar_products', async () => {
			// "Withdrawn from /mcp, still callable internally" is the definition of
			// INTERNAL_ONLY_TOOLS. Enforcing the public unknown-tool answer here would
			// delete the reason those entries exist.
			const { status, body } = await call({ name: 'map_registrar_products', arguments: { domain: 'example.com' } }, webEnv, webAuth);
			expect(status).not.toBe(403);
			expect(body.error).not.toBe('tool_policy_denied');
		});
	});

	describe('paid-only tools: first-party callers keep their reach', () => {
		it('allows a paid-only job creator for the full-authority internal principal', async () => {
			// The ops recon sweep and the load tests run here. A commercial upgrade gate
			// on the internal door would break them for no security gain.
			const { status, body } = await call({ name: 'scan_buckets_start', arguments: { target: 'example.com' } }, networkEnv);
			expect(status).not.toBe(403);
			expect(body.error).not.toBe('tool_policy_denied');
		});

		it('allows a paid-only brand tool for bv-web', async () => {
			const { status, body } = await call({ name: 'discover_brand_domains_start', arguments: { domain: 'example.com' } }, webEnv, webAuth);
			expect(status).not.toBe(403);
			expect(body.error).not.toBe('tool_policy_denied');
		});
	});

	describe('legitimate internal callers still succeed', () => {
		it('serves a hygiene tool over /tools/call with the web capability', async () => {
			const { status, body } = await call({ name: 'explain_finding', arguments: { finding: 'spf_missing' } }, webEnv, webAuth);
			expect(status).toBe(200);
			expect(body.error).toBeUndefined();
		});

		it('serves the batch door in network-guard-only mode', async () => {
			const { status, body } = await batch({ tool: 'check_spf', domains: ['example.com'] }, networkEnv);
			expect(status).toBe(200);
			expect(body.error).toBeUndefined();
			expect(body.summary).toBeDefined();
		});

		it('serves the batch door with the web capability', async () => {
			const { status, body } = await batch({ tool: 'check_spf', domains: ['example.com'] }, webEnv, webAuth);
			expect(status).toBe(200);
			expect(body.error).toBeUndefined();
		});
	});
});
