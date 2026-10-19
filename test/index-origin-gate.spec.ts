// SPDX-License-Identifier: BUSL-1.1

/**
 * Origin gate on the authenticated MCP paths (`app.use(path, ...)` in src/index.ts).
 * Requests without an Origin header pass; a present Origin must be same-origin, a desktop IDE
 * scheme or listed in ALLOWED_ORIGINS, otherwise it is refused with 403 before auth runs.
 */
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import worker from '../src';
import { resetAllRateLimits, resetAllRateLimitsKv } from '../src/lib/rate-limiter';
import { resetSessions } from '../src/lib/session';

async function postInitialize(origin: string | undefined, targetEnv: Env = env): Promise<Response> {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	if (origin !== undefined) headers.Origin = origin;
	const request = new Request('http://example.com/mcp', {
		method: 'POST',
		headers,
		body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
	});
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, targetEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

describe('MCP Origin gate', () => {
	beforeEach(async () => {
		resetAllRateLimits();
		await resetAllRateLimitsKv(env.RATE_LIMIT);
		resetSessions();
	});

	it('passes a request with no Origin header through to the handler', async () => {
		const response = await postInitialize(undefined);
		expect(response.status).toBe(200);
		expect(response.headers.get('mcp-session-id')).toBeTruthy();
	});

	it('allows a same-origin request', async () => {
		const response = await postInitialize('http://example.com');
		expect(response.status).toBe(200);
	});

	it('allows a desktop IDE scheme origin without an allowlist entry', async () => {
		const response = await postInitialize('vscode-webview://abc123');
		expect(response.status).toBe(200);
	});

	it('refuses a cross-origin request that is not allowlisted', async () => {
		const response = await postInitialize('https://evil.example');
		expect(response.status).toBe(403);
		expect(await response.text()).toBe('Forbidden: unauthorized Origin');
	});

	it('allows a cross-origin request listed in ALLOWED_ORIGINS (trimmed, case-insensitive)', async () => {
		const allowedEnv = { ...env, ALLOWED_ORIGINS: ' https://other.example , HTTPS://APP.EXAMPLE ' } as Env;
		const response = await postInitialize('https://app.example', allowedEnv);
		expect(response.status).toBe(200);
	});

	it('still refuses an origin that is absent from a non-empty ALLOWED_ORIGINS list', async () => {
		const allowedEnv = { ...env, ALLOWED_ORIGINS: 'https://app.example' } as Env;
		const response = await postInitialize('https://evil.example', allowedEnv);
		expect(response.status).toBe(403);
		expect(await response.text()).toBe('Forbidden: unauthorized Origin');
	});

	it('refuses an unparseable Origin header as invalid', async () => {
		const response = await postInitialize('not a url');
		expect(response.status).toBe(403);
		expect(await response.text()).toBe('Forbidden: invalid Origin header');
	});
});
