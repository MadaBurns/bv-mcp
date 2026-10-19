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

/**
 * Decision table for `checkOrigin` (src/index.ts), which backs both the CORS echo and the 403 gate.
 * The verdict is 'allowed' | 'denied' | 'invalid'; only 'allowed' echoes the Origin back in
 * `access-control-allow-origin`, 'denied' and 'invalid' answer 403 with distinct bodies.
 *
 *  Origin header                   ALLOWED_ORIGINS               -> verdict
 *  http://example.com              -                             -> allowed (same origin)
 *  vscode-webview://x              -                             -> allowed (desktop IDE scheme)
 *  vscode-file://vscode-app        -                             -> allowed (desktop IDE scheme)
 *  http://example.com:8080         -                             -> denied  (port differs)
 *  https://example.com             -                             -> denied  (scheme differs)
 *  https://evil.example            ''/'  '/',,'                  -> denied  (no usable allowlist entry)
 *  chrome-extension://abc          -                             -> denied
 *  file:///etc/passwd              -                             -> denied
 *  null / '' garbage               -                             -> invalid
 *  https://app.example             'https://app.example'         -> allowed
 *  HTTPS://APP.EXAMPLE             'https://app.example'         -> allowed (case-insensitive)
 *  https://app.example.evil        'https://app.example'         -> denied  (exact match only)
 */
describe('MCP Origin gate decision table', () => {
	beforeEach(async () => {
		resetAllRateLimits();
		await resetAllRateLimitsKv(env.RATE_LIMIT);
		resetSessions();
	});

	const withAllowed = (value: string | undefined) => ({ ...env, ALLOWED_ORIGINS: value }) as Env;

	it.each([
		['vscode-file://vscode-app', 'allowed'],
		['vscode-webview://abc123', 'allowed'],
		['http://example.com', 'allowed'],
		['http://example.com:8080', 'denied'],
		['https://example.com', 'denied'],
		['chrome-extension://abcdefghijklmnop', 'denied'],
		['file:///etc/passwd', 'denied'],
		['null', 'invalid'],
		['', 'noheader'],
	])('with no allowlist, Origin %j is %s', async (origin, verdict) => {
		const response = await postInitialize(origin);
		if (verdict === 'allowed' || verdict === 'noheader') {
			expect(response.status).toBe(200);
		} else {
			expect(response.status).toBe(403);
			expect(await response.text()).toBe(verdict === 'invalid' ? 'Forbidden: invalid Origin header' : 'Forbidden: unauthorized Origin');
		}
	});

	it.each([[undefined], [''], ['   '], [',,'], [' , ,']])('allowlist %j never admits a foreign origin', async (allowed) => {
		const response = await postInitialize('https://evil.example', withAllowed(allowed));
		expect(response.status).toBe(403);
		expect(await response.text()).toBe('Forbidden: unauthorized Origin');
	});

	it.each([
		['https://app.example', 200],
		['HTTPS://APP.EXAMPLE', 200],
		['https://app.example.evil', 403],
		['https://evil.app.example', 403],
		['http://app.example', 403],
		['https://app.example:444', 403],
	])('allowlist https://app.example vs Origin %s -> %i', async (origin, status) => {
		const response = await postInitialize(origin, withAllowed('https://app.example'));
		expect(response.status).toBe(status);
	});

	it('skips empty allowlist entries but still honours the real ones', async () => {
		const response = await postInitialize('https://app.example', withAllowed(',, https://app.example ,'));
		expect(response.status).toBe(200);
	});

	it('echoes an allowed Origin in access-control-allow-origin and nothing for a refused one', async () => {
		const allowed = await postInitialize('https://app.example', withAllowed('https://app.example'));
		expect(allowed.headers.get('access-control-allow-origin')).toBe('https://app.example');
		const refused = await postInitialize('https://evil.example', withAllowed('https://app.example'));
		expect(refused.headers.get('access-control-allow-origin')).toBeNull();
	});
});
