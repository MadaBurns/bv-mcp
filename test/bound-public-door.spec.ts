// SPDX-License-Identifier: BUSL-1.1

/**
 * The bound public door: a named entry point that only another Worker can reach,
 * through a service binding that names it. It serves `/mcp` and nothing else,
 * refuses a caller with no valid key, and labels its access-log rows
 * `source: 'binding'` so they stay out of the public-door client-IP audit.
 */

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker, { BoundPublicDoor, handleBoundPublicDoorRequest } from '../src';
import { resetQuotaCoordinatorState } from '../src/lib/quota-coordinator';
import { resetAllRateLimits, resetAllRateLimitsKv } from '../src/lib/rate-limiter';
import { resetLegacySseState } from '../src/lib/legacy-sse';
import { resetSessions } from '../src/lib/session';
import { AUTH_RESOLUTION_MINUTE_LIMIT } from '../src/lib/tier-auth';

const TEST_API_KEY = 'test-api-key';

type Door = (request: Request, doorEnv: Env, ctx: ExecutionContext) => Response | Promise<Response>;

const defaultDoor: Door = (request, doorEnv, ctx) => worker.fetch(request as Request<unknown, IncomingRequestCfProperties>, doorEnv, ctx);
const boundDoor: Door = (request, doorEnv, ctx) => handleBoundPublicDoorRequest(request, doorEnv, ctx);

function mcpRequest(body: unknown, headers: Record<string, string> = {}, path = '/mcp'): Request {
	return new Request(`http://example.com${path}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', ...headers },
		body: JSON.stringify(body),
	});
}

async function send(door: Door, doorEnv: Env, request: Request): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await door(request, doorEnv, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

/** Env with a key configured and a queue that captures every access-log event. */
function keyedEnv(events: unknown[]): Env {
	return {
		...env,
		BV_API_KEY: TEST_API_KEY,
		MCP_ANALYTICS_QUEUE: {
			send: async (message: unknown) => {
				events.push(message);
			},
		},
	} as Env;
}

/** Initialize a session, then run one domain-bearing tool call; returns the tool call's response. */
async function callToolThrough(door: Door, doorEnv: Env, extraHeaders: Record<string, string> = {}): Promise<Response> {
	const auth = { Authorization: `Bearer ${TEST_API_KEY}`, ...extraHeaders };
	const init = await send(door, doorEnv, mcpRequest({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }, auth));
	expect(init.status).toBe(200);
	const sessionId = init.headers.get('mcp-session-id');
	expect(sessionId).toBeTruthy();
	return send(
		door,
		doorEnv,
		mcpRequest(
			{ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'check_spf', arguments: { domain: 'example.com' } } },
			{ ...auth, 'Mcp-Session-Id': sessionId! },
		),
	);
}

describe('bound public door', () => {
	beforeEach(async () => {
		resetAllRateLimits();
		resetSessions();
		resetLegacySseState();
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
		await resetAllRateLimitsKv(env.RATE_LIMIT);
		// No tool in these tests may reach the network: every lookup gets an empty answer.
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => Response.json({ Status: 0, Answer: [] }, { headers: { 'Content-Type': 'application/dns-json' } })),
		);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('labels a tool call through the bound door as source "binding"', async () => {
		const events: Array<{ source?: string; toolName?: string }> = [];
		const response = await callToolThrough(boundDoor, keyedEnv(events));
		expect(response.status).toBe(200);
		expect(events.length).toBeGreaterThan(0);
		expect(events.map((event) => event.source)).toEqual(events.map(() => 'binding'));
		expect(events[0].toolName).toBe('check_spf');
	});

	it('control: the same call through the default door stays "public", whatever headers it carries', async () => {
		const events: Array<{ source?: string }> = [];
		const response = await callToolThrough(defaultDoor, keyedEnv(events), {
			'x-bv-source': 'binding',
			'x-bv-door': 'binding',
			'x-bv-caller': 'binding',
		});
		expect(response.status).toBe(200);
		expect(events.length).toBeGreaterThan(0);
		expect(events.map((event) => event.source)).toEqual(events.map(() => 'public'));
	});

	it('refuses a bound caller that presents no key', async () => {
		const response = await send(boundDoor, keyedEnv([]), mcpRequest({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }));
		expect(response.status).toBe(401);
	});

	it('control: the default door still serves a caller with no key', async () => {
		const response = await send(defaultDoor, keyedEnv([]), mcpRequest({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }));
		expect(response.status).toBe(200);
	});

	it('refuses a bound caller that presents a wrong key', async () => {
		const response = await send(
			boundDoor,
			keyedEnv([]),
			mcpRequest({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }, { Authorization: 'Bearer wrong-key' }),
		);
		expect(response.status).toBe(401);
	});

	it('refuses a keyless bound caller the access-context diagnostic too', async () => {
		const response = await send(
			boundDoor,
			keyedEnv([]),
			mcpRequest({ jsonrpc: '2.0', id: 0, method: 'tools/call', params: { name: 'get_access_context', arguments: {} } }),
		);
		expect(response.status).toBe(401);
	});

	it('ignores a client-IP header the bound caller sets itself', async () => {
		const events: Array<{ ipMasked?: string; source?: string }> = [];
		const response = await callToolThrough(boundDoor, keyedEnv(events), { 'cf-connecting-ip': '203.0.113.7' });
		expect(response.status).toBe(200);
		expect(events.length).toBeGreaterThan(0);
		expect(events.map((event) => event.source)).toEqual(events.map(() => 'binding'));
		expect(events.filter((event) => event.ipMasked === '203.0.113.xxx')).toEqual([]);
	});

	it('control: the default door does record that client-IP header', async () => {
		const events: Array<{ ipMasked?: string }> = [];
		const response = await callToolThrough(defaultDoor, keyedEnv(events), { 'cf-connecting-ip': '203.0.113.7' });
		expect(response.status).toBe(200);
		expect(events.length).toBeGreaterThan(0);
		expect(events.map((event) => event.ipMasked)).toEqual(events.map(() => '203.0.113.xxx'));
	});

	it('refuses an unrecognised key on the access-context diagnostic with 401, where the default door answers "unavailable"', async () => {
		const diagnostic = () =>
			mcpRequest(
				{ jsonrpc: '2.0', id: 0, method: 'tools/call', params: { name: 'get_access_context', arguments: {} } },
				{ Authorization: 'Bearer wrong-key' },
			);
		const viaBound = await send(boundDoor, keyedEnv([]), diagnostic());
		expect(viaBound.status).toBe(401);
		// Control: the default door serves its read-only "unavailable" receipt for the same request.
		const viaDefault = await send(defaultDoor, keyedEnv([]), diagnostic());
		expect(viaDefault.status).toBe(503);
	});

	it('refuses methods the bound door has no use for, before the app answers a preflight', async () => {
		const preflight = () =>
			new Request('http://example.com/mcp', {
				method: 'OPTIONS',
				headers: { Origin: 'http://example.com', 'Access-Control-Request-Method': 'POST' },
			});
		const viaBound = await send(boundDoor, keyedEnv([]), preflight());
		expect(viaBound.status).toBe(405);
		expect(viaBound.headers.get('Allow')).toBe('GET, POST, DELETE');
		// Control: the default door answers the same preflight itself.
		const viaDefault = await send(defaultDoor, keyedEnv([]), preflight());
		expect(viaDefault.status).not.toBe(405);
	});

	it('keeps its key-lookup rate limit apart from default-door callers that have no client IP', async () => {
		// A companion-app lookup that knows no key: every unique junk key spends one lookup unit.
		const lookupEnv = {
			...keyedEnv([]),
			BV_WEB: { fetch: async () => Response.json({ valid: false }) } as unknown as Fetcher,
			BV_WEB_INTERNAL_KEY: 'internal-key-for-the-lookup-binding-0123456789',
		} as Env;
		const junk = (door: Door, key: string) =>
			send(door, lookupEnv, mcpRequest({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }, { Authorization: `Bearer ${key}` }));

		// Baseline: what an un-throttled junk key gets (the lookup's own answer, never a 429).
		const baseline = await junk(defaultDoor, 'junk-default-baseline');
		expect(baseline.status).not.toBe(429);
		expect(baseline.status).not.toBe(200);

		// Drain the shared no-IP bucket through the default door.
		let drained: Response | undefined;
		for (let i = 0; i <= AUTH_RESOLUTION_MINUTE_LIMIT; i++) drained = await junk(defaultDoor, `junk-default-${i}`);
		expect(drained!.status).toBe(429);

		// The bound door is not throttled by that: its junk key gets the un-throttled answer.
		const viaBound = await junk(boundDoor, 'junk-bound-0');
		expect(viaBound.status).toBe(baseline.status);

		// Control: the default door's bucket is still drained, so the bound call above did not reset anything.
		const stillDrained = await junk(defaultDoor, 'junk-default-after');
		expect(stillDrained.status).toBe(429);
	});

	it.each(['/internal/tools/call', '/internal/analytics/summary', '/health', '/mcp/messages', '/oauth/token', '/mcp/', '/MCP'])(
		'answers "not found" for %s, so the bound door cannot reach any other route',
		async (path) => {
			const response = await send(
				boundDoor,
				keyedEnv([]),
				mcpRequest({ name: 'check_spf', arguments: { domain: 'example.com' } }, { Authorization: `Bearer ${TEST_API_KEY}` }, path),
			);
			expect(response.status).toBe(404);
		},
	);

	it('control: two of those paths are real routes on the default door, so the 404 is the bound door refusing them', async () => {
		const health = await send(defaultDoor, keyedEnv([]), new Request('http://example.com/health'));
		expect(health.status).toBe(200);
		const viaBound = await send(boundDoor, keyedEnv([]), new Request('http://example.com/health'));
		expect(viaBound.status).toBe(404);
		// /internal/* on the default door is guarded by its own key, not absent: anything but 404.
		const internal = await send(
			defaultDoor,
			keyedEnv([]),
			mcpRequest({ name: 'check_spf', arguments: { domain: 'example.com' } }, { Authorization: `Bearer ${TEST_API_KEY}` }, '/internal/tools/call'),
		);
		expect(internal.status).not.toBe(404);
	});

	it.each(['GET', 'DELETE'])('refuses a keyless %s /mcp through the bound door', async (method) => {
		const request = () => new Request('http://example.com/mcp', { method, headers: { Accept: 'text/event-stream' } });
		const viaBound = await send(boundDoor, keyedEnv([]), request());
		expect(viaBound.status).toBe(401);
		// Control: the default door does not answer the same keyless request with 401.
		const viaDefault = await send(defaultDoor, keyedEnv([]), request());
		expect(viaDefault.status).not.toBe(401);
	});

	it('labels every call in a JSON-RPC batch through the bound door as "binding"', async () => {
		const events: Array<{ source?: string }> = [];
		const doorEnv = keyedEnv(events);
		const auth = { Authorization: `Bearer ${TEST_API_KEY}` };
		const init = await send(boundDoor, doorEnv, mcpRequest({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }, auth));
		const sessionId = init.headers.get('mcp-session-id')!;
		const call = (id: number, domain: string) => ({
			jsonrpc: '2.0',
			id,
			method: 'tools/call',
			params: { name: 'check_spf', arguments: { domain } },
		});
		const response = await send(
			boundDoor,
			doorEnv,
			mcpRequest([call(1, 'example.com'), call(2, 'example.org')], { ...auth, 'Mcp-Session-Id': sessionId }),
		);
		expect(response.status).toBe(200);
		expect(events.length).toBe(2);
		expect(events.map((event) => event.source)).toEqual(['binding', 'binding']);
	});

	it('is exported as a named entry point class that serves the same door', async () => {
		const ctx = createExecutionContext();
		const door = new BoundPublicDoor(ctx, keyedEnv([]));
		const refused = await door.fetch(mcpRequest({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }));
		const served = await door.fetch(
			mcpRequest({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }, { Authorization: `Bearer ${TEST_API_KEY}` }),
		);
		await waitOnExecutionContext(ctx);
		expect(refused.status).toBe(401);
		expect(served.status).toBe(200);
	});
});
