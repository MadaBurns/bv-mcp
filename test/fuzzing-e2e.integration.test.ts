// Subcutaneous E2E for the fuzzing-detection feature.
//
// Drives the worker via SELF.fetch (no browser — per testing-methodology.md
// principle 5) and triggers the scheduled handler directly. This is the ONE
// test that proves the wire-up: error in request path → counter incremented
// in KV → scheduled scan picks it up → webhook called with a payload that
// parses against the contract schema.
//
// Anything finer-grained should live in unit/integration/contract tests.

import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { FuzzingAlertSchema } from '../src/schemas/alerting';
import worker from '../src';

const ALERT_WEBHOOK = 'https://hooks.example.test/webhook-fixture';

type TestEnv = typeof env & {
	ALERT_WEBHOOK_URL?: string;
};

async function clearFuzz() {
	const list = await env.RATE_LIMIT.list({ prefix: 'fuzz:' });
	await Promise.all(list.keys.map((k) => env.RATE_LIMIT.delete(k.name)));
}

let originalFetch: typeof globalThis.fetch;
let webhookCalls: { url: string; body: string }[] = [];

beforeEach(async () => {
	await clearFuzz();
	webhookCalls = [];
	originalFetch = globalThis.fetch;
	globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
		if (url.startsWith(ALERT_WEBHOOK)) {
			webhookCalls.push({ url, body: typeof init?.body === 'string' ? init.body : '' });
			return new Response('ok', { status: 200 });
		}
		return originalFetch(input as RequestInfo, init);
	}) as typeof fetch;
});

afterEach(() => {
	globalThis.fetch = originalFetch;
});

describe('fuzzing detection — subcutaneous E2E', () => {
	it('30 unknown-tool calls trip the threshold and the scheduled scan posts a fuzzing_suspected alert', async () => {
		const ip = '203.0.113.99'; // RFC 5737 documentation prefix — safe for tests

		// 1. Initialize a session so subsequent tools/call requests reach the dispatch path.
		const initRes = await SELF.fetch('https://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json, text/event-stream',
				'cf-connecting-ip': ip,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 0,
				method: 'initialize',
				params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'fuzz-e2e', version: '1' } },
			}),
		});
		expect(initRes.status).toBe(200);
		const sessionId = initRes.headers.get('mcp-session-id');
		expect(sessionId).toBeTruthy();

		// 2. Drive 30 unknown-tool requests through the dispatch path.
		for (let i = 0; i < 30; i++) {
			const res = await SELF.fetch('https://example.com/mcp', {
				method: 'POST',
				headers: {
					'Content-Type': 'application/json',
					'Accept': 'application/json, text/event-stream',
					'cf-connecting-ip': ip,
					'mcp-session-id': sessionId!,
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: i + 1,
					method: 'tools/call',
					params: { name: `definitely_not_a_tool_${i}`, arguments: { domain: 'example.com' } },
				}),
			});
			expect([200, 400, 401, 404]).toContain(res.status);
		}

		// 2. Run the scheduled handler. It should list the fuzz: keys, score, and post the alert.
		const customEnv = { ...env, ALERT_WEBHOOK_URL: ALERT_WEBHOOK } as TestEnv;
		const ctx = createExecutionContext();
		await worker.scheduled({ cron: '*/15 * * * *', scheduledTime: Date.now(), type: 'scheduled' } as ScheduledEvent, customEnv, ctx);
		await waitOnExecutionContext(ctx);

		// 3. Assert: at least one webhook call landed and the payload parses against the contract.
		expect(webhookCalls.length).toBeGreaterThan(0);
		const fuzzAlerts = webhookCalls
			.map((c) => {
				try {
					return JSON.parse(c.body);
				} catch {
					return null;
				}
			})
			.filter((p) => p && p.type === 'fuzzing_suspected');
		expect(fuzzAlerts.length).toBeGreaterThan(0);
		for (const payload of fuzzAlerts) {
			expect(() => FuzzingAlertSchema.parse(payload)).not.toThrow();
		}
		expect(fuzzAlerts[0].kind).toBe('unknown_tool');
	});

	it('JSON-only transport (Accept: application/json) also increments the unknown_tool fuzz counter', async () => {
		const ip = '203.0.113.77'; // RFC 5737 documentation prefix — safe for tests

		// 1. Initialize a session (JSON-only Accept routes through the non-SSE dispatch path).
		const initRes = await SELF.fetch('https://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'cf-connecting-ip': ip,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 0,
				method: 'initialize',
				params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'fuzz-e2e-json', version: '1' } },
			}),
		});
		expect(initRes.status).toBe(200);
		const sessionId = initRes.headers.get('mcp-session-id');
		expect(sessionId).toBeTruthy();

		// 2. Drive a single unknown-tool request through the JSON-only (non-SSE) path.
		const res = await SELF.fetch('https://example.com/mcp', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'cf-connecting-ip': ip,
				'mcp-session-id': sessionId!,
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'definitely_not_a_tool_json', arguments: { domain: 'example.com' } },
			}),
		});
		expect([200, 400, 401, 404]).toContain(res.status);

		// 3. Assert the fuzz counter for this principal's unknown_tool kind was incremented in KV.
		// The record is written via ctx.waitUntil; poll briefly to let it flush.
		let unknownToolKeys: { name: string }[] = [];
		for (let attempt = 0; attempt < 20; attempt++) {
			const list = await env.RATE_LIMIT.list({ prefix: 'fuzz:' });
			unknownToolKeys = list.keys.filter((k) => k.name.includes('unknown_tool'));
			if (unknownToolKeys.length > 0) break;
			await new Promise((r) => setTimeout(r, 25));
		}
		expect(unknownToolKeys.length).toBeGreaterThan(0);
	});
});
