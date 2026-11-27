// SPDX-License-Identifier: BUSL-1.1
//
// Which door may point a brand-audit watch at BlackVeil's own Brand Drift
// receiver. Delivery to that origin+path goes over the private BV_WEB binding
// with the internal webhook key, so the public /mcp door must refuse it as a
// caller webhook (whatever query string is added), while the authenticated
// internal tool door — how the first-party service registers its own watches —
// still accepts it.

import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it, vi } from 'vitest';
import worker from '../src';

const API_KEY = 'receiver-door-test-api-key';
const WEB_KEY = 'receiver-door-web-internal-key';
const RECEIVER_URL = 'https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=caller-chosen-token-value';
const EXTERNAL_URL = 'https://hooks.example.com/brand-drift?t=abc';

type DoorEnv = typeof env & {
	BV_API_KEY?: string;
	BV_WEB_INTERNAL_KEY?: string;
	BRAND_AUDIT_DB?: D1Database;
	RATE_LIMIT?: KVNamespace;
	QUOTA_COORDINATOR?: unknown;
};

/** Stub D1 that records every INSERT bind list and admits it (changes=1). */
function recordingDb() {
	const inserts: unknown[][] = [];
	const db = {
		prepare: vi.fn((sql: string) => ({
			bind: (...args: unknown[]) => {
				if (sql.includes('INSERT INTO brand_audit_watches')) inserts.push(args);
				return {
					first: async () => null,
					all: async () => ({ results: [] }),
					run: async () => ({ success: true, meta: { changes: 1 } }),
				};
			},
		})),
		// Owner reconciliation on the public door: nothing to migrate.
		batch: vi.fn(async () => [
			{ success: true, results: [], meta: { changes: 0 } },
			{ success: true, results: [], meta: { changes: 0 } },
		]),
	} as unknown as D1Database;
	return { db, inserts };
}

async function fetchWorker(request: Request, doorEnv: DoorEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await worker.fetch(request, doorEnv as Env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

function toolText(payload: unknown): string {
	const content = (payload as { content?: Array<{ text?: string }> }).content ?? [];
	return content.map((item) => item.text ?? '').join('\n');
}

async function registerViaPublicMcp(webhookUrl: string, doorEnv: DoorEnv): Promise<{ isError: boolean; text: string }> {
	const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', Authorization: `Bearer ${API_KEY}` };
	const init = await fetchWorker(
		new Request('http://example.com/mcp', {
			method: 'POST',
			headers,
			body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'initialize', params: {} }),
		}),
		doorEnv,
	);
	const sessionId = init.headers.get('mcp-session-id');
	if (!sessionId) throw new Error(`initialize returned no session (status ${init.status})`);

	const response = await fetchWorker(
		new Request('http://example.com/mcp', {
			method: 'POST',
			headers: { ...headers, 'Mcp-Session-Id': sessionId },
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'tools/call',
				params: { name: 'register_brand_audit_watch', arguments: { domain: 'example.com', interval: 'weekly', webhook_url: webhookUrl } },
			}),
		}),
		doorEnv,
	);
	const raw = await response.text();
	const dataLine = raw.split('\n').find((line) => line.startsWith('data: '));
	const body = JSON.parse(dataLine ? dataLine.slice('data: '.length) : raw) as { result?: { isError?: boolean }; error?: unknown };
	if (!body.result) throw new Error(`tools/call returned no result: ${raw}`);
	return { isError: body.result.isError === true, text: toolText(body.result) };
}

async function registerViaInternalDoor(webhookUrl: string, doorEnv: DoorEnv): Promise<Response> {
	return fetchWorker(
		new Request('https://example.com/internal/tools/call', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${WEB_KEY}` },
			body: JSON.stringify({
				name: 'register_brand_audit_watch',
				arguments: { domain: 'example.com', interval: 'weekly', webhook_url: webhookUrl },
			}),
		}),
		doorEnv,
	);
}

function doorEnv(db: D1Database): DoorEnv {
	return {
		...env,
		BV_API_KEY: API_KEY,
		BV_WEB_INTERNAL_KEY: WEB_KEY,
		BRAND_AUDIT_DB: db,
	} as DoorEnv;
}

describe('Brand Drift receiver as a watch webhook — per door', () => {
	it('public /mcp: refuses the first-party receiver with a caller-chosen token, and stores nothing', async () => {
		const { db, inserts } = recordingDb();
		const result = await registerViaPublicMcp(RECEIVER_URL, doorEnv(db));
		expect(result.isError).toBe(true);
		expect(result.text).toContain('Invalid webhook_url: this BlackVeil endpoint is reserved');
		expect(inserts).toHaveLength(0);
	});

	it('public /mcp: an ordinary external https webhook still registers', async () => {
		const { db, inserts } = recordingDb();
		const result = await registerViaPublicMcp(EXTERNAL_URL, doorEnv(db));
		expect(result.isError).toBe(false);
		expect(result.text).toContain('Brand audit watch registered');
		expect(inserts).toHaveLength(1);
		expect(inserts[0]).toContain(EXTERNAL_URL);
	});

	it('internal tool door: the first-party service can still register a watch on its own receiver', async () => {
		const { db, inserts } = recordingDb();
		const response = await registerViaInternalDoor(RECEIVER_URL, doorEnv(db));
		expect(response.status).toBe(200);
		const body = await response.json();
		expect(toolText(body)).toContain('Brand audit watch registered');
		expect(inserts).toHaveLength(1);
		expect(inserts[0]).toContain(RECEIVER_URL);
	});
});
