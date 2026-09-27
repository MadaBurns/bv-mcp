import { SELF, env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../../src/index';
import { resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';
import { REGISTER_MAX_BODY_BYTES } from '../../src/oauth/register';
import { clearKvPrefix } from '../helpers/kv';

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

afterEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('POST /oauth/register', () => {
	it('accepts a claude.ai redirect and returns 201 + client_id', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ client_name: 'Claude', redirect_uris: ['https://claude.ai/cb'] }),
		});
		expect(res.status).toBe(201);
		const body = (await res.json()) as Record<string, unknown>;
		expect(typeof body.client_id).toBe('string');
		expect(typeof body.client_id_issued_at).toBe('number');
		expect(body.token_endpoint_auth_method).toBe('none');
	});

	it('accepts a claude.com redirect (post claude.ai → claude.com migration) and returns 201', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ client_name: 'Claude', redirect_uris: ['https://claude.com/api/mcp/auth_callback'] }),
		});
		expect(res.status).toBe(201);
		const body = (await res.json()) as Record<string, unknown>;
		expect(typeof body.client_id).toBe('string');
	});

	it('accepts a genuine Anthropic subdomain redirect parsed by hostname', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://desktop.anthropic.com/cb?platform=desktop'] }),
		});
		expect(res.status).toBe(201);
	});

	it.each([
		'https://evil.example?.anthropic.com/cb',
		'https://evil.example#.anthropic.com/cb',
		'https://desktop.anthropic.com.evil.example/cb',
		'https://user:password@desktop.anthropic.com/cb',
		'https://desktop.anthropic.com/cb#fragment',
	])('rejects parser-confusion or unsafe redirect URI %s', async (redirectUri) => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: [redirectUri] }),
		});
		expect(res.status).toBe(400);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('invalid_redirect_uri');
	});

	it('rejects claude.com lookalike hosts', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://claude.com.evil.example/cb'] }),
		});
		expect(res.status).toBe(400);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('invalid_redirect_uri');
	});

	it('rejects redirect_uri outside allowlist', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://evil.example/cb'] }),
		});
		expect(res.status).toBe(400);
		const body = (await res.json()) as Record<string, unknown>;
		expect(body.error).toBe('invalid_redirect_uri');
	});

	it('rejects body missing redirect_uris', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ client_name: 'Claude' }),
		});
		expect(res.status).toBe(400);
		expect(((await res.json()) as Record<string, unknown>).error).toBe('invalid_client_metadata');
	});

	it('rejects body larger than 4 KB', async () => {
		const huge = 'x'.repeat(5000);
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ client_name: huge, redirect_uris: ['https://claude.ai/cb'] }),
		});
		expect(res.status).toBe(413);
	});

	it('rejects and cancels a chunked body at cap plus one without Content-Length', async () => {
		const cancelled = vi.fn();
		let pull = 0;
		const request = new Request('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.91' },
			body: new ReadableStream<Uint8Array>({
				pull(controller) {
					if (pull++ === 0) controller.enqueue(new Uint8Array(REGISTER_MAX_BODY_BYTES));
					else if (pull === 2) controller.enqueue(new Uint8Array([1]));
					else if (pull === 3) controller.enqueue(new Uint8Array([2]));
					else controller.close();
				},
				cancel: cancelled,
			}),
		});
		expect(request.headers.get('content-length')).toBeNull();
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(413);
		expect(cancelled).toHaveBeenCalledOnce();
	});

	it('rejects array where any redirect_uri is outside allowlist', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb', 'https://evil.example/cb'] }),
		});
		expect(res.status).toBe(400);
		const body = await res.json() as Record<string, unknown>;
		expect(body.error).toBe('invalid_redirect_uri');
	});

	it('rejects malformed JSON body with invalid_client_metadata', async () => {
		const res = await SELF.fetch('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: '{ not valid json',
		});
		expect(res.status).toBe(400);
		const body = await res.json() as Record<string, unknown>;
		expect(body.error).toBe('invalid_client_metadata');
	});

	// SQ-199: putClient()'s kv.put() previously threw unwrapped on a KV outage,
	// so a rejecting SESSION_STORE ended in Hono's default 500 handler instead
	// of the route's OAuth temporarily_unavailable shape.
	it('returns 503 temporarily_unavailable when SESSION_STORE rejects on the write, never a 500', async () => {
		const rejectingEnv = {
			...env,
			SESSION_STORE: {
				get: async () => null,
				put: async () => {
					throw new Error('KV unavailable (SQ-199 register test — must never reach the client)');
				},
				delete: async () => undefined,
			} as unknown as typeof env.SESSION_STORE,
		} as Env;
		const request = new Request('https://example.com/oauth/register', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '198.51.100.92' },
			body: JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] }),
		});
		const ctx = createExecutionContext();
		const res = await worker.fetch(request, rejectingEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(res.status).toBe(503);
		const text = await res.text();
		expect(text).not.toContain('SQ-199 register test');
		const body = JSON.parse(text) as { error?: string };
		expect(body.error).toBe('temporarily_unavailable');
	});
});
