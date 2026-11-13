// SPDX-License-Identifier: BUSL-1.1
//
// Origin signing of brand-audit watch webhook deliveries to caller-supplied URLs
// (SQ-587). The expected signature is recomputed here from the derived per-watch
// key, so the assertion fails if the delivery path stops signing the exact body.

import { afterEach, describe, expect, it, vi } from 'vitest';
import { defaultDeliverWebhook } from '../src/queue/brand-audit-consumer';
import { WATCH_WEBHOOK_KEY_LABEL } from '../src/lib/watch-webhook-signing';

const savedFetch = globalThis.fetch;
const SERVER_SECRET = 'k'.repeat(40);
const URL_ = 'https://hooks.example.com/brand-audit';

afterEach(() => {
	globalThis.fetch = savedFetch;
	vi.restoreAllMocks();
});

async function hmacHex(key: string, message: string): Promise<string> {
	const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(message));
	return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('');
}

function mockFetch() {
	const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
	globalThis.fetch = fetchMock as unknown as typeof fetch;
	return fetchMock;
}

function sentRequest(fetchMock: ReturnType<typeof mockFetch>, call = 0): { body: string; signature: string | null } {
	const init = (fetchMock.mock.calls[call] as unknown as [string, RequestInit])[1];
	return { body: String(init.body), signature: new Headers(init.headers).get('X-Blackveil-Signature') };
}

async function expectedSignature(watchId: string, t: string, body: string): Promise<string> {
	const watchSecret = await hmacHex(SERVER_SECRET, `${WATCH_WEBHOOK_KEY_LABEL}${watchId}`);
	return hmacHex(watchSecret, `${t}.${body}`);
}

function parseHeader(value: string | null): { t: string; v1: string } {
	const match = /^t=(\d+),v1=([0-9a-f]{64})$/.exec(value ?? '');
	expect(match, `signature header format: ${value}`).not.toBeNull();
	return { t: match![1], v1: match![2] };
}

describe('watch webhook signing — caller-supplied URL', () => {
	it('signs the exact request body with the derived per-watch key when enabled', async () => {
		const fetchMock = mockFetch();
		const payload = { schemaVersion: 1, watchId: 'watch-a', auditId: 'audit-1', note: 'unicode é' };

		expect(await defaultDeliverWebhook(URL_, payload, 5_000, { signingSecret: SERVER_SECRET, watchId: 'watch-a' })).toBe(true);

		const { body, signature } = sentRequest(fetchMock);
		expect(body).toBe(JSON.stringify(payload));
		const { t, v1 } = parseHeader(signature);
		expect(Math.abs(Number(t) - Date.now() / 1000)).toBeLessThan(60);
		expect(v1).toBe(await expectedSignature('watch-a', t, body));
	});

	it('sends no signature header when the server secret is unset', async () => {
		const fetchMock = mockFetch();
		await defaultDeliverWebhook(URL_, { watchId: 'watch-a' }, 5_000, { watchId: 'watch-a' });
		expect(sentRequest(fetchMock).signature).toBeNull();
		expect(new Headers((fetchMock.mock.calls[0] as unknown as [string, RequestInit])[1].headers).get('Content-Type')).toBe(
			'application/json',
		);
	});

	it('uses a different key per watch', async () => {
		const fetchMock = mockFetch();
		const payload = { same: 'body' };
		await defaultDeliverWebhook(URL_, payload, 5_000, { signingSecret: SERVER_SECRET, watchId: 'watch-a' });
		await defaultDeliverWebhook(URL_, payload, 5_000, { signingSecret: SERVER_SECRET, watchId: 'watch-b' });
		const a = parseHeader(sentRequest(fetchMock, 0).signature);
		const b = parseHeader(sentRequest(fetchMock, 1).signature);
		// Each header verifies only under its own watch's key, never the other's.
		expect(a.v1).toBe(await expectedSignature('watch-a', a.t, JSON.stringify(payload)));
		expect(b.v1).toBe(await expectedSignature('watch-b', b.t, JSON.stringify(payload)));
		expect(a.v1).not.toBe(await expectedSignature('watch-b', a.t, JSON.stringify(payload)));
	});

	it('keeps the same key for the same watch across deliveries', async () => {
		const fetchMock = mockFetch();
		await defaultDeliverWebhook(URL_, { n: 1 }, 5_000, { signingSecret: SERVER_SECRET, watchId: 'watch-a' });
		await defaultDeliverWebhook(URL_, { n: 2 }, 5_000, { signingSecret: SERVER_SECRET, watchId: 'watch-a' });
		for (const [index, payload] of [{ n: 1 }, { n: 2 }].entries()) {
			const { t, v1 } = parseHeader(sentRequest(fetchMock, index).signature);
			expect(v1).toBe(await expectedSignature('watch-a', t, JSON.stringify(payload)));
		}
	});

	it('does not sign the first-party BlackVeil receiver path (it keeps its bearer)', async () => {
		const bindingFetch = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
		await defaultDeliverWebhook('https://www.blackveilsecurity.com/api/webhooks/brand-drift?t=watch-token', { a: 1 }, 5_000, {
			blackVeilBinding: { fetch: bindingFetch as unknown as typeof fetch },
			authToken: 'w'.repeat(32),
			peerAuthTokens: [],
			signingSecret: SERVER_SECRET,
			watchId: 'watch-a',
		});
		const init = (bindingFetch.mock.calls[0] as unknown as [string, RequestInit])[1];
		expect(new Headers(init.headers).has('X-Blackveil-Signature')).toBe(false);
	});
});
