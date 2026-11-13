// SPDX-License-Identifier: BUSL-1.1
//
// Brand-audit watch webhook signing primitives: per-watch key derivation,
// signature header format, and the optional-secret gate.

import { describe, expect, it } from 'vitest';
import {
	deriveWatchWebhookSecret,
	resolveWatchWebhookSigningSecret,
	signWatchWebhookBody,
	WATCH_WEBHOOK_KEY_LABEL,
} from '../src/lib/watch-webhook-signing';

const SERVER_SECRET = 'S'.repeat(40);

/** Independent re-implementation used as the oracle (does not call the module under test). */
async function hmacHex(key: string, message: string): Promise<string> {
	const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(message));
	return Array.from(new Uint8Array(sig), (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('deriveWatchWebhookSecret', () => {
	it('is HMAC-SHA256(server secret, label + watchId) as lowercase hex', async () => {
		expect(await deriveWatchWebhookSecret(SERVER_SECRET, 'watch-a')).toBe(
			await hmacHex(SERVER_SECRET, `${WATCH_WEBHOOK_KEY_LABEL}watch-a`),
		);
	});

	it('is stable per watch and different across watches and server secrets', async () => {
		const a1 = await deriveWatchWebhookSecret(SERVER_SECRET, 'watch-a');
		const a2 = await deriveWatchWebhookSecret(SERVER_SECRET, 'watch-a');
		const b = await deriveWatchWebhookSecret(SERVER_SECRET, 'watch-b');
		const otherServer = await deriveWatchWebhookSecret('T'.repeat(40), 'watch-a');
		expect(a1).toBe(a2);
		expect(a1).not.toBe(b);
		expect(a1).not.toBe(otherServer);
		expect(a1).toMatch(/^[0-9a-f]{64}$/);
	});
});

describe('signWatchWebhookBody', () => {
	it('returns t=<seconds>,v1=<hex> over `<t>.<body>` keyed by the per-watch secret', async () => {
		const body = '{"watchId":"watch-a","changes":{}}';
		const header = await signWatchWebhookBody(SERVER_SECRET, 'watch-a', body, 1_750_000_000);
		const watchSecret = await hmacHex(SERVER_SECRET, `${WATCH_WEBHOOK_KEY_LABEL}watch-a`);
		expect(header).toBe(`t=1750000000,v1=${await hmacHex(watchSecret, `1750000000.${body}`)}`);
	});

	it('changes when the body or the timestamp changes', async () => {
		const base = await signWatchWebhookBody(SERVER_SECRET, 'watch-a', 'x', 1);
		expect(await signWatchWebhookBody(SERVER_SECRET, 'watch-a', 'y', 1)).not.toBe(base);
		expect(await signWatchWebhookBody(SERVER_SECRET, 'watch-a', 'x', 2)).not.toBe(base);
	});
});

describe('resolveWatchWebhookSigningSecret', () => {
	it('returns a strong, distinct secret', () => {
		expect(resolveWatchWebhookSigningSecret({ WATCH_WEBHOOK_SIGNING_SECRET: SERVER_SECRET })).toBe(SERVER_SECRET);
	});

	it.each([
		['unset', {}],
		['empty', { WATCH_WEBHOOK_SIGNING_SECRET: '' }],
		['too short', { WATCH_WEBHOOK_SIGNING_SECRET: 'short' }],
		['non-string', { WATCH_WEBHOOK_SIGNING_SECRET: 12345 }],
		['aliased to another security secret', { WATCH_WEBHOOK_SIGNING_SECRET: SERVER_SECRET, BV_MCP_BRAND_WEBHOOK_KEY: SERVER_SECRET }],
	])('%s → feature off', (_label, env) => {
		expect(resolveWatchWebhookSigningSecret(env)).toBeUndefined();
	});
});
