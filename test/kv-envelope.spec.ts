// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect } from 'vitest';

describe('kv envelope encryption', () => {
	it('round-trips and produces non-plaintext ciphertext', async () => {
		const { sealKv, openKv } = await import('../src/lib/kv-envelope');
		const key = crypto.getRandomValues(new Uint8Array(32));
		const sealed = await sealKv('trial-secret-123', key, 1);
		expect(sealed).not.toContain('trial-secret-123');
		expect(await openKv(sealed, key)).toBe('trial-secret-123');
	});

	it('fails to open with the wrong key', async () => {
		const { sealKv, openKv } = await import('../src/lib/kv-envelope');
		const k1 = crypto.getRandomValues(new Uint8Array(32));
		const k2 = crypto.getRandomValues(new Uint8Array(32));
		await expect(openKv(await sealKv('x', k1), k2)).rejects.toBeDefined();
	});

	it('includes a version prefix in the sealed output', async () => {
		const { sealKv } = await import('../src/lib/kv-envelope');
		const key = crypto.getRandomValues(new Uint8Array(32));
		const sealed = await sealKv('hello', key, 2);
		expect(sealed.startsWith('v2:')).toBe(true);
	});

	it('isSealed correctly identifies sealed vs legacy values', async () => {
		const { isSealed } = await import('../src/lib/kv-envelope');
		expect(isSealed('v1:abc:def')).toBe(true);
		expect(isSealed('{"tier":"developer"}')).toBe(false);
		expect(isSealed('')).toBe(false);
	});

	it('parseEnvelopeKey returns null for absent or wrong-length key', async () => {
		const { parseEnvelopeKey } = await import('../src/lib/kv-envelope');
		expect(parseEnvelopeKey(undefined)).toBeNull();
		// 16-byte key base64 — too short
		const short = btoa(String.fromCharCode(...new Uint8Array(16)));
		expect(parseEnvelopeKey(short)).toBeNull();
		// 32-byte key base64 — correct
		const ok = btoa(String.fromCharCode(...new Uint8Array(32)));
		expect(parseEnvelopeKey(ok)).not.toBeNull();
	});

	it('defaults keyVersion to 1 when not specified', async () => {
		const { sealKv } = await import('../src/lib/kv-envelope');
		const key = crypto.getRandomValues(new Uint8Array(32));
		const sealed = await sealKv('test', key);
		expect(sealed.startsWith('v1:')).toBe(true);
	});
});
