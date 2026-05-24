// SPDX-License-Identifier: BUSL-1.1
/**
 * Per-IP rate limit on POST /oauth/register.
 *
 * Verifies that the 10/min limit fires on the 11th request from the same IP
 * and that a different IP is NOT blocked (proving per-IP isolation).
 */
import { SELF, env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const VALID_BODY = JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] });
const HEADERS = { 'Content-Type': 'application/json' };

async function clearPrefix(prefix: string) {
	const list = await env.SESSION_STORE.list({ prefix });
	await Promise.all(list.keys.map((k) => env.SESSION_STORE.delete(k.name)));
}

beforeEach(async () => {
	await clearPrefix('oauth:');
});

afterEach(async () => {
	await clearPrefix('oauth:');
});

function register(ip: string) {
	return SELF.fetch('https://example.com/oauth/register', {
		method: 'POST',
		headers: { ...HEADERS, 'cf-connecting-ip': ip },
		body: VALID_BODY,
	});
}

describe('POST /oauth/register — per-IP rate limit', () => {
	it('allows 10 registrations from the same IP then blocks the 11th with 429', async () => {
		const ip = '203.0.113.1';

		// Drive 10 successful requests.
		for (let i = 0; i < 10; i++) {
			const res = await register(ip);
			expect(res.status, `request ${i + 1} should succeed`).toBe(201);
		}

		// 11th from the same IP must be rate-limited.
		const blocked = await register(ip);
		expect(blocked.status).toBe(429);

		// retry-after header must be present and numeric.
		const retryAfter = blocked.headers.get('retry-after');
		expect(retryAfter).not.toBeNull();
		expect(Number(retryAfter)).toBeGreaterThan(0);

		// Response body must carry RFC-style error fields.
		const body = (await blocked.json()) as Record<string, unknown>;
		expect(body.error).toBe('too_many_requests');
		expect(typeof body.error_description).toBe('string');
	});

	it('allows a different IP to register after the first IP is blocked', async () => {
		const blockedIp = '203.0.113.2';
		const allowedIp = '198.51.100.9';

		// Exhaust the limit for blockedIp.
		for (let i = 0; i < 10; i++) {
			await register(blockedIp);
		}
		const blocked = await register(blockedIp);
		expect(blocked.status).toBe(429);

		// A completely different IP must still succeed.
		const res = await register(allowedIp);
		expect(res.status).toBe(201);
	});
});
