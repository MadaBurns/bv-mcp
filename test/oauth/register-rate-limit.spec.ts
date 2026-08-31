// SPDX-License-Identifier: BUSL-1.1
/**
 * Per-IP rate limit on POST /oauth/register.
 *
 * Verifies that the 10/min limit fires on the 11th request from the same IP
 * and that a different IP is NOT blocked (proving per-IP isolation).
 */
import { SELF, env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resetQuotaCoordinatorState } from '../../src/lib/quota-coordinator';
import { clearKvPrefix } from '../helpers/kv';

const VALID_BODY = JSON.stringify({ redirect_uris: ['https://claude.ai/cb'] });
const HEADERS = { 'Content-Type': 'application/json' };

function uniqueRateLimitIp(): string {
	const words = new Uint16Array(4);
	crypto.getRandomValues(words);
	return `2001:db8:0:0:${Array.from(words, (word) => word.toString(16)).join(':')}`;
}

beforeEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

afterEach(async () => {
	await clearKvPrefix(env.SESSION_STORE, 'oauth:');
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

function register(ip: string): Promise<Response> {
	return SELF.fetch('https://example.com/oauth/register', {
		method: 'POST',
		headers: { ...HEADERS, 'cf-connecting-ip': ip },
		body: VALID_BODY,
	});
}

describe('POST /oauth/register — per-IP rate limit', () => {
	it('allows 10 registrations from the same IP then blocks the 11th with 429', async () => {
		const ip = uniqueRateLimitIp();

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
		const blockedIp = uniqueRateLimitIp();
		const allowedIp = uniqueRateLimitIp();

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

	it('admits exactly 10 registrations from a concurrent same-IP burst', async () => {
		const ip = uniqueRateLimitIp();
		const responses = await Promise.all(Array.from({ length: 25 }, () => register(ip)));
		const statuses = responses.map((response) => response.status);
		expect(statuses.filter((status) => status === 201)).toHaveLength(10);
		expect(statuses.filter((status) => status === 429)).toHaveLength(15);
	});
});
