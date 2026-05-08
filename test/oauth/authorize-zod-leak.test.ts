// Regression for L2: pre-fix authorize.ts surfaced ZodError.message in the body of a
// 400 response, leaking schema field names and constraint descriptions to
// unauthenticated callers before redirect_uri was even trusted. Mirror token.ts /
// register.ts: the body must be a single static string with no Zod metadata.

import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('OAuth authorize — generic 400 on invalid query', () => {
	it('GET /oauth/authorize returns generic message (no Zod schema details)', async () => {
		// Missing every required field — ZodError would normally enumerate them all.
		const res = await SELF.fetch('https://example.com/oauth/authorize?garbage=1');
		expect(res.status).toBe(400);
		const body = await res.text();
		// Generic message
		expect(body).toBe('Invalid authorization request');
		// Negative assertions — none of these schema-introspection tokens should leak
		for (const leak of ['Required', 'expected', 'received', 'code_challenge', 'response_type', 'client_id', 'invalid_type']) {
			expect(body).not.toContain(leak);
		}
	});

	it('POST /oauth/authorize returns generic message on malformed _q', async () => {
		const form = new URLSearchParams();
		form.set('api_key', 'irrelevant');
		// _q has only client_id — schema needs many more required fields, will Zod-fail
		form.set('_q', 'client_id=abc');
		const res = await SELF.fetch('https://example.com/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: form.toString(),
		});
		expect(res.status).toBe(400);
		const body = await res.text();
		expect(body).toBe('Invalid authorization request');
		for (const leak of ['Required', 'code_challenge', 'response_type', 'invalid_type']) {
			expect(body).not.toContain(leak);
		}
	});
});
