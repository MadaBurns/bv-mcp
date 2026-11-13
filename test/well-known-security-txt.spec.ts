// SPDX-License-Identifier: BUSL-1.1

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';

const CANONICAL = 'https://www.blackveilsecurity.com/.well-known/security.txt';

async function get(path: string): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await worker.fetch(new Request(`http://example.com${path}`), env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

describe('/.well-known/security.txt', () => {
	it('redirects with 302 to the canonical security.txt', async () => {
		const response = await get('/.well-known/security.txt');
		expect(response.status).toBe(302);
		expect(response.headers.get('location')).toBe(CANONICAL);
	});

	it('leaves the OAuth well-known routes answering 200', async () => {
		expect((await get('/.well-known/oauth-protected-resource')).status).toBe(200);
		expect((await get('/.well-known/oauth-authorization-server')).status).toBe(200);
	});
});
