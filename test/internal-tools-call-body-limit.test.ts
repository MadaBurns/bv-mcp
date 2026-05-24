// M3 regression: /internal/tools/call previously called c.req.json() with no
// pre-parse size guard, while /internal/tools/batch (correctly) caps at 256 KB.
// Service-binding callers can still send oversized bodies; the route should
// reject them at the boundary rather than materializing the full body in memory.
//
// Limit chosen: same MAX_REQUEST_BODY_BYTES (10 KB) used on the public /mcp path —
// a single direct tool invocation never legitimately exceeds the public limit.
//
// REQUIRE_INTERNAL_AUTH=false: these tests cover body-limit behaviour, not bearer
// auth — opt out of the auth gate so assertions stay focused on the 413 contract.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import worker from '../src';
import { MAX_REQUEST_BODY_BYTES } from '../src/lib/config';

// Opt out of bearer auth gate — body-limit tests are about size rejection, not auth.
const testEnv = { ...env, REQUIRE_INTERNAL_AUTH: 'false' } as typeof env & { REQUIRE_INTERNAL_AUTH: string };

describe('/internal/tools/call — body size limit', () => {
	it('rejects bodies larger than MAX_REQUEST_BODY_BYTES with 413', async () => {
		// Padding inside arguments to push body over the cap. Use a benign argument
		// that won't pass schema, but that's fine — body-limit rejection is checked
		// before parse, so the response should be 413, not a Zod 400.
		const big = 'x'.repeat(MAX_REQUEST_BODY_BYTES + 100);
		const body = JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com', _pad: big } });
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body,
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(413);
	});

	it('accepts a small body (regression guard for legitimate calls)', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const request = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toBe(200);
	});
});
