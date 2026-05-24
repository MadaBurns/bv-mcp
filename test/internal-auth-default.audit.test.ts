// FIND-12 regression: internalLenientAuthGate was opt-in (REQUIRE_INTERNAL_AUTH=true to
// activate). The fix inverts to secure-by-default: bearer is required UNLESS
// REQUIRE_INTERNAL_AUTH=false (explicit opt-out). This file codifies that contract.

import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src';

const TEST_KEY = 'find12-test-internal-key';

type TestEnv = typeof env & { BV_WEB_INTERNAL_KEY?: string; REQUIRE_INTERNAL_AUTH?: string };

async function send(req: Request, customEnv: TestEnv): Promise<Response> {
	const ctx = createExecutionContext();
	const res = await worker.fetch(req, customEnv, ctx);
	await waitOnExecutionContext(ctx);
	return res;
}

describe('internal auth strict default (FIND-12)', () => {
	it('401s /internal/tools/call without a bearer when REQUIRE_INTERNAL_AUTH is unset', async () => {
		const customEnv: TestEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_KEY, REQUIRE_INTERNAL_AUTH: undefined };
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
			method: 'POST',
			headers: { 'content-type': 'application/json' }, // no authorization header
			body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(401);
	});

	it('allows with a valid bearer when REQUIRE_INTERNAL_AUTH is unset', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const customEnv: TestEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_KEY, REQUIRE_INTERNAL_AUTH: undefined };
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
			method: 'POST',
			headers: { 'content-type': 'application/json', authorization: `Bearer ${TEST_KEY}` },
			body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
		});
		const res = await send(req, customEnv);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(503);
	});

	it('opt-out: REQUIRE_INTERNAL_AUTH=false skips the bearer requirement', async () => {
		const { mockTxtRecords } = await import('./helpers/dns-mock');
		mockTxtRecords(['v=spf1 -all']);
		const customEnv: TestEnv = { ...env, BV_WEB_INTERNAL_KEY: TEST_KEY, REQUIRE_INTERNAL_AUTH: 'false' };
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
			method: 'POST',
			headers: { 'content-type': 'application/json' }, // no authorization header
			body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
		});
		const res = await send(req, customEnv);
		expect(res.status).not.toBe(401);
		expect(res.status).not.toBe(503);
	});

	it('503 when key is unset and REQUIRE_INTERNAL_AUTH is unset (fail-closed misconfig)', async () => {
		const customEnv: TestEnv = { ...env, BV_WEB_INTERNAL_KEY: undefined, REQUIRE_INTERNAL_AUTH: undefined };
		const req = new Request<unknown, IncomingRequestCfProperties>('http://example.com/internal/tools/call', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ name: 'check_spf', arguments: { domain: 'example.com' } }),
		});
		const res = await send(req, customEnv);
		expect(res.status).toBe(503);
	});
});
