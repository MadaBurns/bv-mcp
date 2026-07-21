// SPDX-License-Identifier: BUSL-1.1
/**
 * Route-level tests for the shim Worker. Exercises the Hono app against an
 * in-memory KV and a fake whoisQuery.
 */

import { describe, it, expect, vi } from 'vitest';
import { buildApp } from '../app';

function makeKV() {
	const data = new Map<string, string>();
	return {
		get: vi.fn(async (k: string) => (data.has(k) ? data.get(k)! : null)),
		put: vi.fn(async (k: string, v: string) => { data.set(k, v); }),
	};
}

describe('POST /lookup', () => {
	it('returns 200 with registrar JSON for a valid request', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn(async () => 'Registrar: TestReg Inc.\n');
		const app = buildApp({ kv: kv as never, whoisQuery });

		const res = await app.request('/lookup', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ domain: 'example.com' }),
		});

		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ registrar: 'TestReg Inc.', registrarIanaId: null, creationDate: null, updatedDate: null, expiryDate: null, registrantOrg: null, registrantPrivacy: false, source: 'whois' });
	});

	it('returns registrar IANA ID in the JSON response when WHOIS includes it', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn(async () => 'Registrar: TestReg Inc.\nRegistrar IANA ID: 299\n');
		const app = buildApp({ kv: kv as never, whoisQuery });

		const res = await app.request('/lookup', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ domain: 'example.com' }),
		});

		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ registrar: 'TestReg Inc.', registrarIanaId: '299', creationDate: null, updatedDate: null, expiryDate: null, registrantOrg: null, registrantPrivacy: false, source: 'whois' });
	});

	it('returns 400 when domain field is missing', async () => {
		const kv = makeKV();
		const app = buildApp({ kv: kv as never, whoisQuery: vi.fn() });

		const res = await app.request('/lookup', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({}),
		});

		expect(res.status).toBe(400);
	});

	it('returns 400 when domain field is not a string', async () => {
		const kv = makeKV();
		const app = buildApp({ kv: kv as never, whoisQuery: vi.fn() });

		const res = await app.request('/lookup', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ domain: 123 }),
		});

		expect(res.status).toBe(400);
	});

	it('returns 415 when content-type is not application/json', async () => {
		const kv = makeKV();
		const app = buildApp({ kv: kv as never, whoisQuery: vi.fn() });

		const res = await app.request('/lookup', {
			method: 'POST',
			headers: { 'content-type': 'text/plain' },
			body: 'domain=example.com',
		});

		expect(res.status).toBe(415);
	});

	it('returns 405 on GET /lookup', async () => {
		const kv = makeKV();
		const app = buildApp({ kv: kv as never, whoisQuery: vi.fn() });

		const res = await app.request('/lookup', { method: 'GET' });

		expect(res.status).toBe(405);
	});

	it('returns 200 with source=redacted for DENIC-style response', async () => {
		const kv = makeKV();
		const whoisQuery = vi.fn(async (server: string) =>
			server === 'whois.denic.de'
				? `% The DENIC whois service on port 43 doesn't disclose any information concerning the domain holder.\nDomain: example.de\n`
				: '',
		);
		const app = buildApp({ kv: kv as never, whoisQuery });

		const res = await app.request('/lookup', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ domain: 'example.de' }),
		});

		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ registrar: null, registrarIanaId: null, creationDate: null, updatedDate: null, expiryDate: null, registrantOrg: null, registrantPrivacy: false, source: 'redacted' });
	});

	it('rejects body larger than 1KB', async () => {
		const kv = makeKV();
		const app = buildApp({ kv: kv as never, whoisQuery: vi.fn() });

		const oversize = JSON.stringify({ domain: 'x'.repeat(2000) + '.com' });
		const res = await app.request('/lookup', {
			method: 'POST',
			headers: { 'content-type': 'application/json', 'content-length': String(oversize.length) },
			body: oversize,
		});

		expect(res.status).toBe(413);
	});

	it('rejects oversized body even when content-length header is absent', async () => {
		const kv = makeKV();
		const app = buildApp({ kv: kv as never, whoisQuery: vi.fn() });

		const oversize = JSON.stringify({ domain: 'x'.repeat(2000) + '.com' });
		// Omit content-length to simulate chunked encoding bypass attempt.
		const res = await app.request('/lookup', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: oversize,
		});

		expect(res.status).toBe(413);
	});
});

describe('GET /health', () => {
	it('returns 200 ok', async () => {
		const kv = makeKV();
		const app = buildApp({ kv: kv as never, whoisQuery: vi.fn() });

		const res = await app.request('/health', { method: 'GET' });

		expect(res.status).toBe(200);
		expect(await res.json()).toEqual({ status: 'ok' });
	});
});
