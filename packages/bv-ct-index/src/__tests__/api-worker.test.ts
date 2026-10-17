// SPDX-License-Identifier: BUSL-1.1
/**
 * The Worker's fetch handler end to end: the real reader (createReader) over runs written by the real indexer
 * in miniflare D1/R2, behind the bearer key.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import worker from '../index';
import { T, applyCatalog, ingest, obs, sib, testEnv, withFault } from './indexer-harness';

/** Response-body shape the assertions read; fields are optional because each route returns a subset. */
interface ApiBody {
	domain?: string;
	subdomains?: string[];
	names?: string[];
	entries?: Array<Record<string, unknown>>;
	issuer?: string | null;
	error?: string;
	cursor?: string | null;
	truncated?: boolean;
	coverage: { source?: string; historyWindow?: string; truncated?: boolean; indexStartedAt?: string | null; freshThrough?: string | null };
}

beforeEach(applyCatalog);

const authed = (path: string) =>
	new Request<unknown, IncomingRequestCfProperties>(`https://bv-ct-index${path}`, { headers: { authorization: 'Bearer test-key' } });

describe('bv-ct-index query API over the real reader', () => {
	it('answers /enumerate, /sans and /cert-meta from indexed observations, govt.nz included', async () => {
		const env = testEnv();
		await ingest(
			env,
			T,
			[
				obs('dia.govt.nz', { issuer: 'R11' }),
				obs('www.dia.govt.nz', { issuer: 'R10' }),
				obs('health.govt.nz', { issuer: 'E6' }),
				obs('example.com', { issuer: 'Old CA', notAfter: Math.floor(T / 1000) + 5 * 86_400 }),
				obs('api.example.com'),
			],
			[sib('example.com', 'example.org')],
		);
		// A later observation of example.com with a larger notAfter wins the issuer.
		await ingest(env, T + 1000, [obs('example.com', { issuer: 'New CA', notAfter: Math.floor(T / 1000) + 90 * 86_400 })]);

		const suffix = await (await worker.fetch(authed('/enumerate?domain=govt.nz'), env)).json<ApiBody>();
		expect(suffix.subdomains).toEqual(['dia.govt.nz', 'www.dia.govt.nz', 'health.govt.nz']);
		expect(suffix.coverage).toMatchObject({ source: 'bv-ct-index', historyWindow: 'forward-from', truncated: false });
		expect(typeof suffix.coverage.indexStartedAt).toBe('string');
		expect(typeof suffix.coverage.freshThrough).toBe('string');

		const siblings = await (await worker.fetch(authed('/sans?domain=www.example.com'), env)).json<ApiBody>();
		expect(siblings.names).toEqual(['example.org']);

		const meta = await (await worker.fetch(authed('/cert-meta?domain=example.com'), env)).json<ApiBody>();
		expect(meta.issuer).toBe('New CA');
	});

	it('answers 503 (not an empty 200) when R2 faults while serving /enumerate', async () => {
		const seeded = testEnv();
		await ingest(seeded, T, [obs('example.com')]);
		const faulty = testEnv({
			INDEX: withFault(seeded.INDEX, 'get', () => Promise.reject(new Error('R2 unavailable'))),
		});
		const response = await worker.fetch(authed('/enumerate?domain=example.com'), faulty);
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: 'ct_index_unavailable' });
	});

	it('answers 503 index_not_ready before anything was indexed', async () => {
		const response = await worker.fetch(authed('/enumerate?domain=example.com'), testEnv());
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: 'index_not_ready' });
	});

	it('answers 401 without the key, and keeps /health open', async () => {
		const env = testEnv();
		expect((await worker.fetch(new Request('https://bv-ct-index/enumerate?domain=example.com'), env)).status).toBe(401);
		expect((await worker.fetch(new Request('https://bv-ct-index/health'), env)).status).toBe(200);
		expect((await worker.fetch(authed('/enumerate?domain=bad%20name'), env)).status).toBe(400);
	});
});
