// SPDX-License-Identifier: BUSL-1.1
/**
 * The query API over a FAKE IndexReader: route shapes, pagination, auth, validation, and the fault rule
 * (a fault is a 503, never an empty 200).
 */

import { describe, expect, it } from 'vitest';
import { API_BUDGET_MS, PAGE_LIMIT, handleApiRequest, parseDomain } from '../api/handler';
import { isAuthorized } from '../api/auth';
import { nameKey, siblingKey } from '../codec';
import type { IndexReader, NameObservation, ScanPage, SiblingObservation } from '../types';

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

const KEY = 'test-admin-key';
const META = { indexStartedAt: '2026-10-17T00:00:00.000Z', freshThrough: '2026-10-17T05:00:00.000Z', generation: 1 };
const NOT_AFTER = 1_800_000_000; // 2027-01-15T08:00:00.000Z
const FIRST_SEEN = 1_790_000_000;

function row(name: string, overrides: Partial<NameObservation> = {}): NameObservation {
	const k = nameKey(name);
	return {
		key: k.key,
		name: k.name,
		apex: name.split('.').slice(-2).join('.'),
		firstSeen: FIRST_SEEN,
		notAfter: NOT_AFTER,
		issuer: "Let's Encrypt R11",
		wildcard: k.wildcard,
		...overrides,
	};
}

function sibling(apex: string, name: string): SiblingObservation {
	return { key: siblingKey(apex, name), apex, sibling: name, firstSeen: FIRST_SEEN, notAfter: NOT_AFTER };
}

interface FakeOptions {
	names?: NameObservation[];
	truncated?: boolean;
	cursor?: string | null;
	siblings?: SiblingObservation[];
	siblingsTruncated?: boolean;
	meta?: Awaited<ReturnType<IndexReader['meta']>>;
}

/** A reader that records its calls. */
function fakeReader(options: FakeOptions = {}) {
	const calls = {
		scan: [] as Array<{ domain: string; opts: { limit: number; cursor?: string | null } }>,
		siblings: [] as Array<{ apex: string; limit: number }>,
	};
	const reader: IndexReader = {
		async scan(domain, opts): Promise<ScanPage> {
			calls.scan.push({ domain, opts });
			return { names: options.names ?? [], truncated: options.truncated ?? false, cursor: options.cursor ?? null };
		},
		async siblings(apex, opts) {
			calls.siblings.push({ apex, limit: opts.limit });
			return { siblings: options.siblings ?? [], truncated: options.siblingsTruncated ?? false };
		},
		async meta() {
			return options.meta ?? META;
		},
	};
	return { reader, calls };
}

function failingReader(overrides: Partial<IndexReader>): IndexReader {
	return { ...fakeReader().reader, ...overrides };
}

async function call(reader: IndexReader, path: string, init: { key?: string | null; method?: string; budgetMs?: number } = {}) {
	const headers: Record<string, string> = {};
	const key = init.key === undefined ? KEY : init.key;
	if (key !== null) headers.authorization = `Bearer ${key}`;
	const response = await handleApiRequest(
		new Request(`https://bv-ct-index${path}`, { method: init.method ?? 'GET', headers }),
		{ CT_INDEX_ADMIN_KEY: KEY },
		{ reader, budgetMs: init.budgetMs },
	);
	return { response, body: (await response.json()) as ApiBody };
}

describe('GET /enumerate', () => {
	it('returns the names under the domain in the shape bv-mcp parses, plus coverage', async () => {
		const { reader, calls } = fakeReader({
			names: [row('example.com'), row('api.example.com'), row('dev.example.com', { wildcard: true, issuer: 'R10' })],
		});
		const { response, body } = await call(reader, '/enumerate?domain=Example.COM.');
		expect(response.status).toBe(200);
		expect(calls.scan).toEqual([{ domain: 'example.com', opts: { limit: PAGE_LIMIT, cursor: null } }]);
		expect(body.domain).toBe('example.com');
		// A wildcard row also lists `*.name`, because bv-mcp counts wildcards from the `*.` prefix.
		expect(body.subdomains).toEqual(['example.com', 'api.example.com', 'dev.example.com', '*.dev.example.com']);
		expect(body).toMatchObject({ certificateCount: 3, timedOut: false, cached: false, truncated: false, cursor: null });
		expect(body.entries?.[2]).toEqual({
			name: 'dev.example.com',
			firstSeen: '2026-09-21T14:13:20.000Z',
			notAfter: '2027-01-15T08:00:00.000Z',
			issuer: 'R10',
			wildcard: true,
		});
		expect(body.coverage).toEqual({
			source: 'bv-ct-index',
			indexStartedAt: META.indexStartedAt,
			freshThrough: META.freshThrough,
			historyWindow: 'forward-from',
			truncated: false,
		});
	});

	it('serves a public suffix (govt.nz) as a plain range scan', async () => {
		const { reader, calls } = fakeReader({ names: [row('dia.govt.nz'), row('www.dia.govt.nz'), row('health.govt.nz')] });
		const { response, body } = await call(reader, '/enumerate?domain=govt.nz');
		expect(response.status).toBe(200);
		expect(calls.scan[0]!.domain).toBe('govt.nz');
		expect(body.subdomains).toEqual(['dia.govt.nz', 'www.dia.govt.nz', 'health.govt.nz']);
	});

	it('marks a giant apex truncated and hands back the cursor, and accepts it on the next call', async () => {
		const names = Array.from({ length: PAGE_LIMIT }, (_, i) => row(`h${String(i).padStart(4, '0')}.amazonaws.com`));
		const { reader, calls } = fakeReader({ names, truncated: true, cursor: 'Y3Vyc29y' });
		const first = await call(reader, '/enumerate?domain=amazonaws.com');
		expect(first.response.status).toBe(200);
		expect(first.body.truncated).toBe(true);
		expect(first.body.coverage.truncated).toBe(true);
		expect(first.body.subdomains).toHaveLength(PAGE_LIMIT);
		expect(first.body.cursor).toBe('Y3Vyc29y');

		await call(reader, '/enumerate?domain=amazonaws.com&cursor=Y3Vyc29y');
		expect(calls.scan[1]!.opts).toEqual({ limit: PAGE_LIMIT, cursor: 'Y3Vyc29y' });
	});

	it('answers a healthy empty index read with 200, zero names and coverage', async () => {
		const { reader } = fakeReader({ names: [] });
		const { response, body } = await call(reader, '/enumerate?domain=unseen.example');
		expect(response.status).toBe(200);
		expect(body).toMatchObject({ subdomains: [], certificateCount: 0, truncated: false });
		expect(body.coverage.historyWindow).toBe('forward-from');
		expect(body.error).toBeUndefined();
	});
});

describe('GET /sans', () => {
	it('returns the siblings of the registrable domain as `names`', async () => {
		const { reader, calls } = fakeReader({
			siblings: [sibling('example.co.nz', 'example.nz'), sibling('example.co.nz', 'example-shop.co.nz')],
		});
		const { response, body } = await call(reader, '/sans?domain=www.example.co.nz');
		expect(response.status).toBe(200);
		expect(calls.siblings).toEqual([{ apex: 'example.co.nz', limit: PAGE_LIMIT }]);
		expect(body).toMatchObject({
			domain: 'www.example.co.nz',
			apex: 'example.co.nz',
			names: ['example.nz', 'example-shop.co.nz'],
			certificateCount: 2,
			timedOut: false,
			truncated: false,
			cached: false,
		});
		expect(body.coverage).toMatchObject({ source: 'bv-ct-index', historyWindow: 'forward-from', truncated: false });
	});

	it('reports a truncated sibling page in both `truncated` and coverage', async () => {
		const { reader } = fakeReader({ siblings: [sibling('cdn.example', 'a.example')], siblingsTruncated: true });
		const { body } = await call(reader, '/sans?domain=cdn.example');
		expect(body.truncated).toBe(true);
		expect(body.coverage.truncated).toBe(true);
	});

	it('answers a public suffix, which has no apex, with a healthy empty list and no reader call', async () => {
		const { reader, calls } = fakeReader();
		const { response, body } = await call(reader, '/sans?domain=govt.nz');
		expect(response.status).toBe(200);
		expect(body).toMatchObject({ names: [], apex: null, truncated: false });
		expect(calls.siblings).toEqual([]);
	});
});

describe('GET /cert-meta', () => {
	it('returns the issuer of the exact-name row', async () => {
		const { reader, calls } = fakeReader({ names: [row('example.com', { issuer: 'Google Trust Services WE1' })] });
		const { response, body } = await call(reader, '/cert-meta?domain=example.com');
		expect(response.status).toBe(200);
		expect(calls.scan).toEqual([{ domain: 'example.com', opts: { limit: 1, cursor: undefined } }]);
		expect(body).toMatchObject({
			domain: 'example.com',
			issuer: 'Google Trust Services WE1',
			firstSeen: '2026-09-21T14:13:20.000Z',
			notAfter: '2027-01-15T08:00:00.000Z',
		});
		expect(body.coverage.truncated).toBe(false);
	});

	it('gives no issuer when only a child name was seen (the first row is not the exact name)', async () => {
		const { reader } = fakeReader({ names: [row('api.example.com')] });
		const { response, body } = await call(reader, '/cert-meta?domain=example.com');
		expect(response.status).toBe(200);
		expect(body.issuer).toBeNull();
	});
});

describe('faults are 503, never an empty 200', () => {
	const boom = () => Promise.reject(new Error('R2 get failed: secret-internal-detail'));

	it.each([
		['/enumerate?domain=example.com', failingReader({ scan: boom })],
		['/enumerate?domain=example.com', failingReader({ meta: boom })],
		['/sans?domain=example.com', failingReader({ siblings: boom })],
		['/sans?domain=example.com', failingReader({ meta: boom })],
		['/cert-meta?domain=example.com', failingReader({ scan: boom })],
	])('%s', async (path, reader) => {
		const { response, body } = await call(reader, path);
		expect(response.status).toBe(503);
		expect(body.error).toBe('ct_index_unavailable');
		// No answer fields that bv-mcp could take for a result, and no internal detail.
		expect(body.subdomains).toBeUndefined();
		expect(body.names).toBeUndefined();
		expect(body.issuer).toBeUndefined();
		expect(JSON.stringify(body)).not.toContain('secret-internal-detail');
	});

	it('answers 503 once the internal budget is spent', async () => {
		const hang = () => new Promise<never>(() => undefined);
		const { response, body } = await call(failingReader({ scan: hang }), '/enumerate?domain=example.com', { budgetMs: 20 });
		expect(response.status).toBe(503);
		expect(body.error).toBe('ct_index_timeout');
		expect(API_BUDGET_MS).toBe(1500);
	});

	it('answers 503 from an index that has never been populated, not an empty 200', async () => {
		const { reader } = fakeReader({ meta: { indexStartedAt: null, freshThrough: null, generation: 1 } });
		for (const path of ['/enumerate', '/sans', '/cert-meta']) {
			const { response, body } = await call(reader, `${path}?domain=example.com`);
			expect(response.status).toBe(503);
			expect(body.error).toBe('index_not_ready');
		}
	});
});

describe('authentication', () => {
	const { reader } = fakeReader({ names: [row('example.com')] });

	it.each([
		['no Authorization header', null],
		['a wrong key', 'not-the-key'],
		['an empty key', ''],
		['a prefix of the key', KEY.slice(0, -1)],
		['the key with extra characters', `${KEY}x`],
	])('rejects %s with 401', async (_label, key) => {
		const { response, body } = await call(reader, '/enumerate?domain=example.com', { key });
		expect(response.status).toBe(401);
		expect(body.error).toBe('unauthorized');
	});

	it('rejects a non-Bearer scheme', async () => {
		const response = await handleApiRequest(
			new Request('https://bv-ct-index/enumerate?domain=example.com', { headers: { authorization: `Basic ${KEY}` } }),
			{ CT_INDEX_ADMIN_KEY: KEY },
			{ reader },
		);
		expect(response.status).toBe(401);
	});

	it.each([undefined, ''])('fails closed with 401 when CT_INDEX_ADMIN_KEY is %j, whatever the caller sends', async (secret) => {
		for (const authorization of [`Bearer ${KEY}`, 'Bearer ', 'Bearer undefined', undefined]) {
			const response = await handleApiRequest(
				new Request('https://bv-ct-index/enumerate?domain=example.com', { headers: authorization ? { authorization } : {} }),
				{ CT_INDEX_ADMIN_KEY: secret as string },
				{ reader },
			);
			expect(response.status).toBe(401);
		}
	});

	it('accepts the right key', async () => {
		const { response } = await call(reader, '/enumerate?domain=example.com');
		expect(response.status).toBe(200);
	});

	it('compares the key itself, not its length', async () => {
		expect(await isAuthorized(`Bearer ${KEY}`, KEY)).toBe(true);
		expect(await isAuthorized(`bearer ${KEY}`, KEY)).toBe(true);
		expect(await isAuthorized(`Bearer ${'x'.repeat(KEY.length)}`, KEY)).toBe(false);
		expect(await isAuthorized(`Bearer ${KEY}`, undefined)).toBe(false);
	});
});

describe('request validation', () => {
	const { reader, calls } = fakeReader();

	it.each([
		['a missing domain', '/enumerate'],
		['an empty domain', '/sans?domain='],
		['a space in the name', '/enumerate?domain=bad%20domain.com'],
		['a wildcard', '/enumerate?domain=*.example.com'],
		['an empty label', '/cert-meta?domain=a..example.com'],
		['a non-ASCII label', '/sans?domain=b%C3%BCcher.example'],
		['a slash', '/enumerate?domain=example.com/path'],
		['a 64-character label', `/enumerate?domain=${'a'.repeat(64)}.example`],
		['a name over 253 characters', `/enumerate?domain=${`${'a'.repeat(60)}.`.repeat(5)}example`],
	])('answers 400 with an error body for %s, before touching the reader', async (_label, path) => {
		const { response, body } = await call(reader, path);
		expect(response.status).toBe(400);
		expect(typeof body.error).toBe('string');
		expect(body.error).toMatch(/^invalid_request/);
		expect(calls.scan).toEqual([]);
		expect(calls.siblings).toEqual([]);
	});

	it('maps a reader RangeError (a cursor from another scan) to 400', async () => {
		const rejecting = failingReader({
			scan: () => Promise.reject(new RangeError('cursor does not belong to this scan')),
		});
		const { response, body } = await call(rejecting, '/enumerate?domain=example.com&cursor=abc');
		expect(response.status).toBe(400);
		expect(body.error).toBe('invalid_request: cursor does not belong to this scan');
	});

	it('answers 404 for an unknown path and 405 for a non-GET method, after auth', async () => {
		expect((await call(reader, '/nope?domain=example.com')).response.status).toBe(404);
		expect((await call(reader, '/enumerate?domain=example.com', { method: 'POST' })).response.status).toBe(405);
		expect((await call(reader, '/nope?domain=example.com', { key: null })).response.status).toBe(401);
	});

	it('parseDomain normalizes case and a trailing dot, and accepts a bare suffix and A-labels', () => {
		expect(parseDomain(' WWW.Example.COM. ')).toBe('www.example.com');
		expect(parseDomain('govt.nz')).toBe('govt.nz');
		expect(parseDomain('xn--bcher-kva.example')).toBe('xn--bcher-kva.example');
		expect(parseDomain('_dmarc.example.com')).toBe('_dmarc.example.com');
		expect(parseDomain('-bad.example')).toBeNull();
		expect(parseDomain(null)).toBeNull();
	});
});
