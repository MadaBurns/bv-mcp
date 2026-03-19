import { afterEach, describe, expect, it, vi } from 'vitest';
import { type DohResponse, DnsQueryError, queryDns, RecordType } from '../src/lib/dns';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

describe('dns transport helpers', () => {
	it('retries once after a transient 5xx response', async () => {
		const fetchMock = vi
			.fn()
			.mockResolvedValueOnce({
				ok: false,
				status: 503,
			} as unknown as Response)
			.mockResolvedValueOnce({
				ok: true,
				status: 200,
				json: () =>
					Promise.resolve({
						Status: 0,
						TC: false,
						RD: true,
						RA: true,
						AD: false,
						CD: false,
						Question: [{ name: 'example.com', type: RecordType.A }],
						Answer: [{ name: 'example.com', type: RecordType.A, TTL: 300, data: '1.2.3.4' }],
					}),
			} as unknown as Response);

		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const response = await queryDns('example.com', 'A', false, { retries: 1, confirmWithSecondaryOnEmpty: false });

		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(response.Answer?.[0]?.data).toBe('1.2.3.4');
	});

	it('passes cf edge cache options to fetch in queryDns', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: () =>
				Promise.resolve({
					Status: 0,
					TC: false,
					RD: true,
					RA: true,
					AD: false,
					CD: false,
					Question: [{ name: 'example.com', type: RecordType.A }],
					Answer: [{ name: 'example.com', type: RecordType.A, TTL: 300, data: '1.2.3.4' }],
				}),
		} as unknown as Response);

		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		await queryDns('example.com', 'A', false, { retries: 0, confirmWithSecondaryOnEmpty: false });

		expect(fetchMock).toHaveBeenCalledTimes(1);
		const callArgs = fetchMock.mock.calls[0];
		expect(callArgs[1]).toHaveProperty('cf');
		expect(callArgs[1].cf).toEqual({ cacheTtl: 300, cacheEverything: true });
	});

	it('adds delay between retry attempts (jitter)', async () => {
		const start = Date.now();
		const fetchMock = vi
			.fn()
			.mockRejectedValueOnce(new Error('network fail'))
			.mockResolvedValueOnce({
				ok: true,
				status: 200,
				json: () =>
					Promise.resolve({
						Status: 0,
						Question: [{ name: 'example.com', type: RecordType.A }],
						Answer: [{ name: 'example.com', type: RecordType.A, TTL: 300, data: '1.2.3.4' }],
					}),
			} as unknown as Response);

		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		await queryDns('example.com', 'A', false, { retries: 1, confirmWithSecondaryOnEmpty: false });
		const elapsed = Date.now() - start;

		expect(fetchMock).toHaveBeenCalledTimes(2);
		// Should have at least some delay (base 100ms * 1 attempt = 100ms minimum)
		expect(elapsed).toBeGreaterThanOrEqual(50);
	});

	it('throws a timeout error after the final abort', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('The operation was aborted.', 'AbortError')) as unknown as typeof globalThis.fetch;

		await expect(queryDns('example.com', 'TXT', false, { retries: 0, timeoutMs: 5 })).rejects.toMatchObject<DnsQueryError>({
			message: 'DNS query timed out after 5ms',
			domain: 'example.com',
			recordType: 'TXT',
		});
	});
});

describe('queryDns cache', () => {
	const makeDohResponse = (domain = 'example.com', type = RecordType.TXT): DohResponse => ({
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: domain, type }],
		Answer: [{ name: domain, type, TTL: 300, data: '"v=spf1 -all"' }],
	});

	it('cache hit returns same response without calling fetch', async () => {
		const cached = makeDohResponse();
		const queryCache = new Map<string, Promise<DohResponse>>([['example.com:TXT:false', Promise.resolve(cached)]]);

		const fetchMock = vi.fn();
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const result = await queryDns('example.com', 'TXT', false, { queryCache, retries: 0, confirmWithSecondaryOnEmpty: false });

		expect(fetchMock).not.toHaveBeenCalled();
		expect(result).toBe(cached);
	});

	it('concurrent queries coalesce into one fetch', async () => {
		const dohResponse = makeDohResponse();
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: () => Promise.resolve(dohResponse),
		} as unknown as Response);

		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const queryCache = new Map<string, Promise<DohResponse>>();
		const [r1, r2] = await Promise.all([
			queryDns('example.com', 'TXT', false, { queryCache, retries: 0, confirmWithSecondaryOnEmpty: false }),
			queryDns('example.com', 'TXT', false, { queryCache, retries: 0, confirmWithSecondaryOnEmpty: false }),
		]);

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(r1).toBe(r2);
	});

	it('no caching when queryCache not provided', async () => {
		const dohResponse = makeDohResponse();
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: () => Promise.resolve(dohResponse),
		} as unknown as Response);

		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		await queryDns('example.com', 'TXT', false, { retries: 0, confirmWithSecondaryOnEmpty: false });
		await queryDns('example.com', 'TXT', false, { retries: 0, confirmWithSecondaryOnEmpty: false });

		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('failed queries evicted from cache', async () => {
		const dohResponse = makeDohResponse();
		const fetchMock = vi
			.fn()
			.mockRejectedValueOnce(new DOMException('The operation was aborted.', 'AbortError'))
			.mockResolvedValueOnce({
				ok: true,
				status: 200,
				json: () => Promise.resolve(dohResponse),
			} as unknown as Response);

		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const queryCache = new Map<string, Promise<DohResponse>>();
		const cacheKey = 'example.com:TXT:false';

		await expect(queryDns('example.com', 'TXT', false, { queryCache, retries: 0, timeoutMs: 5 })).rejects.toThrow();

		// Allow microtask for .catch() eviction to run
		await new Promise((r) => setTimeout(r, 0));
		expect(queryCache.has(cacheKey)).toBe(false);

		const result = await queryDns('example.com', 'TXT', false, { queryCache, retries: 0, confirmWithSecondaryOnEmpty: false });
		expect(result).toEqual(dohResponse);
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});
});

describe('secondary DoH resolver (bv-dns)', () => {
	const emptyCloudflareResponse: DohResponse = {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: 'example.com', type: RecordType.TXT }],
		// No Answer — triggers secondary confirmation
	};

	const bvDnsResponse: DohResponse = {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: 'example.com', type: RecordType.TXT }],
		Answer: [{ name: 'example.com', type: RecordType.TXT, TTL: 300, data: '"v=spf1 -all"' }],
	};

	const googleResponse: DohResponse = {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: 'example.com', type: RecordType.TXT }],
		Answer: [{ name: 'example.com', type: RecordType.TXT, TTL: 300, data: '"v=spf1 ~all"' }],
	};

	it('uses bv-dns as secondary when Cloudflare returns empty and secondaryDoh is configured', async () => {
		const fetchMock = vi.fn().mockImplementation((url: string | URL | Request) => {
			const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
			if (urlStr.includes('cloudflare-dns.com')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(emptyCloudflareResponse),
				} as unknown as Response);
			}
			if (urlStr.includes('harlan.blackveil')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(bvDnsResponse),
				} as unknown as Response);
			}
			return Promise.reject(new Error(`unexpected URL: ${urlStr}`));
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const result = await queryDns('example.com', 'TXT', false, {
			retries: 0,
			confirmWithSecondaryOnEmpty: true,
			secondaryDoh: { endpoint: 'https://harlan.blackveilsecurity.com/dns-query', token: 'test-token' },
		});

		expect(result.Answer).toHaveLength(1);
		expect(result.Answer![0].data).toBe('"v=spf1 -all"');
		// Cloudflare + bv-dns = 2 calls, Google not called
		expect(fetchMock).toHaveBeenCalledTimes(2);
		const bvDnsCall = fetchMock.mock.calls.find((c: unknown[]) => (c[0] as string).includes('harlan.blackveil'));
		expect(bvDnsCall).toBeDefined();
	});

	it('sends X-BV-Token header when token is provided', async () => {
		const fetchMock = vi.fn().mockImplementation((url: string | URL | Request) => {
			const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
			if (urlStr.includes('cloudflare-dns.com')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(emptyCloudflareResponse),
				} as unknown as Response);
			}
			if (urlStr.includes('harlan.blackveil')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(bvDnsResponse),
				} as unknown as Response);
			}
			return Promise.reject(new Error(`unexpected URL: ${urlStr}`));
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		await queryDns('example.com', 'TXT', false, {
			retries: 0,
			confirmWithSecondaryOnEmpty: true,
			secondaryDoh: { endpoint: 'https://harlan.blackveilsecurity.com/dns-query', token: 'my-secret' },
		});

		const bvDnsCall = fetchMock.mock.calls.find((c: unknown[]) => (c[0] as string).includes('harlan.blackveil'));
		expect(bvDnsCall).toBeDefined();
		expect(bvDnsCall![1].headers).toHaveProperty('X-BV-Token', 'my-secret');
	});

	it('falls through to Google when bv-dns also returns empty', async () => {
		const emptyBvDns: DohResponse = { ...emptyCloudflareResponse };

		const fetchMock = vi.fn().mockImplementation((url: string | URL | Request) => {
			const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
			if (urlStr.includes('cloudflare-dns.com')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(emptyCloudflareResponse),
				} as unknown as Response);
			}
			if (urlStr.includes('harlan.blackveil')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(emptyBvDns),
				} as unknown as Response);
			}
			if (urlStr.includes('dns.google')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(googleResponse),
				} as unknown as Response);
			}
			return Promise.reject(new Error(`unexpected URL: ${urlStr}`));
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const result = await queryDns('example.com', 'TXT', false, {
			retries: 0,
			confirmWithSecondaryOnEmpty: true,
			secondaryDoh: { endpoint: 'https://harlan.blackveilsecurity.com/dns-query' },
		});

		// Should get Google's response since bv-dns was also empty
		expect(result.Answer).toHaveLength(1);
		expect(result.Answer![0].data).toBe('"v=spf1 ~all"');
		// Cloudflare + bv-dns + Google = 3 calls
		expect(fetchMock).toHaveBeenCalledTimes(3);
	});

	it('falls through to Google when bv-dns times out or errors', async () => {
		const fetchMock = vi.fn().mockImplementation((url: string | URL | Request) => {
			const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
			if (urlStr.includes('cloudflare-dns.com')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(emptyCloudflareResponse),
				} as unknown as Response);
			}
			if (urlStr.includes('harlan.blackveil')) {
				return Promise.reject(new Error('connection refused'));
			}
			if (urlStr.includes('dns.google')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(googleResponse),
				} as unknown as Response);
			}
			return Promise.reject(new Error(`unexpected URL: ${urlStr}`));
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const result = await queryDns('example.com', 'TXT', false, {
			retries: 0,
			confirmWithSecondaryOnEmpty: true,
			secondaryDoh: { endpoint: 'https://harlan.blackveilsecurity.com/dns-query', token: 'test' },
		});

		// Should fall through to Google
		expect(result.Answer).toHaveLength(1);
		expect(result.Answer![0].data).toBe('"v=spf1 ~all"');
		expect(fetchMock).toHaveBeenCalledTimes(3);
	});

	it('does not call bv-dns when secondaryDoh is not configured (existing behavior)', async () => {
		const fetchMock = vi.fn().mockImplementation((url: string | URL | Request) => {
			const urlStr = typeof url === 'string' ? url : url instanceof URL ? url.toString() : url.url;
			if (urlStr.includes('cloudflare-dns.com')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(emptyCloudflareResponse),
				} as unknown as Response);
			}
			if (urlStr.includes('dns.google')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve(googleResponse),
				} as unknown as Response);
			}
			return Promise.reject(new Error(`unexpected URL: ${urlStr}`));
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const result = await queryDns('example.com', 'TXT', false, {
			retries: 0,
			confirmWithSecondaryOnEmpty: true,
			// No secondaryDoh configured
		});

		// Should go straight to Google, no bv-dns call
		expect(result.Answer).toHaveLength(1);
		expect(fetchMock).toHaveBeenCalledTimes(2);
		const urls = fetchMock.mock.calls.map((c: unknown[]) => c[0] as string);
		expect(urls.some((u: string) => u.includes('harlan.blackveil'))).toBe(false);
	});

	it('skips all secondary calls when skipSecondaryConfirmation is true', async () => {
		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: () => Promise.resolve(emptyCloudflareResponse),
		} as unknown as Response);
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		const result = await queryDns('example.com', 'TXT', false, {
			retries: 0,
			confirmWithSecondaryOnEmpty: true,
			skipSecondaryConfirmation: true,
			secondaryDoh: { endpoint: 'https://harlan.blackveilsecurity.com/dns-query', token: 'test' },
		});

		// Only Cloudflare called, no secondary
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(result.Answer).toBeUndefined();
	});
});