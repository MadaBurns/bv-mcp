import { afterEach, describe, expect, it, vi } from 'vitest';
import { DnsQueryError, queryDns, RecordType } from '../src/lib/dns';
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

	it('throws a timeout error after the final abort', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new DOMException('The operation was aborted.', 'AbortError')) as unknown as typeof globalThis.fetch;

		await expect(queryDns('example.com', 'TXT', false, { retries: 0, timeoutMs: 5 })).rejects.toMatchObject<DnsQueryError>({
			message: 'DNS query timed out after 5ms',
			domain: 'example.com',
			recordType: 'TXT',
		});
	});
});