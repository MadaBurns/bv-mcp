import { describe, it, expect, vi, afterEach } from 'vitest';
import { queryDns, queryDnsRecords, queryTxtRecords, checkDnssec, queryMxRecords, DnsQueryError, RecordType } from '../src/lib/dns';
import { setupFetchMock, mockFetchResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

describe('DNS library', () => {
	describe('queryDns', () => {
		it('sends correct DoH request', async () => {
			const dohResponse = {
				Status: 0,
				TC: false,
				RD: true,
				RA: true,
				AD: false,
				CD: false,
				Question: [{ name: 'example.com', type: 1 }],
				Answer: [{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' }],
			};
			mockFetchResponse(dohResponse);

			const result = await queryDns('example.com', 'A');
			expect(result).toEqual(dohResponse);

			const fetchCall = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0];
			const url = fetchCall[0] as string;
			expect(url).toContain('name=example.com');
			expect(url).toContain('type=A');
			expect(fetchCall[1].headers.Accept).toBe('application/dns-json');
		});

		it('includes cd=0 param when dnssecCheck is true', async () => {
			mockFetchResponse({ Status: 0, TC: false, RD: true, RA: true, AD: true, CD: false, Question: [], Answer: [] });
			await queryDns('example.com', 'A', true);

			const url = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0][0] as string;
			expect(url).toContain('cd=0');
		});

		it('throws DnsQueryError on HTTP error', async () => {
			mockFetchResponse({}, false, 503);
			await expect(queryDns('example.com', 'A')).rejects.toThrow(DnsQueryError);
		});

		it('throws DnsQueryError on network failure', async () => {
			mockFetchError(new Error('Network error'));
			await expect(queryDns('example.com', 'A')).rejects.toThrow(DnsQueryError);
		});
	});

	describe('queryDnsRecords', () => {
		it('returns data strings filtered by record type', async () => {
			mockFetchResponse({
				Status: 0,
				TC: false,
				RD: true,
				RA: true,
				AD: false,
				CD: false,
				Question: [{ name: 'example.com', type: 16 }],
				Answer: [
					{ name: 'example.com', type: RecordType.TXT, TTL: 300, data: '"v=spf1 -all"' },
					{ name: 'example.com', type: RecordType.CNAME, TTL: 300, data: 'other.com' },
				],
			});

			const records = await queryDnsRecords('example.com', 'TXT');
			expect(records).toEqual(['"v=spf1 -all"']);
		});

		it('returns empty array when no answers', async () => {
			mockFetchResponse({
				Status: 0,
				TC: false,
				RD: true,
				RA: true,
				AD: false,
				CD: false,
				Question: [{ name: 'example.com', type: 16 }],
			});

			const records = await queryDnsRecords('example.com', 'TXT');
			expect(records).toEqual([]);
		});
	});

	describe('queryTxtRecords', () => {
		it('strips surrounding quotes from TXT data', async () => {
			mockFetchResponse({
				Status: 0,
				TC: false,
				RD: true,
				RA: true,
				AD: false,
				CD: false,
				Question: [{ name: 'example.com', type: 16 }],
				Answer: [{ name: 'example.com', type: RecordType.TXT, TTL: 300, data: '"v=spf1 include:_spf.google.com -all"' }],
			});

			const records = await queryTxtRecords('example.com');
			expect(records).toEqual(['v=spf1 include:_spf.google.com -all']);
		});
	});

	describe('checkDnssec', () => {
		it('returns true when AD flag is set', async () => {
			mockFetchResponse({ Status: 0, TC: false, RD: true, RA: true, AD: true, CD: false, Question: [], Answer: [] });
			expect(await checkDnssec('example.com')).toBe(true);
		});

		it('returns false when AD flag is not set', async () => {
			mockFetchResponse({ Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [], Answer: [] });
			expect(await checkDnssec('example.com')).toBe(false);
		});
	});

	describe('queryMxRecords', () => {
		it('parses MX records into priority and exchange', async () => {
			mockFetchResponse({
				Status: 0,
				TC: false,
				RD: true,
				RA: true,
				AD: false,
				CD: false,
				Question: [{ name: 'example.com', type: 15 }],
				Answer: [
					{ name: 'example.com', type: RecordType.MX, TTL: 300, data: '10 mail.example.com.' },
					{ name: 'example.com', type: RecordType.MX, TTL: 300, data: '20 backup.example.com.' },
				],
			});

			const records = await queryMxRecords('example.com');
			expect(records).toEqual([
				{ priority: 10, exchange: 'mail.example.com' },
				{ priority: 20, exchange: 'backup.example.com' },
			]);
		});
	});
});
