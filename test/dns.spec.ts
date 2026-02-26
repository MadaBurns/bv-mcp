import { describe, it, expect, vi, afterEach } from 'vitest';
import { queryDns, queryDnsRecords, queryTxtRecords, checkDnssec, queryMxRecords, DnsQueryError, RecordType } from '../src/lib/dns';
import { setupFetchMock, mockFetchResponse, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

describe('DNS library', () => {
	it('should parse DNS response correctly', () => {
		const response = {
			Answer: [{ name: 'example.com', type: 1, TTL: 300, data: '93.184.216.34' }],
		};
		expect(response.Answer[0].name).toBe('example.com');
		expect(response.Answer[0].data).toBe('93.184.216.34');
	});

	it('should handle empty DNS response', () => {
		const response = { Answer: [] as Array<{ name: string; type: number; TTL: number; data: string }> };
		expect(response.Answer).toEqual([]);
	});

	describe('queryTxtRecords', () => {
		it('returns parsed TXT records', async () => {
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
