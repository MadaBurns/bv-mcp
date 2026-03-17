// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it } from 'vitest';
import { vi } from 'vitest';
import { createDohResponse, ptrResponse, setupFetchMock, srvResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

describe('queryPtrRecords', () => {
	it('queries reverse DNS and strips trailing dots', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(ptrResponse('1.2.3.4', ['mail.example.com']));

		const { queryPtrRecords } = await import('../src/lib/dns-records');
		const results = await queryPtrRecords('1.2.3.4');

		expect(results).toEqual(['mail.example.com']);
		expect(vi.mocked(globalThis.fetch)).toHaveBeenCalledWith(
			expect.stringContaining('4.3.2.1.in-addr.arpa'),
			expect.anything(),
		);
	});

	it('returns multiple PTR hostnames', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(ptrResponse('10.20.30.40', ['a.example.com', 'b.example.com']));

		const { queryPtrRecords } = await import('../src/lib/dns-records');
		const results = await queryPtrRecords('10.20.30.40');

		expect(results).toEqual(['a.example.com', 'b.example.com']);
	});

	it('returns empty array when no PTR records exist', async () => {
		const reverseName = '4.3.2.1.in-addr.arpa';
		globalThis.fetch = vi.fn().mockResolvedValue(createDohResponse([{ name: reverseName, type: 12 }], []));

		const { queryPtrRecords } = await import('../src/lib/dns-records');
		const results = await queryPtrRecords('1.2.3.4');

		expect(results).toEqual([]);
	});
});

describe('querySrvRecords', () => {
	it('parses SRV records with priority, weight, port, and target', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			srvResponse('_submission._tcp.example.com', [
				{ priority: 10, weight: 5, port: 587, target: 'mail.example.com' },
			]),
		);

		const { querySrvRecords } = await import('../src/lib/dns-records');
		const results = await querySrvRecords('_submission._tcp.example.com');

		expect(results).toEqual([{ priority: 10, weight: 5, port: 587, target: 'mail.example.com' }]);
	});

	it('parses multiple SRV records', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			srvResponse('_imaps._tcp.example.com', [
				{ priority: 10, weight: 60, port: 993, target: 'imap1.example.com' },
				{ priority: 20, weight: 40, port: 993, target: 'imap2.example.com' },
			]),
		);

		const { querySrvRecords } = await import('../src/lib/dns-records');
		const results = await querySrvRecords('_imaps._tcp.example.com');

		expect(results).toEqual([
			{ priority: 10, weight: 60, port: 993, target: 'imap1.example.com' },
			{ priority: 20, weight: 40, port: 993, target: 'imap2.example.com' },
		]);
	});

	it('returns empty array when no SRV records exist', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse([{ name: '_submission._tcp.example.com', type: 33 }], []),
		);

		const { querySrvRecords } = await import('../src/lib/dns-records');
		const results = await querySrvRecords('_submission._tcp.example.com');

		expect(results).toEqual([]);
	});
});

describe('parseTlsaRecord', () => {
	it('parses human-readable TLSA record', async () => {
		const { parseTlsaRecord } = await import('../src/lib/dns-records');
		const result = parseTlsaRecord('3 1 1 abc123def456');

		expect(result).toEqual({
			usage: 3,
			selector: 1,
			matchingType: 1,
			certData: 'abc123def456',
		});
	});

	it('parses TLSA record with DANE-EE full cert SHA-256', async () => {
		const { parseTlsaRecord } = await import('../src/lib/dns-records');
		const hash = '8d02536c887482bc34ff54e41d2ba659bf85b341a0a20afadb5813dcfbcf286d';
		const result = parseTlsaRecord(`3 0 1 ${hash}`);

		expect(result).toEqual({
			usage: 3,
			selector: 0,
			matchingType: 1,
			certData: hash,
		});
	});

	it('parses hex wire-format TLSA record', async () => {
		const { parseTlsaRecord } = await import('../src/lib/dns-records');
		const result = parseTlsaRecord('\\# 35 03 01 01 61 62 63');

		expect(result).toEqual({
			usage: 3,
			selector: 1,
			matchingType: 1,
			certData: '616263',
		});
	});

	it('returns null for empty string', async () => {
		const { parseTlsaRecord } = await import('../src/lib/dns-records');
		expect(parseTlsaRecord('')).toBeNull();
	});

	it('returns null for insufficient parts', async () => {
		const { parseTlsaRecord } = await import('../src/lib/dns-records');
		expect(parseTlsaRecord('3 1')).toBeNull();
	});

	it('returns null for non-numeric fields', async () => {
		const { parseTlsaRecord } = await import('../src/lib/dns-records');
		expect(parseTlsaRecord('x y z certdata')).toBeNull();
	});

	it('returns null for insufficient hex wire bytes', async () => {
		const { parseTlsaRecord } = await import('../src/lib/dns-records');
		expect(parseTlsaRecord('\\# 2 03 01')).toBeNull();
	});
});
