// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it } from 'vitest';
import { vi } from 'vitest';
import { createDohResponse, ptrResponse, setupFetchMock, srvResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
});

describe('queryTxtRecords', () => {
	it('concatenates multi-string TXT records without adding spaces (RFC 7208 §3.3)', async () => {
		// Simulate DoH data where a token is split across TXT string boundaries
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse([{ name: 'example.com', type: 16 }], [
				{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 include:a.example.com ip" "4:192.0.2.1 ~all"' },
			]),
		);

		const { queryTxtRecords } = await import('../src/lib/dns-records');
		const results = await queryTxtRecords('example.com');

		expect(results).toEqual(['v=spf1 include:a.example.com ip4:192.0.2.1 ~all']);
	});

	it('unescapes single-backslash DNS escaping in TXT data', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse([{ name: '_dmarc.example.com', type: 16 }], [
				{ name: '_dmarc.example.com', type: 16, TTL: 300, data: '"v=DMARC1\\; p=none\\; sp=reject\\; rua=mailto:d@example.com"' },
			]),
		);

		const { queryTxtRecords } = await import('../src/lib/dns-records');
		const results = await queryTxtRecords('_dmarc.example.com');

		expect(results).toEqual(['v=DMARC1; p=none; sp=reject; rua=mailto:d@example.com']);
	});

	it('unescapes double-backslash DNS escaping from DoH providers', async () => {
		// Cloudflare/Google DoH double-escapes: raw JSON has \\\\; which JS parses to \\;
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse([{ name: '_dmarc.example.com', type: 16 }], [
				{ name: '_dmarc.example.com', type: 16, TTL: 300, data: '"v=DMARC1\\\\; p=none\\\\; sp=reject\\\\; rua=mailto:d@example.com"' },
			]),
		);

		const { queryTxtRecords } = await import('../src/lib/dns-records');
		const results = await queryTxtRecords('_dmarc.example.com');

		expect(results).toEqual(['v=DMARC1; p=none; sp=reject; rua=mailto:d@example.com']);
	});

	it('unescapes DNS decimal octet escapes (\\DDD)', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse([{ name: 'example.com', type: 16 }], [
				{ name: 'example.com', type: 16, TTL: 300, data: '"hello\\032world"' },
			]),
		);

		const { queryTxtRecords } = await import('../src/lib/dns-records');
		const results = await queryTxtRecords('example.com');

		// \032 = space character (decimal 32)
		expect(results).toEqual(['hello world']);
	});

	it('passes through records without escaping unchanged', async () => {
		globalThis.fetch = vi.fn().mockResolvedValue(
			createDohResponse([{ name: 'example.com', type: 16 }], [
				{ name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 include:_spf.google.com ~all"' },
			]),
		);

		const { queryTxtRecords } = await import('../src/lib/dns-records');
		const results = await queryTxtRecords('example.com');

		expect(results).toEqual(['v=spf1 include:_spf.google.com ~all']);
	});
});

describe('unescapeDnsTxt', () => {
	it('unescapes backslash-semicolons', async () => {
		const { unescapeDnsTxt } = await import('../src/lib/dns-records');
		expect(unescapeDnsTxt('p=none\\; sp=reject')).toBe('p=none; sp=reject');
	});

	it('unescapes double-backslash-semicolons from DoH providers', async () => {
		const { unescapeDnsTxt } = await import('../src/lib/dns-records');
		expect(unescapeDnsTxt('p=none\\\\; sp=reject')).toBe('p=none; sp=reject');
	});

	it('unescapes decimal octets', async () => {
		const { unescapeDnsTxt } = await import('../src/lib/dns-records');
		expect(unescapeDnsTxt('hello\\032world')).toBe('hello world');
	});

	it('preserves invalid decimal octets above 255', async () => {
		const { unescapeDnsTxt } = await import('../src/lib/dns-records');
		expect(unescapeDnsTxt('test\\999value')).toBe('test\\999value');
	});

	it('returns plain text unchanged', async () => {
		const { unescapeDnsTxt } = await import('../src/lib/dns-records');
		expect(unescapeDnsTxt('v=DMARC1; p=reject')).toBe('v=DMARC1; p=reject');
	});
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
