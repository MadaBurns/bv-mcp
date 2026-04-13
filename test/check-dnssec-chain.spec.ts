// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { RecordType } from '../src/lib/dns-types';

const { restore } = setupFetchMock();

afterEach(() => restore());

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a DoH response containing DS records for a zone. */
function dsResponse(zone: string, records: string[]) {
	return createDohResponse(
		[{ name: zone, type: RecordType.DS }],
		records.map((data) => ({ name: zone, type: RecordType.DS, TTL: 300, data })),
	);
}

/** Build a DoH response containing DNSKEY records for a zone. */
function dnskeyResponse(zone: string, records: string[]) {
	return createDohResponse(
		[{ name: zone, type: RecordType.DNSKEY }],
		records.map((data) => ({ name: zone, type: RecordType.DNSKEY, TTL: 300, data })),
	);
}

/** Build an empty DoH response for a given type. */
function emptyDsResponse(zone: string) {
	return createDohResponse([{ name: zone, type: RecordType.DS }], []);
}

function emptyDnskeyResponse(zone: string) {
	return createDohResponse([{ name: zone, type: RecordType.DNSKEY }], []);
}

/** Build an A-record response with AD flag. */
function adResponse(domain: string, ad: boolean) {
	return createDohResponse([{ name: domain, type: RecordType.A }], [{ name: domain, type: RecordType.A, TTL: 300, data: '93.184.216.34' }], { ad });
}

/**
 * Create a fetch mock that routes by URL query params (name + type).
 * `routeMap` keys are "name:type" (e.g. "com:DS", "example.com:DNSKEY", "example.com:A").
 */
function mockDnsFetch(routeMap: Record<string, Response>) {
	globalThis.fetch = vi.fn().mockImplementation((url: string | URL | Request) => {
		const u = new URL(typeof url === 'string' ? url : url instanceof Request ? url.url : url.toString());
		const name = u.searchParams.get('name') ?? '';
		const type = u.searchParams.get('type') ?? '';
		const key = `${name}:${type}`;
		const resp = routeMap[key];
		if (resp) return Promise.resolve(resp);
		// Default: empty response
		return Promise.resolve(createDohResponse([{ name, type: 1 }], []));
	});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('checkDnssecChain', () => {
	async function run(domain = 'example.com') {
		const { checkDnssecChain } = await import('../src/tools/check-dnssec-chain');
		return checkDnssecChain(domain);
	}

	it('fully signed chain reports chainComplete=true', async () => {
		mockDnsFetch({
			// Root zone — DNSKEY only (no DS for root)
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			// com zone
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com zone
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 8 AwEAAexample...']),
			// AD flag query
			'example.com:A': adResponse('example.com', true),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		// Should have at least an info finding with chain summary
		const infoFinding = result.findings.find((f) => f.severity === 'info' && f.metadata?.chainComplete === true);
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.metadata!.adFlag).toBe(true);
	});

	it('unsigned domain reports no DS', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com has no DS and no DNSKEY → unsigned
			'example.com:DS': emptyDsResponse('example.com'),
			'example.com:DNSKEY': emptyDnskeyResponse('example.com'),
			'example.com:A': adResponse('example.com', false),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		// Chain stops at unsigned zone — detail should mention "no DS" or "unsigned"
		const infoFinding = result.findings.find((f) => f.severity === 'info');
		expect(infoFinding).toBeDefined();
		expect(infoFinding!.detail).toMatch(/no DS|unsigned|not signed/i);
	});

	it('broken linkage (DS exists but no DNSKEY) produces high severity', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			// example.com has DS but NO DNSKEY → broken
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': emptyDnskeyResponse('example.com'),
			'example.com:A': adResponse('example.com', false),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		const highFinding = result.findings.find((f) => f.severity === 'high');
		expect(highFinding).toBeDefined();
		expect(highFinding!.detail).toMatch(/broken|no DNSKEY|mismatch/i);
	});

	it('maps algorithm 8 to RSA-SHA256', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 8 AwEAAexample...']),
			'example.com:A': adResponse('example.com', true),
		});

		const result = await run();

		// At least one zone should have RSA-SHA256 in its metadata
		const chainFinding = result.findings.find((f) => f.severity === 'info' && f.metadata?.zones);
		expect(chainFinding).toBeDefined();
		const zones = chainFinding!.metadata!.zones as Array<{ algorithms?: string[] }>;
		const allAlgs = zones.flatMap((z) => z.algorithms ?? []);
		expect(allAlgs).toContain('RSA-SHA256');
	});

	it('weak algorithm (algo 5 → RSA-SHA1) produces medium severity', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 5 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 5 1 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 5 AwEAAcom...']),
			'example.com:DS': dsResponse('example.com', ['54321 5 1 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 5 AwEAAexample...']),
			'example.com:A': adResponse('example.com', true),
		});

		const result = await run();
		expect(result.category).toBe('dnssec_chain');

		const mediumFinding = result.findings.find((f) => f.severity === 'medium');
		expect(mediumFinding).toBeDefined();
		expect(mediumFinding!.detail).toMatch(/weak|RSA-SHA1|deprecated/i);
	});

	it('deep subdomain walks root→com→example.com→sub.example.com', async () => {
		mockDnsFetch({
			'.:DNSKEY': dnskeyResponse('.', ['257 3 8 AwEAAagAI...']),
			'com:DS': dsResponse('com', ['12345 8 2 AABBCCDD']),
			'com:DNSKEY': dnskeyResponse('com', ['257 3 8 AwEAAcom...']),
			'example.com:DS': dsResponse('example.com', ['54321 8 2 DDEEFF00']),
			'example.com:DNSKEY': dnskeyResponse('example.com', ['257 3 8 AwEAAexample...']),
			'sub.example.com:DS': dsResponse('sub.example.com', ['11111 8 2 11223344']),
			'sub.example.com:DNSKEY': dnskeyResponse('sub.example.com', ['257 3 8 AwEAAsub...']),
			'sub.example.com:A': adResponse('sub.example.com', true),
		});

		const result = await run('sub.example.com');
		expect(result.category).toBe('dnssec_chain');

		const chainFinding = result.findings.find((f) => f.severity === 'info' && f.metadata?.zones);
		expect(chainFinding).toBeDefined();
		const zones = chainFinding!.metadata!.zones as Array<{ zone: string }>;
		const zoneNames = zones.map((z) => z.zone);
		expect(zoneNames).toContain('.');
		expect(zoneNames).toContain('com');
		expect(zoneNames).toContain('example.com');
		expect(zoneNames).toContain('sub.example.com');
	});
});
