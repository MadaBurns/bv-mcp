// SPDX-License-Identifier: BUSL-1.1

import { afterEach, describe, expect, it, vi } from 'vitest';
import { RecordType } from '../src/lib/dns';
import type { DelegationConsistencyEvidence } from '../src/lib/authoritative-dns-infra/delegation-types';
import { createDohResponse, setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

function mockCoreNsDns() {
	globalThis.fetch = vi.fn(async (input: string | URL | Request) => {
		const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
		const name = (url.searchParams.get('name') ?? '').replace(/\.$/, '').toLowerCase();
		const type = url.searchParams.get('type');
		if (type === 'NS') {
			return createDohResponse(
				[{ name: 'example.com', type: RecordType.NS }],
				[
					{ name: 'example.com', type: RecordType.NS, TTL: 300, data: 'ns1.provider-a.com.' },
					{ name: 'example.com', type: RecordType.NS, TTL: 300, data: 'ns2.provider-b.net.' },
				],
			);
		}
		if (type === 'SOA') {
			return createDohResponse(
				[{ name: 'example.com', type: RecordType.SOA }],
				[{ name: 'example.com', type: RecordType.SOA, TTL: 300, data: 'ns1.provider-a.com. hostmaster.example.com. 1 3600 900 604800 300' }],
			);
		}
		if (type === 'A' && !name.startsWith('_bv-probe-')) {
			return createDohResponse(
				[{ name, type: RecordType.A }],
				[{ name, type: RecordType.A, TTL: 300, data: '192.0.2.53' }],
			);
		}
		return createDohResponse([{ name, type: type === 'AAAA' ? RecordType.AAAA : RecordType.A }], []);
	});
}

function delegationEvidence(): DelegationConsistencyEvidence {
	return {
		hostname: 'example.com',
		parentZone: 'com',
		checkedAt: '2026-08-07T00:00:00.000Z',
		parentNameservers: ['a.gtld-servers.net'],
		parentDelegationNs: ['ns1.provider-a.com', 'ns2.provider-b.net'],
		parentObservations: [
			{ nameserver: 'a.gtld-servers.net', delegationNs: ['ns1.provider-a.com', 'ns2.provider-b.net'], rcode: 0 },
		],
		childObservations: [
			{ nameserver: 'ns1.provider-a.com', aaFlag: true, publishedNs: ['ns1.provider-a.com', 'ns2.provider-b.net'], rcode: 0 },
			{ nameserver: 'ns2.provider-b.net', aaFlag: false, publishedNs: [], rcode: 0 },
		],
		glue: [],
	};
}

describe('checkNs delegation consistency enrichment', () => {
	it('adds direct authoritative-AA evidence and removes the contradictory healthy summary', async () => {
		mockCoreNsDns();
		const probeFetch = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
			new Response(JSON.stringify(delegationEvidence())));
		const { checkNs } = await import('../src/tools/check-ns');
		const result = await checkNs(
			'example.com',
			undefined,
			{
				scannedLabel: 'example.com',
				registrableDomain: 'example.com',
				isApex: true,
				zoneApex: 'example.com',
				apexNsRecords: [],
				delegationStatus: 'apex',
			},
			{ infraProbe: { fetch: probeFetch as unknown as typeof globalThis.fetch } },
		);

		expect(probeFetch).toHaveBeenCalledOnce();
		expect(probeFetch.mock.calls[0][0]).toBe('https://infra-probe.internal/probe/delegation-consistency');
		expect(result.findings).toContainEqual(
			expect.objectContaining({ title: 'Delegated nameserver is not authoritative', severity: 'high' }),
		);
		expect(result.findings.some((finding) => finding.title === 'Nameservers properly configured')).toBe(false);
		expect(result.score).toBe(75);
		expect(result.metadata).toMatchObject({
			delegationEvidenceMode: 'direct_dns_tcp',
			delegationFailedChecks: ['authoritative_aa'],
		});
	});

	it('keeps the core score unchanged when the optional probe fails', async () => {
		mockCoreNsDns();
		const probeFetch = vi.fn(async () => new Response('unavailable', { status: 503 }));
		const { checkNs } = await import('../src/tools/check-ns');
		const result = await checkNs(
			'example.com',
			undefined,
			{
				scannedLabel: 'example.com', registrableDomain: 'example.com', isApex: true,
				zoneApex: 'example.com', apexNsRecords: [], delegationStatus: 'apex',
			},
			{ infraProbe: { fetch: probeFetch as unknown as typeof globalThis.fetch } },
		);
		expect(result.score).toBe(100);
		expect(result.metadata?.delegationEvidenceMode).toBe('probe_unavailable');
	});

	// #828/#837 sibling — a malformed 200 body must degrade exactly like a probe outage,
	// leaving the core NS score untouched. Today this holds only because checkNs's try
	// happens to wrap the analysis too; the boundary guard below makes it structural.
	it('keeps the core score unchanged when the probe returns a malformed 200 body', async () => {
		mockCoreNsDns();
		const probeFetch = vi.fn(async () => new Response(JSON.stringify({ hostname: 'example.com', parentZone: 'com' })));
		const { checkNs } = await import('../src/tools/check-ns');
		const result = await checkNs(
			'example.com',
			undefined,
			{
				scannedLabel: 'example.com', registrableDomain: 'example.com', isApex: true,
				zoneApex: 'example.com', apexNsRecords: [], delegationStatus: 'apex',
			},
			{ infraProbe: { fetch: probeFetch as unknown as typeof globalThis.fetch } },
		);
		expect(result.score).toBe(100);
		expect(result.metadata?.delegationEvidenceMode).toBe('probe_unavailable');
	});
});

// #828/#837 sibling — `readJsonResponse<T>` is an unchecked generic cast, and
// `analyzeDelegationConsistency` dereferences the required evidence arrays (and each glue
// entry's parentIpv4/parentIpv6) unconditionally. Its only caller, checkNs, happens to
// wrap the fetch AND the analysis in one try — incidental safety that a narrowed
// try-scope would silently lose (exactly what had already happened to
// check-root-server-set.ts, #828). The shape is therefore validated at the
// fetchDelegationConsistencyEvidence boundary, mirroring PR #837's isUsableRootHintArray.
describe('fetchDelegationConsistencyEvidence shape guard (#828/#837 sibling)', () => {
	function probeReturning(body: unknown) {
		return { fetch: vi.fn(async () => new Response(JSON.stringify(body))) as unknown as typeof globalThis.fetch };
	}

	it('rejects a 200 body missing the required arrays', async () => {
		const { fetchDelegationConsistencyEvidence } = await import('../src/lib/authoritative-dns-infra/probe-client');
		await expect(
			fetchDelegationConsistencyEvidence('example.com', probeReturning({ hostname: 'example.com', parentZone: 'com' })),
		).rejects.toThrow(/^Invalid infra probe response/);
	});

	it('rejects observation entries that are not objects carrying a nameserver string', async () => {
		const { fetchDelegationConsistencyEvidence } = await import('../src/lib/authoritative-dns-infra/probe-client');
		await expect(
			fetchDelegationConsistencyEvidence(
				'example.com',
				probeReturning({ ...delegationEvidence(), childObservations: ['ns1.provider-a.com'] }),
			),
		).rejects.toThrow(/^Invalid infra probe response/);
	});

	it('rejects glue entries missing their required parentIpv4/parentIpv6 arrays', async () => {
		const { fetchDelegationConsistencyEvidence } = await import('../src/lib/authoritative-dns-infra/probe-client');
		await expect(
			fetchDelegationConsistencyEvidence(
				'example.com',
				probeReturning({ ...delegationEvidence(), glue: [{ nameserver: 'ns1.example.com' }] }),
			),
		).rejects.toThrow(/^Invalid infra probe response/);
	});

	// Unlike the root-server-set probe (whose domain fixes a non-empty 13-entry answer),
	// empty observation arrays here are legitimate measurements — e.g. `glue: []` simply
	// means no in-bailiwick nameservers were observed. The guard must not reject them.
	it('accepts a contract-valid body with empty observation arrays', async () => {
		const { fetchDelegationConsistencyEvidence } = await import('../src/lib/authoritative-dns-infra/probe-client');
		await expect(
			fetchDelegationConsistencyEvidence(
				'example.com',
				probeReturning({ ...delegationEvidence(), parentObservations: [], childObservations: [], glue: [] }),
			),
		).resolves.toMatchObject({ hostname: 'example.com', parentZone: 'com' });
	});

	it('accepts the full valid fixture', async () => {
		const { fetchDelegationConsistencyEvidence } = await import('../src/lib/authoritative-dns-infra/probe-client');
		await expect(
			fetchDelegationConsistencyEvidence('example.com', probeReturning(delegationEvidence())),
		).resolves.toMatchObject({ hostname: 'example.com', parentDelegationNs: ['ns1.provider-a.com', 'ns2.provider-b.net'] });
	});
});
