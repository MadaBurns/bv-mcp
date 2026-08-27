// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it, vi } from 'vitest';
import { probeDelegationConsistency } from '../src/lib/authoritative-dns-infra/delegation-probe';
import type { DirectDnsResponse } from '../src/lib/authoritative-dns-infra/dns-tcp';
import { RecordType } from '../src/lib/dns-types';

function response(overrides: Partial<DirectDnsResponse>): DirectDnsResponse {
	return { aa: false, rcode: 0, answers: [], authority: [], additional: [], ...overrides };
}

describe('probeDelegationConsistency', () => {
	it('queries the parent referral and each delegated child directly with bounded fan-out', async () => {
		const recursiveQuery = vi.fn(async (name: string, type: string) => {
			if (name === 'com' && type === 'NS') return ['a.gtld-servers.net.', 'b.gtld-servers.net.'];
			if (name === 'ns1.example.com' && type === 'A') return ['192.0.2.53'];
			return [];
		});
		const directQuery = vi.fn(async (server: string) => {
			if (server.endsWith('gtld-servers.net')) {
				return response({
					authority: [
						{ name: 'example.com', type: RecordType.NS, data: 'ns1.example.com' },
						{ name: 'example.com', type: RecordType.NS, data: 'ns2.provider.net' },
					],
					additional: [{ name: 'ns1.example.com', type: RecordType.A, data: '192.0.2.53' }],
				});
			}
			return response({
				aa: true,
				answers: [
					{ name: 'example.com', type: RecordType.NS, data: 'ns1.example.com' },
					{ name: 'example.com', type: RecordType.NS, data: 'ns2.provider.net' },
				],
			});
		});

		const evidence = await probeDelegationConsistency('Example.COM.', {
			recursiveQuery,
			directQuery,
			now: () => new Date('2026-08-07T00:00:00.000Z'),
		});

		expect(evidence).toMatchObject({
			hostname: 'example.com',
			parentZone: 'com',
			parentNameservers: ['a.gtld-servers.net', 'b.gtld-servers.net'],
			parentDelegationNs: ['ns1.example.com', 'ns2.provider.net'],
			checkedAt: '2026-08-07T00:00:00.000Z',
		});
		expect(evidence.childObservations).toHaveLength(2);
		expect(evidence.glue).toEqual([
			expect.objectContaining({ nameserver: 'ns1.example.com', parentIpv4: ['192.0.2.53'], currentIpv4: ['192.0.2.53'] }),
		]);
		expect(directQuery).toHaveBeenCalledTimes(4); // two parent + two child
	});

	it('keeps direct-query failures as inconclusive evidence', async () => {
		const evidence = await probeDelegationConsistency('example.com', {
			recursiveQuery: async (name, type) => (name === 'com' && type === 'NS' ? ['a.gtld-servers.net'] : []),
			directQuery: async () => { throw new Error('socket blocked'); },
		});
		expect(evidence.parentObservations[0]).toMatchObject({ nameserver: 'a.gtld-servers.net', error: 'parent_query_failed' });
		expect(evidence.parentDelegationNs).toEqual([]);
		expect(evidence.childObservations).toEqual([]);
	});

	it('does not expose recursive resolver exception details in evidence', async () => {
		const evidence = await probeDelegationConsistency('example.com', {
			recursiveQuery: async () => { throw new Error('secret resolver endpoint and stack'); },
		});
		expect(evidence.errors).toEqual(['parent_ns_lookup_failed', 'parent_nameservers_unavailable']);
		expect(JSON.stringify(evidence)).not.toContain('secret resolver endpoint and stack');
	});

	it('does not expose child nameserver exception details in evidence', async () => {
		const evidence = await probeDelegationConsistency('example.com', {
			recursiveQuery: async (name, type) => (name === 'com' && type === 'NS' ? ['a.gtld-servers.net'] : []),
			directQuery: async (server) => {
				if (server === 'a.gtld-servers.net') {
					return response({ authority: [{ name: 'example.com', type: RecordType.NS, data: 'ns1.example.com' }] });
				}
				throw new Error('secret child transport endpoint and stack');
			},
		});
		expect(evidence.childObservations).toEqual([{ nameserver: 'ns1.example.com', error: 'child_query_failed' }]);
		expect(JSON.stringify(evidence)).not.toContain('secret child transport endpoint and stack');
	});
});
