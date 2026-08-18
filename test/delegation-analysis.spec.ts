// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { analyzeDelegationConsistency } from '../src/lib/authoritative-dns-infra/delegation-analysis';
import type { DelegationConsistencyEvidence } from '../src/lib/authoritative-dns-infra/delegation-types';

function evidence(overrides: Partial<DelegationConsistencyEvidence> = {}): DelegationConsistencyEvidence {
	return {
		hostname: 'example.com',
		parentZone: 'com',
		checkedAt: '2026-08-07T00:00:00.000Z',
		parentNameservers: ['a.gtld-servers.net', 'b.gtld-servers.net'],
		parentDelegationNs: ['ns1.example.com', 'ns2.provider.net'],
		parentObservations: [
			{
				nameserver: 'a.gtld-servers.net',
				delegationNs: ['ns1.example.com', 'ns2.provider.net'],
				glueIpv4: { 'ns1.example.com': ['192.0.2.53'] },
				glueIpv6: {},
				rcode: 0,
			},
		],
		childObservations: [
			{ nameserver: 'ns1.example.com', aaFlag: true, publishedNs: ['ns1.example.com', 'ns2.provider.net'], rcode: 0 },
			{ nameserver: 'ns2.provider.net', aaFlag: true, publishedNs: ['ns1.example.com', 'ns2.provider.net'], rcode: 0 },
		],
		glue: [
			{
				nameserver: 'ns1.example.com',
				parentIpv4: ['192.0.2.53'],
				parentIpv6: [],
				currentIpv4: ['192.0.2.53'],
				currentIpv6: [],
			},
		],
		...overrides,
	};
}

describe('analyzeDelegationConsistency', () => {
	it('reports a healthy direct parent/child, AA, and glue check', () => {
		const result = analyzeDelegationConsistency(evidence());
		expect(result.conclusive).toBe(true);
		expect(result.failedChecks).toEqual([]);
		expect(result.findings).toContainEqual(
			expect.objectContaining({ title: 'Parent/child delegation and glue are consistent', severity: 'info' }),
		);
	});

	it('detects non-authoritative delegated servers and parent/child NS mismatch', () => {
		const result = analyzeDelegationConsistency(evidence({
			childObservations: [
				{ nameserver: 'ns1.example.com', aaFlag: false, publishedNs: [], rcode: 0 },
				{ nameserver: 'ns2.provider.net', aaFlag: true, publishedNs: ['ns2.provider.net'], rcode: 0 },
			],
		}));
		expect(result.failedChecks).toEqual(expect.arrayContaining(['authoritative_aa', 'parent_child_ns_match']));
		expect(result.findings).toEqual(expect.arrayContaining([
			expect.objectContaining({ title: 'Delegated nameserver is not authoritative', severity: 'high' }),
			expect.objectContaining({ title: 'Parent and child NS sets do not match', severity: 'high' }),
		]));
	});

	it('detects missing and stale in-bailiwick glue without treating probe errors as failures', () => {
		const result = analyzeDelegationConsistency(evidence({
			parentDelegationNs: ['ns1.example.com', 'ns2.example.com'],
			childObservations: [
				{ nameserver: 'ns1.example.com', aaFlag: true, publishedNs: ['ns1.example.com', 'ns2.example.com'], rcode: 0 },
				{ nameserver: 'ns2.example.com', error: 'timeout' },
			],
			glue: [
				{ nameserver: 'ns1.example.com', parentIpv4: ['192.0.2.10'], parentIpv6: [], currentIpv4: ['192.0.2.99'] },
				{ nameserver: 'ns2.example.com', parentIpv4: [], parentIpv6: [] },
			],
		}));
		expect(result.failedChecks).toEqual(expect.arrayContaining(['in_bailiwick_glue', 'glue_address_match']));
		expect(result.findings).toEqual(expect.arrayContaining([
			expect.objectContaining({ title: 'In-bailiwick nameserver glue is missing', severity: 'high' }),
			expect.objectContaining({ title: 'Parent glue addresses are stale', severity: 'medium' }),
		]));
		expect(result.findings.some((finding) => finding.detail.includes('timeout'))).toBe(false);
	});
});
