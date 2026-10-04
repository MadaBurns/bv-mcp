// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it } from 'vitest';
import { buildSanCertificateProvenance, MAX_SAN_PROVENANCE_OBSERVATIONS } from '../../../src/tenants/discovery/san-provenance';
import { compareSanCertificateProvenance, summarizeSanCandidateProvenance } from '../../../src/tenants/discovery/san-provenance-comparison';

function observation(candidate: string, hash = 'ab'.repeat(32)) {
	return buildSanCertificateProvenance({
		source: 'certspotter',
		tbsSha256: hash,
		dnsNames: ['example.com', 'example.net'],
		candidateDomains: [candidate],
		responseComplete: true,
	});
}
const compare = (firstOrder = [observation('example.net')], reciprocal = [observation('example.com')]) =>
	compareSanCertificateProvenance({ seed: 'example.com', candidate: 'example.net', firstOrder, reciprocal });

describe('observed SAN issuance reporting', () => {
	it('reports a shared issuance without claiming independence, including duplicate observations', () => {
		expect(compare([observation('example.net'), observation('example.net')])).toEqual({
			issuanceRelation: 'same_issuance_observed',
			firstOrder: { coverage: 'complete', observedIssuanceCount: 1, registrableDomainCountRange: { min: 2, max: 2 } },
			reciprocal: { coverage: 'complete', observedIssuanceCount: 1, registrableDomainCountRange: { min: 2, max: 2 } },
		});
	});
	it('reports distinct observed issuances even when another pair is shared; no fan-out threshold is applied', () => {
		const different = observation('example.com', 'cd'.repeat(32));
		different.registrableDomainCount = 136;
		const result = compare(undefined, [observation('example.com'), different]);
		expect(result.issuanceRelation).toBe('distinct_issuances_observed');
		expect(result.reciprocal.registrableDomainCountRange).toEqual({ min: 2, max: 136 });
	});
	it('withholds relation and exact summaries for absent, partial, malformed, or bounded-away mappings', () => {
		for (const firstOrder of [
			[],
			[{ ...observation('example.net'), coverage: 'unknown' as const }],
			[{ ...observation('example.net'), candidateMappingComplete: false }],
			[{ ...observation('example.net'), issuanceSha256: 'cursor-1' }],
			Array(MAX_SAN_PROVENANCE_OBSERVATIONS + 1).fill(observation('example.net')),
			[observation('other.example.net')],
		]) {
			expect(compare(firstOrder).issuanceRelation).toBe('unknown');
			expect(compare(firstOrder).firstOrder.observedIssuanceCount).toBeNull();
		}
		expect(
			compareSanCertificateProvenance({
				seed: 'example.com',
				candidate: 'example.net',
				firstOrder: [observation('example.net')],
				firstOrderTruncated: true,
				reciprocal: [observation('example.com')],
			}).issuanceRelation,
		).toBe('unknown');
		expect(summarizeSanCandidateProvenance('example.net', undefined)).toEqual({
			coverage: 'unknown',
			observedIssuanceCount: null,
			registrableDomainCountRange: null,
		});
	});
	it('does not treat unrelated incomplete observations as proof that the candidate mapping is exhaustive', () => {
		const unrelated = { ...observation('other.example.net'), coverage: 'unknown' as const };
		expect(compare([observation('example.net'), unrelated]).issuanceRelation).toBe('unknown');
	});
});
