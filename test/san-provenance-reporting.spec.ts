// SPDX-License-Identifier: BUSL-1.1
import { describe, expect, it, vi } from 'vitest';
import { makeTieredDeps, okSan } from './helpers/brand-discovery-tiered';
import { buildSanCertificateProvenance } from '../src/tenants/discovery/san-provenance';
import { correlateSansRecursive, type SanRecursiveOptions } from '../src/tenants/discovery/san-correlator';
import { discoverBrandDomains } from '../src/tools/discover-brand-domains';

const firstOrder = [
	buildSanCertificateProvenance({
		source: 'certspotter',
		tbsSha256: 'ab'.repeat(32),
		dnsNames: ['example.com', 'example.net'],
		candidateDomains: ['example.net'],
		responseComplete: true,
	}),
];

describe('SAN provenance report plumbing preserves discovery', () => {
	it('propagates first-order evidence into recursion and compact summaries into findings, preserving candidate confidence', async () => {
		const run = async (withProvenance: boolean) => {
			const recursive = vi.fn(async (_seed: string, _candidates: readonly string[], options: SanRecursiveOptions = {}) =>
				correlateSansRecursive('example.com', ['example.net'], {
					...options,
					fetchFn: vi.fn(async (input) =>
						String(input).includes('certspotter')
							? Response.json([{ id: '2', tbs_sha256: 'ab'.repeat(32), dns_names: ['example.com', 'example.net'] }])
							: Response.json([]),
					),
					maxRetries: 0,
				}),
			);
			const result = await discoverBrandDomains(
				'example.com',
				{ signals: ['san', 'san_recursive'], min_confidence: 0.1, discovery_mode: 'classic' },
				makeTieredDeps({
					correlateSans: vi
						.fn()
						.mockResolvedValue({
							...okSan(['example.net']),
							...(withProvenance ? { certificateProvenance: firstOrder, certificateProvenanceTruncated: false } : {}),
						}),
					correlateSansRecursive: recursive,
				}),
			);
			return { result, recursive };
		};
		const before = await run(false);
		const after = await run(true);
		const candidate = (result: typeof after.result) => result.findings.find((finding) => finding.metadata?.candidate === 'example.net');
		expect(candidate(before.result)).toBeDefined();
		expect(candidate(before.result)?.metadata?.combinedConfidence).toBeTypeOf('number');
		expect(after.result.score).toBe(before.result.score);
		expect(after.result.passed).toBe(before.result.passed);
		expect(candidate(after.result)?.metadata?.combinedConfidence).toEqual(candidate(before.result)?.metadata?.combinedConfidence);
		expect(candidate(after.result)?.severity).toEqual(candidate(before.result)?.severity);
		expect(after.result.findings.map((finding) => finding.title)).toEqual(before.result.findings.map((finding) => finding.title));
		expect(after.recursive.mock.calls[0][2].firstOrderCertificateProvenance).toBe(firstOrder);
		const serialized = JSON.stringify(after.result);
		const wireResult = JSON.parse(serialized) as typeof after.result;
		expect(serialized).not.toContain('ab'.repeat(32));
		expect(candidate(wireResult)?.metadata?.sources).toMatchObject({
			san: { certificateProvenanceSummary: { observedIssuanceCount: 1, registrableDomainCountRange: { min: 2, max: 2 } } },
			san_recursive: { provenanceComparison: { issuanceRelation: 'same_issuance_observed' } },
		});
		expect(candidate(before.result)?.metadata?.sources).toMatchObject({
			san_recursive: { provenanceComparison: { issuanceRelation: 'unknown' } },
		});
	});
});
