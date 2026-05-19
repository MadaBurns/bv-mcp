// SPDX-License-Identifier: BUSL-1.1

/**
 * Contract: every brand-discovery detector returns a result that conforms to
 * the shared {@link DiscoverySignalResultSchema}.
 *
 * Add a new detector?
 *   1. Wire it through `src/tenants/discovery/index.ts`
 *   2. Add a `representative<Name>Result()` fixture below
 *   3. Add it to the table-driven test — CI fails until it parses cleanly
 *
 * Per testing-methodology.md principle 3: Zod schemas ARE the inter-service
 * contract. This test catches drift between any detector's output shape and
 * the consumers downstream (corroboration gate, candidate-universe builder,
 * report renderers).
 */

import { describe, it, expect } from 'vitest';
import {
	DiscoverySignalResultSchema,
	StrictDiscoverySignalResultSchema,
	CoOwnedCandidateSchema,
	QueryStatusSchema,
} from '../../src/schemas/discovery-signal-result';
import type { NsCorrelationResult } from '../../src/tenants/discovery/ns-correlator';
import type { SanCorrelationResult } from '../../src/tenants/discovery/san-correlator';
import type { DkimKeyReuseResult } from '../../src/tenants/discovery/dkim-key-reuse';
import type { SpfIncludeResult } from '../../src/tenants/discovery/spf-include-detector';
import type { MxOverlapResult } from '../../src/tenants/discovery/mx-overlap-detector';
import type { TxtVerificationResult } from '../../src/tenants/discovery/txt-verification-detector';
import type { CnameAlignmentResult } from '../../src/tenants/discovery/cname-alignment-detector';
import type { BountyScopeResult } from '../../src/tenants/discovery/bounty-scope-detector';

/** Representative outputs constructed from each detector's exported Result type. */
function representativeNsResult(): NsCorrelationResult {
	return {
		seedDomain: 'example.com',
		seedNs: ['ns1.example.net', 'ns2.example.net'],
		coOwnedDomains: [
			{ domain: 'example.org', sharedNs: ['ns1.example.net'], confidence: 0.5 },
		],
		queryStatus: 'ok',
	};
}

function representativeSanResult(): SanCorrelationResult {
	return {
		seedDomain: 'example.com',
		coOwnedDomains: ['sibling.example.net', 'sibling.example.org'],
		certIds: [123456, 789012],
		queryStatus: 'ok',
	};
}

function representativeDkimResult(): DkimKeyReuseResult {
	return {
		seedDomain: 'example.com',
		seedSelectors: ['google', 'selector1'],
		coOwnedDomains: [
			{
				domain: 'example.net',
				sharedKeys: ['a1b2c3d4e5f60718'],
				sharedSelectors: ['google'],
				confidence: 0.95,
			},
		],
		queryStatus: 'ok',
	};
}

function representativeSpfResult(): SpfIncludeResult {
	return {
		coOwnedDomains: [
			{ domain: 'example.net', confidence: 0.7, evidence: { include: '_spf.example.com' } },
		],
		queryStatus: 'ok',
	};
}

function representativeMxResult(): MxOverlapResult {
	return {
		coOwnedDomains: [
			{
				domain: 'example.net',
				confidence: 0.8,
				evidence: { matched: ['mail.example.com'], sharedSaas: false },
			},
		],
		queryStatus: 'ok',
	};
}

function representativeTxtResult(): TxtVerificationResult {
	return {
		seedDomain: 'example.com',
		coOwnedDomains: [
			{
				domain: 'example.org',
				sharedTxtVerifications: ['google-site-verification=abc123'],
				confidence: 1.0,
			},
		],
		queryStatus: 'ok',
	};
}

function representativeCnameResult(): CnameAlignmentResult {
	return {
		coOwnedDomains: [
			{
				domain: 'www.example.org',
				confidence: 0.9,
				evidence: { chain: ['www.example.org', 'edge.example.com'], matchType: 'seed-rooted' as const },
			},
		],
		queryStatus: 'ok',
	};
}

function representativeBountyResult(): BountyScopeResult {
	return {
		seedDomain: 'example.com',
		coOwnedDomains: [
			{
				domain: 'app.example.com',
				confidence: 1,
				evidence: { platform: 'hackerone', programHandle: 'example', assetType: 'url' },
			},
		],
		queryStatus: 'ok',
		wildcardScopes: ['example.com'],
		outOfScopeDomains: [],
		fetchedPlatforms: ['hackerone'],
		failedPlatforms: [],
	};
}

interface DetectorCase {
	name: string;
	build: () => unknown;
}

const DETECTOR_CASES: readonly DetectorCase[] = [
	{ name: 'ns-correlator', build: representativeNsResult },
	{ name: 'san-correlator', build: representativeSanResult },
	{ name: 'dkim-key-reuse', build: representativeDkimResult },
	{ name: 'spf-include-detector', build: representativeSpfResult },
	{ name: 'mx-overlap-detector', build: representativeMxResult },
	{ name: 'txt-verification-detector', build: representativeTxtResult },
	{ name: 'cname-alignment-detector', build: representativeCnameResult },
	{ name: 'bounty-scope-detector', build: representativeBountyResult },
];

describe('discovery-signals contract', () => {
	describe('queryStatus enum coverage', () => {
		it('accepts every canonical value', () => {
			for (const v of ['ok', 'partial', 'failed'] as const) {
				expect(QueryStatusSchema.safeParse(v).success).toBe(true);
			}
		});

		it('accepts legacy values pending convergence', () => {
			for (const v of ['error', 'rate_limited', 'timeout', 'no_spf', 'budget_exceeded'] as const) {
				expect(QueryStatusSchema.safeParse(v).success).toBe(true);
			}
		});

		it('rejects unknown values', () => {
			expect(QueryStatusSchema.safeParse('unknown').success).toBe(false);
			expect(QueryStatusSchema.safeParse('').success).toBe(false);
		});
	});

	describe('CoOwnedCandidateSchema', () => {
		it('accepts a bare-string candidate (legacy SAN-style)', () => {
			expect(CoOwnedCandidateSchema.safeParse('example.com').success).toBe(true);
		});

		it('accepts an object candidate with confidence + evidence', () => {
			const result = CoOwnedCandidateSchema.safeParse({
				domain: 'example.com',
				confidence: 0.8,
				evidence: { reason: 'matched' },
			});
			expect(result.success).toBe(true);
		});

		it('rejects an empty domain string', () => {
			expect(CoOwnedCandidateSchema.safeParse('').success).toBe(false);
			expect(CoOwnedCandidateSchema.safeParse({ domain: '' }).success).toBe(false);
		});

		it('rejects confidence outside 0..1', () => {
			expect(CoOwnedCandidateSchema.safeParse({ domain: 'a.b', confidence: 1.5 }).success).toBe(false);
			expect(CoOwnedCandidateSchema.safeParse({ domain: 'a.b', confidence: -0.1 }).success).toBe(false);
		});
	});

	describe('DiscoverySignalResultSchema — each detector', () => {
		for (const { name, build } of DETECTOR_CASES) {
			it(`${name} representative output conforms`, () => {
				const parsed = DiscoverySignalResultSchema.safeParse(build());
				if (!parsed.success) {
					throw new Error(`${name} failed schema: ${JSON.stringify(parsed.error.issues)}`);
				}
				expect(parsed.success).toBe(true);
			});
		}

		it('rejects a result missing coOwnedDomains', () => {
			const bad = { seedDomain: 'example.com', queryStatus: 'ok' };
			expect(DiscoverySignalResultSchema.safeParse(bad).success).toBe(false);
		});

		it('rejects a result missing queryStatus', () => {
			const bad = { seedDomain: 'example.com', coOwnedDomains: [] };
			expect(DiscoverySignalResultSchema.safeParse(bad).success).toBe(false);
		});

		it('rejects coOwnedDomains containing an invalid element', () => {
			const bad = {
				seedDomain: 'example.com',
				coOwnedDomains: [{ domain: 'ok.com' }, { confidence: 0.5 }],
				queryStatus: 'ok',
			};
			expect(DiscoverySignalResultSchema.safeParse(bad).success).toBe(false);
		});

		it('preserves extra fields via passthrough', () => {
			const result = DiscoverySignalResultSchema.safeParse({
				seedDomain: 'example.com',
				coOwnedDomains: [{ domain: 'a.b' }],
				queryStatus: 'ok',
				detectorVersion: 'v2',
			});
			expect(result.success).toBe(true);
			if (result.success) {
				expect((result.data as Record<string, unknown>).detectorVersion).toBe('v2');
			}
		});
	});

	describe('StrictDiscoverySignalResultSchema (gate for new detectors)', () => {
		it('rejects bare-string candidates', () => {
			const bad = {
				seedDomain: 'example.com',
				coOwnedDomains: ['example.net'],
				queryStatus: 'ok',
			};
			expect(StrictDiscoverySignalResultSchema.safeParse(bad).success).toBe(false);
		});

		it('rejects legacy queryStatus values', () => {
			const bad = {
				seedDomain: 'example.com',
				coOwnedDomains: [{ domain: 'a.b', confidence: 0.5 }],
				queryStatus: 'rate_limited',
			};
			expect(StrictDiscoverySignalResultSchema.safeParse(bad).success).toBe(false);
		});

		it('requires seedDomain', () => {
			const bad = {
				coOwnedDomains: [{ domain: 'a.b', confidence: 0.5 }],
				queryStatus: 'ok',
			};
			expect(StrictDiscoverySignalResultSchema.safeParse(bad).success).toBe(false);
		});

		it('accepts a fully-canonical new-detector output', () => {
			const good = {
				seedDomain: 'example.com',
				coOwnedDomains: [
					{ domain: 'sib.example.net', confidence: 0.9, evidence: { source: 'bounty-scope' } },
				],
				queryStatus: 'ok',
			};
			expect(StrictDiscoverySignalResultSchema.safeParse(good).success).toBe(true);
		});
	});
});
