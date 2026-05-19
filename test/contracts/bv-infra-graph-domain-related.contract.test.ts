// SPDX-License-Identifier: BUSL-1.1

/**
 * Contract: bv-infrastructure-graph `GET /domain/:domain/related` payload
 * conforms to {@link DomainRelatedResponseSchema}.
 *
 * Producer-side schema lives in bv-web under proprietary license. This file
 * holds the bv-mcp consumer copy under BSL-1.1 and is the drift-detector
 * for the cross-worker contract surface defined in
 * docs/superpowers/plans/2026-05-20-brand-discovery-cross-worker-contract.md § 1.1.
 *
 * The fixture below is hand-written (PII-free) — when a real
 * test/fixtures/cross-worker/* capture exists it can be substituted directly.
 */

import { describe, it, expect } from 'vitest';
import {
	DomainRelatedResponseSchema,
	FreshnessSchema,
	SharedSignalSchema,
} from '../../src/schemas/cross-worker-domain-related';

function representativeProducerPayload() {
	return {
		domain: 'example.com',
		totalRelated: 3,
		clusters: [
			{
				id: 'cluster-1',
				name: 'example-corp',
				type: 'organization',
				riskLevel: 'low',
				domainCount: 12,
				matchScore: 0.82,
			},
		],
		sharedSignals: [
			{
				signalType: 'cert_fingerprint',
				signalValue: 'sha256:abc...',
				specificityScore: 0.92,
				coOccurringDomains: ['shop.example.net', 'pay.example.net'],
			},
			{
				signalType: 'mx',
				signalValue: 'mx.gmail.com',
				specificityScore: 0.05,
				coOccurringDomains: ['login.example.net'],
			},
		],
		freshness: {
			perSignalType: {
				cert_fingerprint: { capturedAt: 1_700_000_000_000, ageHours: 4 },
				mx: { capturedAt: 1_699_000_000_000, ageHours: 100 },
			},
			overallStaleness: 'partial' as const,
		},
	};
}

describe('bv-infra-graph /domain/:domain/related contract', () => {
	describe('representative producer payloads', () => {
		it('accepts a fully-populated response', () => {
			const result = DomainRelatedResponseSchema.safeParse(representativeProducerPayload());
			if (!result.success) {
				throw new Error(`producer payload failed schema: ${JSON.stringify(result.error.issues)}`);
			}
			expect(result.success).toBe(true);
		});

		it('accepts an empty sharedSignals + empty clusters response (no co-occurrences)', () => {
			const empty = {
				domain: 'isolated.example',
				totalRelated: 0,
				clusters: [],
				sharedSignals: [],
				freshness: { perSignalType: {}, overallStaleness: 'fresh' as const },
			};
			expect(DomainRelatedResponseSchema.safeParse(empty).success).toBe(true);
		});

		it('preserves unknown producer-added fields via passthrough', () => {
			const payload = representativeProducerPayload() as Record<string, unknown>;
			payload.redactedOptOuts = 2;
			const result = DomainRelatedResponseSchema.safeParse(payload);
			expect(result.success).toBe(true);
			if (result.success) {
				expect((result.data as Record<string, unknown>).redactedOptOuts).toBe(2);
			}
		});

		it('accepts a producer-added novel signalType (open string contract)', () => {
			const payload = representativeProducerPayload();
			payload.sharedSignals.push({
				signalType: 'webhook_target_host', // hypothetical future signal
				signalValue: 'hooks.example.com',
				specificityScore: 0.5,
				coOccurringDomains: ['hooks.example.net'],
			});
			expect(DomainRelatedResponseSchema.safeParse(payload).success).toBe(true);
		});
	});

	describe('consumer rejects invalid shapes', () => {
		it('rejects missing freshness', () => {
			const bad = representativeProducerPayload() as Record<string, unknown>;
			delete bad.freshness;
			expect(DomainRelatedResponseSchema.safeParse(bad).success).toBe(false);
		});

		it('rejects missing sharedSignals', () => {
			const bad = representativeProducerPayload() as Record<string, unknown>;
			delete bad.sharedSignals;
			expect(DomainRelatedResponseSchema.safeParse(bad).success).toBe(false);
		});

		it('rejects specificityScore outside 0..1', () => {
			const bad = {
				signalType: 'mx',
				signalValue: 'x',
				specificityScore: 1.5,
				coOccurringDomains: [],
			};
			expect(SharedSignalSchema.safeParse(bad).success).toBe(false);

			const bad2 = { ...bad, specificityScore: -0.1 };
			expect(SharedSignalSchema.safeParse(bad2).success).toBe(false);
		});

		it('rejects coOccurringDomains containing non-strings', () => {
			const bad = {
				signalType: 'mx',
				signalValue: 'x',
				specificityScore: 0.5,
				coOccurringDomains: ['ok.com', 42],
			};
			expect(SharedSignalSchema.safeParse(bad).success).toBe(false);
		});

		it('rejects unknown overallStaleness values', () => {
			const bad = { perSignalType: {}, overallStaleness: 'unknown' };
			expect(FreshnessSchema.safeParse(bad).success).toBe(false);
		});

		it('rejects a perSignalType entry missing capturedAt', () => {
			const bad = {
				perSignalType: { mx: { ageHours: 5 } },
				overallStaleness: 'fresh',
			};
			expect(FreshnessSchema.safeParse(bad).success).toBe(false);
		});
	});

	describe('freshness staleness enum', () => {
		it('accepts every defined value', () => {
			for (const v of ['fresh', 'partial', 'stale', 'very_stale'] as const) {
				const result = FreshnessSchema.safeParse({ perSignalType: {}, overallStaleness: v });
				expect(result.success).toBe(true);
			}
		});
	});
});
