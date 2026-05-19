// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the Tier 1 `bv-infrastructure-graph` service-binding wrapper.
 *
 * Pyramid layer: Unit. We pass a stub Fetcher object; no real Workers binding
 * involved. Integration coverage of the live binding lives in
 * `test/brand-tier1-graph.integration.test.ts` (skipped placeholders until
 * the cross-worker contract is deployed).
 *
 * Privacy invariant: tests never assert on raw domain values inside log
 * output — they only assert on returned observation shapes.
 */

import { describe, it, expect, vi } from 'vitest';
import { computeTier1Confidence, tier1GraphLookup } from '../src/lib/brand-tier1-graph';

interface MockEnv {
	BV_WEB_INTERNAL_KEY?: string;
}

function mockBindingReturning(payload: unknown, status = 200): Fetcher {
	return {
		fetch: vi.fn(async () =>
			new Response(JSON.stringify(payload), {
				status,
				headers: { 'Content-Type': 'application/json' },
			}),
		),
	} as unknown as Fetcher;
}

function mockBindingThrowing(err: Error): Fetcher {
	return {
		fetch: vi.fn(async () => {
			throw err;
		}),
	} as unknown as Fetcher;
}

const baseEnv: MockEnv = { BV_WEB_INTERNAL_KEY: 'test-internal-key' };

const baseResponse = {
	domain: 'example.com',
	totalRelated: 0,
	clusters: [],
	sharedSignals: [],
	freshness: { perSignalType: {}, overallStaleness: 'fresh' as const },
};

describe('computeTier1Confidence', () => {
	it('applies the three-term formula', () => {
		// 0.15*1 + 0.50*0.9 + 0.10*0 = 0.15 + 0.45 + 0 = 0.60
		expect(
			computeTier1Confidence({ numSharedSignals: 1, maxSpecificity: 0.9, signalTypeWeightBonus: 0 }),
		).toBeCloseTo(0.6, 2);
		// 0.15*3 + 0.50*0.7 + 0.10*0.3 = 0.45 + 0.35 + 0.03 = 0.83
		expect(
			computeTier1Confidence({ numSharedSignals: 3, maxSpecificity: 0.7, signalTypeWeightBonus: 0.3 }),
		).toBeCloseTo(0.83, 2);
	});

	it('clamps to [0, 1]', () => {
		expect(
			computeTier1Confidence({ numSharedSignals: 100, maxSpecificity: 1, signalTypeWeightBonus: 0 }),
		).toBe(1);
		expect(
			computeTier1Confidence({ numSharedSignals: 0, maxSpecificity: 0, signalTypeWeightBonus: -0.5 }),
		).toBe(0);
	});

	it('returns 0 when no signals contribute (defensive)', () => {
		expect(
			computeTier1Confidence({ numSharedSignals: 0, maxSpecificity: 0, signalTypeWeightBonus: 0 }),
		).toBe(0);
	});
});

describe('tier1GraphLookup', () => {
	describe('happy path', () => {
		it('emits one Tier 1 observation per candidate with three-term confidence formula', async () => {
			const mockResponse = {
				domain: 'example.com',
				totalRelated: 3,
				clusters: [],
				sharedSignals: [
					{
						signalType: 'cert_fingerprint',
						signalValue: 'sha256:abc',
						specificityScore: 0.9,
						coOccurringDomains: ['shop.example.net', 'pay.example.net'],
					},
					{
						signalType: 'mx',
						signalValue: 'mx.gmail.com',
						specificityScore: 0.05,
						coOccurringDomains: ['login.example.net'],
					},
				],
				freshness: { perSignalType: {}, overallStaleness: 'fresh' as const },
			};

			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning(mockResponse),
				baseEnv,
			);

			expect(result.status).toBe('ok');
			expect(result.triggerTier3Fallback).toBe(false);
			// 3 distinct candidates → 3 observations (one per candidate).
			expect(result.observations).toHaveLength(3);

			const shop = result.observations.find((o) => o.candidate === 'shop.example.net');
			// 1 signal (cert_fingerprint), max specificity 0.9, bonus 0 (deferred):
			// 0.15*1 + 0.50*0.9 + 0.10*0 = 0.60
			expect(shop).toMatchObject({
				tier: 1,
				source: 'infra_graph_signal',
				specificityScore: 0.9,
				signalType: 'cert_fingerprint',
				signalValue: 'sha256:abc',
				numSharedSignals: 1,
				maxSpecificity: 0.9,
			});
			expect(shop?.confidence).toBeCloseTo(0.6, 2);
			expect(shop?.signalTypes).toEqual(['cert_fingerprint']);

			const login = result.observations.find((o) => o.candidate === 'login.example.net');
			// 1 signal (mx), max specificity 0.05, bonus 0:
			// 0.15*1 + 0.50*0.05 + 0 = 0.175
			expect(login?.confidence).toBeCloseTo(0.175, 3);
			expect(login?.signalType).toBe('mx');
		});

		it('aggregates multiple shared signals per candidate into one observation', async () => {
			const mockResponse = {
				...baseResponse,
				totalRelated: 1,
				sharedSignals: [
					{
						signalType: 'cert_fingerprint',
						signalValue: 'sha256:abc',
						specificityScore: 0.9,
						coOccurringDomains: ['shop.example.net'],
					},
					{
						signalType: 'soa_admin',
						signalValue: 'admin@example.com',
						specificityScore: 0.7,
						coOccurringDomains: ['shop.example.net'],
					},
				],
			};

			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning(mockResponse),
				baseEnv,
			);

			const shop = result.observations.filter((o) => o.candidate === 'shop.example.net');
			// ONE aggregated observation, not two.
			expect(shop).toHaveLength(1);
			// 2 signals, max specificity 0.9, bonus 0:
			// 0.15*2 + 0.50*0.9 + 0 = 0.75
			expect(shop[0].confidence).toBeCloseTo(0.75, 2);
			expect(shop[0].numSharedSignals).toBe(2);
			expect(shop[0].maxSpecificity).toBe(0.9);
			// Highest-specificity signal wins for the singular fields.
			expect(shop[0].signalType).toBe('cert_fingerprint');
			expect(shop[0].signalValue).toBe('sha256:abc');
			// Both contributing signal types listed.
			expect(shop[0].signalTypes).toEqual(expect.arrayContaining(['cert_fingerprint', 'soa_admin']));
			expect(shop[0].signalTypes).toHaveLength(2);
		});

		it('emits ALL co-occurring candidates, including low-specificity (no consumer-side filter)', async () => {
			// Producer-side bug compensation is explicitly NOT this wrapper's job.
			// Even tiny specificityScore entries (e.g. gmail-shared MX) must surface
			// so downstream gating (T6) sees the full data.
			const mockResponse = {
				...baseResponse,
				sharedSignals: [
					{
						signalType: 'mx',
						signalValue: 'mx.gmail.com',
						specificityScore: 0.001,
						coOccurringDomains: ['random.example.net'],
					},
				],
			};

			const result = await tier1GraphLookup('seed.example', mockBindingReturning(mockResponse), baseEnv);
			expect(result.observations).toHaveLength(1);
			expect(result.observations[0].candidate).toBe('random.example.net');
		});

		it('returns an empty observation set on empty sharedSignals', async () => {
			const result = await tier1GraphLookup(
				'isolated.example',
				mockBindingReturning(baseResponse),
				baseEnv,
			);
			expect(result.status).toBe('ok');
			expect(result.observations).toEqual([]);
		});

		it('carries the freshness field through to the caller', async () => {
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning(baseResponse),
				baseEnv,
			);
			expect(result.freshness?.overallStaleness).toBe('fresh');
		});

		it('forwards Authorization bearer + X-Contract-Version header to the binding', async () => {
			const fetchSpy = vi.fn(async () =>
				new Response(JSON.stringify(baseResponse), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				}),
			);
			const binding: Fetcher = { fetch: fetchSpy } as unknown as Fetcher;

			await tier1GraphLookup('example.com', binding, baseEnv);

			expect(fetchSpy).toHaveBeenCalledTimes(1);
			const callArg = fetchSpy.mock.calls[0]?.[0] as Request;
			expect(callArg.headers.get('Authorization')).toBe('Bearer test-internal-key');
			expect(callArg.headers.get('X-Contract-Version')).toBe('1');
			// URL-encodes the domain segment
			expect(callArg.url).toContain('/domain/example.com/related');
		});

		it('URL-encodes the domain path segment to avoid binding-side path injection', async () => {
			const fetchSpy = vi.fn(async () =>
				new Response(JSON.stringify(baseResponse), { status: 200 }),
			);
			const binding: Fetcher = { fetch: fetchSpy } as unknown as Fetcher;

			await tier1GraphLookup('foo bar.example/x', binding, baseEnv);

			const callArg = fetchSpy.mock.calls[0]?.[0] as Request;
			expect(callArg.url).toContain('/domain/foo%20bar.example%2Fx/related');
		});
	});

	describe('specificity input boundary handling', () => {
		it('applies three-term formula to a single-signal candidate', async () => {
			const inRange = {
				...baseResponse,
				sharedSignals: [
					{
						signalType: 'ns',
						signalValue: 'ns1.example',
						specificityScore: 0.42,
						coOccurringDomains: ['sib.example.net'],
					},
				],
			};
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning(inRange),
				baseEnv,
			);
			// 1 signal, max specificity 0.42, bonus 0:
			// 0.15*1 + 0.50*0.42 + 0 = 0.36
			expect(result.observations[0].confidence).toBeCloseTo(0.36, 2);
			expect(result.observations[0].specificityScore).toBe(0.42);
			expect(result.observations[0].maxSpecificity).toBe(0.42);
		});

		it('propagates 0 and 1 specificity inputs correctly through the formula', async () => {
			const inRange = {
				...baseResponse,
				sharedSignals: [
					{
						signalType: 'ns',
						signalValue: 'ns1.example',
						specificityScore: 0,
						coOccurringDomains: ['a.example.net'],
					},
					{
						signalType: 'ns',
						signalValue: 'ns2.example',
						specificityScore: 1,
						coOccurringDomains: ['b.example.net'],
					},
				],
			};
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning(inRange),
				baseEnv,
			);
			expect(result.status).toBe('ok');
			// a: 1 signal, max 0 → 0.15*1 + 0.50*0 = 0.15
			// b: 1 signal, max 1 → 0.15*1 + 0.50*1 = 0.65
			const a = result.observations.find((o) => o.candidate === 'a.example.net');
			const b = result.observations.find((o) => o.candidate === 'b.example.net');
			expect(a?.confidence).toBeCloseTo(0.15, 2);
			expect(b?.confidence).toBeCloseTo(0.65, 2);
		});

		it('degrades when producer emits specificityScore > 1 (schema-level guard)', async () => {
			// Contract is min(0).max(1); a drifted producer emitting 1.7 means
			// schema validation fails and the wrapper falls back to degraded
			// rather than silently surfacing out-of-contract data.
			const drifted = {
				...baseResponse,
				sharedSignals: [
					{
						signalType: 'ns',
						signalValue: 'ns1.example',
						specificityScore: 1.7,
						coOccurringDomains: ['sib.example.net'],
					},
				],
			};
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning(drifted),
				baseEnv,
			);
			expect(result.status).toBe('degraded');
		});

		it('degrades when producer emits specificityScore < 0', async () => {
			const drifted = {
				...baseResponse,
				sharedSignals: [
					{
						signalType: 'ns',
						signalValue: 'ns1.example',
						specificityScore: -0.5,
						coOccurringDomains: ['sib.example.net'],
					},
				],
			};
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning(drifted),
				baseEnv,
			);
			expect(result.status).toBe('degraded');
		});
	});

	describe('freshness fallback', () => {
		it('returns triggerTier3Fallback=true when freshness=very_stale', async () => {
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning({
					...baseResponse,
					freshness: { perSignalType: {}, overallStaleness: 'very_stale' as const },
				}),
				baseEnv,
			);
			expect(result.triggerTier3Fallback).toBe(true);
		});

		it('does NOT trigger fallback for stale (7d-30d)', async () => {
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning({
					...baseResponse,
					freshness: { perSignalType: {}, overallStaleness: 'stale' as const },
				}),
				baseEnv,
			);
			expect(result.triggerTier3Fallback).toBe(false);
		});
	});

	describe('error handling', () => {
		it('returns degraded status (with fallback trigger) when binding throws', async () => {
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingThrowing(new Error('binding unreachable')),
				baseEnv,
			);
			expect(result.status).toBe('degraded');
			expect(result.observations).toEqual([]);
			expect(result.triggerTier3Fallback).toBe(true);
		});

		it('returns degraded on non-2xx HTTP status', async () => {
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning({ error: 'internal_key_invalid' }, 401),
				baseEnv,
			);
			expect(result.status).toBe('degraded');
			expect(result.observations).toEqual([]);
			expect(result.triggerTier3Fallback).toBe(true);
		});

		it('returns degraded on malformed JSON', async () => {
			const malformed: Fetcher = {
				fetch: vi.fn(async () =>
					new Response('not-json-at-all', { status: 200 }),
				),
			} as unknown as Fetcher;

			const result = await tier1GraphLookup('example.com', malformed, baseEnv);
			expect(result.status).toBe('degraded');
			expect(result.triggerTier3Fallback).toBe(true);
		});

		it('returns degraded on schema-mismatched payload', async () => {
			const result = await tier1GraphLookup(
				'example.com',
				mockBindingReturning({ unexpected: 'shape' }),
				baseEnv,
			);
			expect(result.status).toBe('degraded');
			expect(result.observations).toEqual([]);
			expect(result.triggerTier3Fallback).toBe(true);
		});

		it('returns degraded with empty observations when BV_WEB_INTERNAL_KEY is missing', async () => {
			// Hard requirement: never construct an Authorization header without
			// the env var. The wrapper must short-circuit before touching the
			// binding (preventing any unauth'd call from reaching the producer).
			const noopBinding: Fetcher = {
				fetch: vi.fn(async () => new Response('{}', { status: 200 })),
			} as unknown as Fetcher;

			const result = await tier1GraphLookup('example.com', noopBinding, {});

			expect(result.status).toBe('degraded');
			expect(result.observations).toEqual([]);
			expect(result.triggerTier3Fallback).toBe(true);
			expect((noopBinding.fetch as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
		});

		it('does not throw on any error path', async () => {
			// Defensive: belt-and-braces. Any throw here is a regression.
			await expect(
				tier1GraphLookup(
					'example.com',
					mockBindingThrowing(new Error('boom')),
					baseEnv,
				),
			).resolves.toBeDefined();
		});
	});
});
