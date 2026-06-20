// SPDX-License-Identifier: BUSL-1.1
//
// R10 PROPOSAL — ProfileAccumulator write-sharding by profile.
//
// Verifies the two correctness properties the maintainer must trust before
// flipping sharding on in production:
//   1. resolveAccumulatorShardName is a pure, deterministic profile→instance map
//      that is byte-identical to the legacy "global" routing in the default mode.
//   2. Routing writes by profile actually PARTITIONS state across DO instances
//      (a write to profile A's shard is invisible to profile B's shard), AND a
//      same-profile read still CONVERGES on the data that was written, because the
//      /weights read resolves the SAME shard name the /ingest write used.

import { describe, expect, it } from 'vitest';
import { env } from 'cloudflare:test';
import type { ScanTelemetry } from '../src/lib/adaptive-weights';

async function ingest(stub: DurableObjectStub, telemetry: ScanTelemetry): Promise<Response> {
	return stub.fetch('https://accumulator.internal/ingest', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify(telemetry),
	});
}

async function getWeights(stub: DurableObjectStub, profile: string, provider?: string): Promise<Response> {
	const url = new URL('https://accumulator.internal/weights');
	url.searchParams.set('profile', profile);
	if (provider) url.searchParams.set('provider', provider);
	return stub.fetch(url.toString(), { method: 'GET' });
}

/**
 * Minimal DurableObjectNamespace test double that records which instance NAME each
 * `idFromName(...)` resolved and forwards `.get(...).fetch(...)` to the real
 * PROFILE_ACCUMULATOR DO. Used to prove the intelligence read seams
 * (getBenchmark / getProviderInsights) resolve the SAME instance the ingest write
 * targeted — i.e. there is no split-brain between writes and the benchmark reads.
 */
function recordingNamespace(): { ns: DurableObjectNamespace; names: string[] } {
	const names: string[] = [];
	const real = env.PROFILE_ACCUMULATOR;
	const ns = {
		idFromName(name: string) {
			names.push(name);
			return real.idFromName(name);
		},
		get(id: DurableObjectId) {
			return real.get(id);
		},
	} as unknown as DurableObjectNamespace;
	return { ns, names };
}

describe('ProfileAccumulator sharding (R10 PROPOSAL)', () => {
	describe('resolveAccumulatorShardName', () => {
		it("defaults to the legacy 'global' instance (behavior-preserving)", async () => {
			const { resolveAccumulatorShardName, PROFILE_ACCUMULATOR_GLOBAL_NAME } = await import('../src/lib/profile-accumulator');
			// No mode arg, explicit undefined, and explicit 'global' all → legacy name.
			expect(resolveAccumulatorShardName('mail_enabled')).toBe(PROFILE_ACCUMULATOR_GLOBAL_NAME);
			expect(resolveAccumulatorShardName('non_mail', undefined)).toBe(PROFILE_ACCUMULATOR_GLOBAL_NAME);
			expect(resolveAccumulatorShardName('enterprise_mail', 'global')).toBe(PROFILE_ACCUMULATOR_GLOBAL_NAME);
		});

		it('maps each of the six profiles to a distinct, stable shard in profile mode', async () => {
			const { resolveAccumulatorShardName, PROFILE_SHARD_NAMES } = await import('../src/lib/profile-accumulator');
			const profiles = ['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal', 'authoritative_dns_infra'];

			const names = profiles.map((p) => resolveAccumulatorShardName(p, 'profile'));

			// Distinct: each profile gets its own shard (the whole point — 6 input gates).
			expect(new Set(names).size).toBe(profiles.length);
			// Stable: same input → same output, and equals the published shard-name set.
			for (const p of profiles) {
				expect(resolveAccumulatorShardName(p, 'profile')).toBe(resolveAccumulatorShardName(p, 'profile'));
			}
			expect(new Set(names)).toEqual(new Set(PROFILE_SHARD_NAMES));
			// Never collides with the legacy global instance.
			expect(names).not.toContain('global');
		});

		it('routes an unknown profile to the mail_enabled shard (matches the DO fallback)', async () => {
			const { resolveAccumulatorShardName } = await import('../src/lib/profile-accumulator');
			expect(resolveAccumulatorShardName('totally_unknown', 'profile')).toBe(resolveAccumulatorShardName('mail_enabled', 'profile'));
		});
	});

	describe('per-profile routing partitions writes and reads converge', () => {
		it('isolates write state across profile shards while same-profile reads still see it', async () => {
			const { resolveAccumulatorShardName } = await import('../src/lib/profile-accumulator');

			const profileA = 'mail_enabled';
			const profileB = 'non_mail';

			const shardA = resolveAccumulatorShardName(profileA, 'profile');
			const shardB = resolveAccumulatorShardName(profileB, 'profile');
			expect(shardA).not.toBe(shardB);

			const stubA = env.PROFILE_ACCUMULATOR.getByName(shardA);
			const stubB = env.PROFILE_ACCUMULATOR.getByName(shardB);

			// Write 3 scans for profile A only, to shard A.
			for (let i = 0; i < 3; i++) {
				const res = await ingest(stubA, {
					profile: profileA,
					provider: null,
					categoryFindings: [{ category: 'dmarc', score: 80, passed: true }],
					timestamp: Date.now(),
				});
				expect(res.status).toBe(204);
			}

			// CONVERGENCE: reading profile A from its OWN shard sees all 3 writes.
			const readA = await getWeights(stubA, profileA);
			expect(readA.status).toBe(200);
			const bodyA = (await readA.json()) as { sampleCount: number; weights: Record<string, number> };
			expect(bodyA.sampleCount).toBe(3);
			expect(bodyA.weights).toHaveProperty('dmarc');

			// PARTITION: shard B never received profile A's writes — empty, not cross-contaminated.
			const readB = await getWeights(stubB, profileB);
			expect(readB.status).toBe(200);
			const bodyB = (await readB.json()) as { sampleCount: number; weights: Record<string, number> };
			expect(bodyB.sampleCount).toBe(0);
			expect(bodyB.weights).toEqual({});
		});

		it('keeps the legacy global shard untouched when sharding is enabled (no double-count)', async () => {
			const { resolveAccumulatorShardName, PROFILE_ACCUMULATOR_GLOBAL_NAME } = await import('../src/lib/profile-accumulator');

			const profile = 'web_only';
			const globalStub = env.PROFILE_ACCUMULATOR.getByName(PROFILE_ACCUMULATOR_GLOBAL_NAME);

			// Baseline sample count for this profile on the global instance.
			const before = (await (await getWeights(globalStub, profile)).json()) as { sampleCount: number };

			// A sharded write goes ONLY to the per-profile shard, not 'global'.
			const shard = resolveAccumulatorShardName(profile, 'profile');
			expect(shard).not.toBe(PROFILE_ACCUMULATOR_GLOBAL_NAME);
			const shardStub = env.PROFILE_ACCUMULATOR.getByName(shard);
			await ingest(shardStub, {
				profile,
				provider: null,
				categoryFindings: [{ category: 'spf', score: 50, passed: false }],
				timestamp: Date.now(),
			});

			// Global instance's web_only stats are unchanged — the write did not leak in.
			const after = (await (await getWeights(globalStub, profile)).json()) as { sampleCount: number };
			expect(after.sampleCount).toBe(before.sampleCount);

			// And the shard itself converged on exactly the one write.
			const shardBody = (await (await getWeights(shardStub, profile)).json()) as {
				sampleCount: number;
				weights: Record<string, number>;
			};
			expect(shardBody.sampleCount).toBe(1);
			expect(shardBody.weights).toHaveProperty('spf');
		});
	});

	// ── Adam non-negotiable #1: dormant default-OFF must route EVERY seam to 'global' ──
	describe("default-off ('global'/undefined) routes ingest AND all read seams to 'global'", () => {
		it("resolveAccumulatorShardModeFromEnv defaults OFF unless the var is exactly 'profile'", async () => {
			const { resolveAccumulatorShardModeFromEnv } = await import('../src/lib/profile-accumulator');
			// Default-off: anything that isn't the exact opt-in string → 'global'.
			expect(resolveAccumulatorShardModeFromEnv(undefined)).toBe('global');
			expect(resolveAccumulatorShardModeFromEnv('')).toBe('global');
			expect(resolveAccumulatorShardModeFromEnv('global')).toBe('global');
			expect(resolveAccumulatorShardModeFromEnv('PROFILE')).toBe('global'); // case-sensitive
			expect(resolveAccumulatorShardModeFromEnv('true')).toBe('global');
			// Opt-in: only the exact literal flips it on.
			expect(resolveAccumulatorShardModeFromEnv('profile')).toBe('profile');
		});

		it("routes the ingest write to 'global' for every profile when mode is undefined/'global'", async () => {
			const { resolveAccumulatorShardName, PROFILE_ACCUMULATOR_GLOBAL_NAME } = await import('../src/lib/profile-accumulator');
			const profiles = ['mail_enabled', 'enterprise_mail', 'non_mail', 'web_only', 'minimal', 'authoritative_dns_infra'];
			for (const p of profiles) {
				expect(resolveAccumulatorShardName(p, undefined)).toBe(PROFILE_ACCUMULATOR_GLOBAL_NAME);
				expect(resolveAccumulatorShardName(p, 'global')).toBe(PROFILE_ACCUMULATOR_GLOBAL_NAME);
			}
		});

		it("getBenchmark reads the 'global' instance when shardMode is default/undefined/'global'", async () => {
			const { getBenchmark } = await import('../src/tools/intelligence');
			const { PROFILE_ACCUMULATOR_GLOBAL_NAME } = await import('../src/lib/profile-accumulator');
			// default arg
			{
				const { ns, names } = recordingNamespace();
				await getBenchmark(ns, 'non_mail');
				expect(names).toEqual([PROFILE_ACCUMULATOR_GLOBAL_NAME]);
			}
			// explicit 'global'
			{
				const { ns, names } = recordingNamespace();
				await getBenchmark(ns, 'authoritative_dns_infra', 'global');
				expect(names).toEqual([PROFILE_ACCUMULATOR_GLOBAL_NAME]);
			}
		});

		it("getProviderInsights reads the 'global' instance when shardMode is default/'global'", async () => {
			const { getProviderInsights } = await import('../src/tools/intelligence');
			const { PROFILE_ACCUMULATOR_GLOBAL_NAME } = await import('../src/lib/profile-accumulator');
			{
				const { ns, names } = recordingNamespace();
				await getProviderInsights(ns, 'google', 'mail_enabled');
				expect(names).toEqual([PROFILE_ACCUMULATOR_GLOBAL_NAME]);
			}
			{
				const { ns, names } = recordingNamespace();
				await getProviderInsights(ns, 'google', 'enterprise_mail', 'global');
				expect(names).toEqual([PROFILE_ACCUMULATOR_GLOBAL_NAME]);
			}
		});
	});

	// ── Adam non-negotiable #5 / Linus must-fix #1: read seams co-route by profile ──
	describe('profile mode co-routes the intelligence read seams to the per-profile shard', () => {
		it('getBenchmark resolves the SAME shard the ingest write used, and reads converge', async () => {
			const { resolveAccumulatorShardName } = await import('../src/lib/profile-accumulator');
			const { getBenchmark } = await import('../src/tools/intelligence');

			const profile = 'web_only';
			const shard = resolveAccumulatorShardName(profile, 'profile');
			const shardStub = env.PROFILE_ACCUMULATOR.getByName(shard);

			// Seed the shard above MIN_BENCHMARK_SCANS so the benchmark reports 'ok'
			// rather than 'insufficient_data', proving the read landed on the written shard.
			for (let i = 0; i < 120; i++) {
				await ingest(shardStub, {
					profile,
					provider: null,
					categoryFindings: [{ category: 'spf', score: 70, passed: true }],
					timestamp: Date.now(),
					overallScore: 70,
				} as ScanTelemetry);
			}

			const { ns, names } = recordingNamespace();
			const result = await getBenchmark(ns, profile, 'profile');
			// The read resolved the per-profile shard (NOT 'global').
			expect(names[0]).toBe(shard);
			expect(names[0]).not.toBe('global');
			// And it converged on the data written to that shard.
			expect(result.status).toBe('ok');
			expect(result.totalScans).toBeGreaterThanOrEqual(120);
		});

		it("getBenchmark on an unwritten 'global' instance returns insufficient_data — the split-brain we prevent", async () => {
			// This is the failure the read-seam fix prevents: if the reads stayed pinned to
			// 'global' while writes went to a shard, 'global' would be write-starved. Here we
			// read 'global' explicitly (no writes routed to it for this fresh profile) and
			// confirm it is NOT 'ok' — i.e. routing the read to the shard above is load-bearing.
			const { getBenchmark } = await import('../src/tools/intelligence');
			const result = await getBenchmark(env.PROFILE_ACCUMULATOR, 'minimal', 'global');
			expect(result.status).not.toBe('ok');
		});
	});

	// ── Adam non-negotiable #4 / Linus must-fix #3: VALID_PROFILES ⊇ SHARDABLE_PROFILES ──
	describe('VALID_PROFILES (DO /ingest) is a superset of SHARDABLE_PROFILES (routing set)', () => {
		it('every shardable profile is accepted by the DO at /ingest (no permanently-empty shard)', async () => {
			const { VALID_PROFILES, SHARDABLE_PROFILES } = await import('../src/lib/profile-accumulator');
			for (const p of SHARDABLE_PROFILES) {
				expect(VALID_PROFILES.has(p)).toBe(true);
			}
		});

		it('authoritative_dns_infra is accepted at /ingest (the fixed latent bug) — write is not dropped', async () => {
			const { resolveAccumulatorShardName } = await import('../src/lib/profile-accumulator');
			const profile = 'authoritative_dns_infra';
			const shard = resolveAccumulatorShardName(profile, 'profile');
			const stub = env.PROFILE_ACCUMULATOR.getByName(shard);
			const res = await ingest(stub, {
				profile,
				provider: null,
				categoryFindings: [{ category: 'dnssec', score: 90, passed: true }],
				timestamp: Date.now(),
				overallScore: 90,
			} as ScanTelemetry);
			// Pre-fix this returned 400 'Invalid profile' and the write was silently dropped.
			expect(res.status).toBe(204);
			const body = (await (await getWeights(stub, profile)).json()) as { sampleCount: number };
			expect(body.sampleCount).toBe(1);
		});
	});

	// ── Adam non-negotiable #6: observable warm-up degradation signal ──
	describe('maybeEmitShardWarmupDegradation (warm-up observability)', () => {
		it('emits shard_below_benchmark_floor only in profile mode below the floor', async () => {
			const { maybeEmitShardWarmupDegradation } = await import('../src/lib/profile-accumulator');
			const events: Array<{ degradationType: string; component: string }> = [];
			const emit = (e: { degradationType: 'shard_below_benchmark_floor'; component: string }) => events.push(e);

			// Below floor + profile mode → emits, component carries the shard name.
			maybeEmitShardWarmupDegradation({ mode: 'profile', profile: 'minimal', sampleCount: 0, emit });
			expect(events).toHaveLength(1);
			expect(events[0].degradationType).toBe('shard_below_benchmark_floor');
			expect(events[0].component).toContain('aw-shard:minimal');
		});

		it('does NOT emit in global mode (legacy instance is converged — no warm-up noise)', async () => {
			const { maybeEmitShardWarmupDegradation } = await import('../src/lib/profile-accumulator');
			const events: unknown[] = [];
			const emit = () => events.push(1);
			maybeEmitShardWarmupDegradation({ mode: 'global', profile: 'minimal', sampleCount: 0, emit });
			maybeEmitShardWarmupDegradation({ mode: undefined, profile: 'minimal', sampleCount: 0, emit });
			expect(events).toHaveLength(0);
		});

		it('does NOT emit once the shard reaches MIN_BENCHMARK_SCANS (warm-up drained)', async () => {
			const { maybeEmitShardWarmupDegradation, MIN_BENCHMARK_SCANS } = await import('../src/lib/profile-accumulator');
			const events: unknown[] = [];
			const emit = () => events.push(1);
			maybeEmitShardWarmupDegradation({ mode: 'profile', profile: 'minimal', sampleCount: MIN_BENCHMARK_SCANS, emit });
			expect(events).toHaveLength(0);
		});
	});
});
