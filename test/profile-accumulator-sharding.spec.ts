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
			expect(resolveAccumulatorShardName('totally_unknown', 'profile')).toBe(
				resolveAccumulatorShardName('mail_enabled', 'profile'),
			);
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
});
