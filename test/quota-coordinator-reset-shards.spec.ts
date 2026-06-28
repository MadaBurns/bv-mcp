// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 3 (decision #1): `resetQuotaCoordinatorShards` is the salt/count-ROTATION
 * reset — it clears the per-IP / per-tool-daily counters stranded on the shard
 * instances WITHOUT touching the singleton's authoritative `global-daily` cost
 * ceiling. The full `resetQuotaCoordinatorState` (used for test isolation) DOES nuke
 * global-daily and must never run in production.
 *
 * Invariants under test:
 *  - shards-only reset clears a sharded counter but PRESERVES the global-daily counter;
 *  - shards-only reset targets every `quota-shard-N` and NEVER the singleton name;
 *  - it is a fail-soft no-op when the namespace is absent;
 *  - the full reset (contrast) clears global-daily too.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { env } from 'cloudflare:test';
import {
	checkGlobalDailyLimitWithCoordinator,
	checkToolDailyRateLimitWithCoordinator,
	resetQuotaCoordinatorShards,
	resetQuotaCoordinatorState,
	type ShardRouting,
} from '../src/lib/quota-coordinator';

const SHARD_COUNT = 16;
const SHARDED: ShardRouting = { enabled: true, salt: '' };

afterEach(async () => {
	// Full wipe between cases (singleton + shards) so global-daily starts at 0.
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
});

describe('resetQuotaCoordinatorShards — routing', () => {
	it('resets every shard instance and NEVER the singleton', async () => {
		const names: string[] = [];
		const ns = {
			getByName: (name: string) => {
				names.push(name);
				return { fetch: async () => new Response(null, { status: 204 }) };
			},
		} as unknown as DurableObjectNamespace;

		await resetQuotaCoordinatorShards(ns);

		expect(names).toHaveLength(SHARD_COUNT);
		expect(names).not.toContain('global-quota-coordinator');
		for (let i = 0; i < SHARD_COUNT; i++) {
			expect(names).toContain(`quota-shard-${i}`);
		}
	});

	it('is a fail-soft no-op when the namespace is absent', async () => {
		await expect(resetQuotaCoordinatorShards(undefined)).resolves.toBeUndefined();
	});

	it('swallows a single failing shard reset (best-effort)', async () => {
		const ns = {
			getByName: (name: string) => ({
				fetch: async () => {
					if (name === 'quota-shard-3') throw new Error('shard unreachable');
					return new Response(null, { status: 204 });
				},
			}),
		} as unknown as DurableObjectNamespace;
		await expect(resetQuotaCoordinatorShards(ns)).resolves.toBeUndefined();
	});
});

describe('resetQuotaCoordinatorShards — preserves global-daily (real DO)', () => {
	it('clears a sharded counter but PRESERVES the global-daily cost ceiling', async () => {
		const ns = env.QUOTA_COORDINATOR;

		// Exhaust the global-daily ceiling (limit 2) — these land on the singleton.
		const g1 = await checkGlobalDailyLimitWithCoordinator(2, ns);
		const g2 = await checkGlobalDailyLimitWithCoordinator(2, ns);
		const g3 = await checkGlobalDailyLimitWithCoordinator(2, ns);
		expect([g1!.allowed, g2!.allowed, g3!.allowed]).toEqual([true, true, false]);

		// Exhaust a sharded per-principal tool-daily counter (limit 1) — lands on a shard.
		const principal = 'ip:198.51.100.9';
		const t1 = await checkToolDailyRateLimitWithCoordinator(principal, 'check_spf', 1, ns, SHARDED);
		const t2 = await checkToolDailyRateLimitWithCoordinator(principal, 'check_spf', 1, ns, SHARDED);
		expect([t1!.allowed, t2!.allowed]).toEqual([true, false]);

		// Shards-only reset.
		await resetQuotaCoordinatorShards(ns);

		// Global-daily is UNTOUCHED: still over its limit → denied.
		const gAfter = await checkGlobalDailyLimitWithCoordinator(2, ns);
		expect(gAfter!.allowed).toBe(false);

		// The sharded counter WAS cleared: the principal's first call is allowed again.
		const tAfter = await checkToolDailyRateLimitWithCoordinator(principal, 'check_spf', 1, ns, SHARDED);
		expect(tAfter!.allowed).toBe(true);
	});

	it('contrast: the full reset DOES clear global-daily', async () => {
		const ns = env.QUOTA_COORDINATOR;

		await checkGlobalDailyLimitWithCoordinator(1, ns);
		const denied = await checkGlobalDailyLimitWithCoordinator(1, ns);
		expect(denied!.allowed).toBe(false);

		await resetQuotaCoordinatorState(ns);

		// Global-daily counter was wiped → allowed again (the prod foot-gun the JSDoc warns about).
		const reAllowed = await checkGlobalDailyLimitWithCoordinator(1, ns);
		expect(reAllowed!.allowed).toBe(true);
	});
});
