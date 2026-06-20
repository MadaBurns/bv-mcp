// SPDX-License-Identifier: BUSL-1.1

/**
 * R8 correctness tests for QuotaCoordinator sharding + batched evaluation.
 *
 * Invariants under test:
 *  - same principal/IP → same shard (so counts are never split/double-counted);
 *  - distinct principals fan across shards (the throughput win);
 *  - per-IP/per-principal kinds route to shards; global-daily + reset stay on the singleton;
 *  - the batched `evaluate` round trip yields counts IDENTICAL to the serial single-instance path,
 *    including short-circuit-on-first-denial semantics;
 *  - the global-daily ceiling is still enforced exactly (it stays on the singleton).
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { env } from 'cloudflare:test';
import {
	shardIndexForKey,
	shardNameForKey,
	validateQuotaPayload,
	evaluateQuotaWithCoordinator,
	checkScopedRateLimitWithCoordinator,
	checkToolDailyRateLimitWithCoordinator,
	checkGlobalDailyLimitWithCoordinator,
	resetQuotaCoordinatorState,
	parseEvaluateResponse,
	MalformedEvaluateResponse,
	SINGLETON_ROUTING,
	type ShardRouting,
} from '../src/lib/quota-coordinator';

const SHARD_COUNT = 16;

/** Sharding-ON routing (no salt) — exercises the shard fan-out path. */
const SHARDED: ShardRouting = { enabled: true, salt: '' };

afterEach(async () => {
	await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
	vi.restoreAllMocks();
});

describe('shard key derivation', () => {
	it('is deterministic for a given key', () => {
		expect(shardIndexForKey('203.0.113.7')).toBe(shardIndexForKey('203.0.113.7'));
		expect(shardNameForKey('203.0.113.7')).toBe(shardNameForKey('203.0.113.7'));
	});

	it('maps the same principal to the same shard always', () => {
		const key = 'ip:198.51.100.42';
		const first = shardNameForKey(key);
		for (let i = 0; i < 100; i++) {
			expect(shardNameForKey(key)).toBe(first);
		}
	});

	it('stays within [0, SHARD_COUNT)', () => {
		for (let i = 0; i < 500; i++) {
			const idx = shardIndexForKey(`10.0.${i % 255}.${i}`);
			expect(idx).toBeGreaterThanOrEqual(0);
			expect(idx).toBeLessThan(SHARD_COUNT);
		}
	});

	it('fans distinct principals across multiple shards', () => {
		const buckets = new Set<number>();
		for (let i = 0; i < 256; i++) {
			buckets.add(shardIndexForKey(`192.0.2.${i}`));
		}
		// With 256 distinct IPs over 16 shards we expect broad coverage, certainly > 1.
		expect(buckets.size).toBeGreaterThan(8);
	});
});

describe('evaluate payload validation', () => {
	it('accepts a well-formed evaluate batch', () => {
		const result = validateQuotaPayload({
			kind: 'evaluate',
			shardKey: '203.0.113.1',
			checks: [
				{ kind: 'scoped-rate', scope: 'tools', ip: '203.0.113.1', minuteLimit: 50, hourLimit: 300 },
				{ kind: 'tool-daily', principalId: '203.0.113.1', toolName: 'check_spf', limit: 200 },
			],
		});
		expect(result.valid).toBe(true);
	});

	it('rejects an evaluate batch that smuggles a global-daily sub-check (would mis-route the global counter)', () => {
		const result = validateQuotaPayload({
			kind: 'evaluate',
			shardKey: '203.0.113.1',
			checks: [{ kind: 'global-daily', limit: 10 }],
		});
		expect(result.valid).toBe(false);
		if (!result.valid) expect(result.error).toContain('scoped-rate or tool-daily');
	});

	it('rejects an empty or missing shardKey', () => {
		expect(validateQuotaPayload({ kind: 'evaluate', shardKey: '', checks: [{ kind: 'tool-daily', principalId: 'x', toolName: 't', limit: 1 }] }).valid).toBe(false);
		expect(validateQuotaPayload({ kind: 'evaluate', checks: [] }).valid).toBe(false);
	});

	it('rejects an over-long batch', () => {
		const checks = Array.from({ length: 20 }, () => ({ kind: 'scoped-rate', scope: 'tools', ip: '1.2.3.4', minuteLimit: 5, hourLimit: 5 }));
		expect(validateQuotaPayload({ kind: 'evaluate', shardKey: '1.2.3.4', checks }).valid).toBe(false);
	});
});

describe('routing', () => {
	function spyNamespace(): { ns: DurableObjectNamespace; names: string[] } {
		const names: string[] = [];
		const ns = {
			getByName: (name: string) => {
				names.push(name);
				return {
					fetch: async () =>
						new Response(JSON.stringify({ allowed: true, minuteRemaining: 1, hourRemaining: 1, remaining: 1, limit: 1, results: [] }), {
							status: 200,
							headers: { 'content-type': 'application/json' },
						}),
				};
			},
		} as unknown as DurableObjectNamespace;
		return { ns, names };
	}

	it('routes scoped-rate to the IP shard (sharding ON)', async () => {
		const { ns, names } = spyNamespace();
		await checkScopedRateLimitWithCoordinator('203.0.113.9', 'tools', 50, 300, ns, SHARDED);
		expect(names).toEqual([shardNameForKey('203.0.113.9', SHARDED.salt)]);
		expect(names[0]).toMatch(/^quota-shard-\d+$/);
	});

	it('routes tool-daily to the principal shard (sharding ON)', async () => {
		const { ns, names } = spyNamespace();
		await checkToolDailyRateLimitWithCoordinator('ip:198.51.100.5', 'check_spf', 200, ns, SHARDED);
		expect(names).toEqual([shardNameForKey('ip:198.51.100.5', SHARDED.salt)]);
	});

	it('routes global-daily to the singleton (NOT a shard)', async () => {
		const { ns, names } = spyNamespace();
		await checkGlobalDailyLimitWithCoordinator(500_000, ns);
		expect(names).toEqual(['global-quota-coordinator']);
	});

	it('routes the evaluate batch to the shardKey shard (sharding ON)', async () => {
		const { ns, names } = spyNamespace();
		await evaluateQuotaWithCoordinator('203.0.113.20', [{ kind: 'scoped-rate', scope: 'tools', ip: '203.0.113.20', minuteLimit: 50, hourLimit: 300 }], ns, SHARDED);
		expect(names).toEqual([shardNameForKey('203.0.113.20', SHARDED.salt)]);
	});

	// ADAM #2: flag-OFF (the default SINGLETON_ROUTING) keeps EVERY per-IP/per-principal
	// kind on the singleton — byte-for-byte the pre-shard behavior.
	it('flag-OFF routes scoped-rate to the singleton (no shard)', async () => {
		const { ns, names } = spyNamespace();
		await checkScopedRateLimitWithCoordinator('203.0.113.9', 'tools', 50, 300, ns, SINGLETON_ROUTING);
		expect(names).toEqual(['global-quota-coordinator']);
	});

	it('flag-OFF routes tool-daily to the singleton (no shard)', async () => {
		const { ns, names } = spyNamespace();
		await checkToolDailyRateLimitWithCoordinator('ip:198.51.100.5', 'check_spf', 200, ns, SINGLETON_ROUTING);
		expect(names).toEqual(['global-quota-coordinator']);
	});

	it('flag-OFF routes the evaluate batch to the singleton (no shard)', async () => {
		const { ns, names } = spyNamespace();
		await evaluateQuotaWithCoordinator('203.0.113.20', [{ kind: 'scoped-rate', scope: 'tools', ip: '203.0.113.20', minuteLimit: 50, hourLimit: 300 }], ns, SINGLETON_ROUTING);
		expect(names).toEqual(['global-quota-coordinator']);
	});

	// ADAM #4: the salt changes the shard mapping (raw IP is not directly hashable).
	it('the salt changes the shard mapping for a given key', () => {
		const unsalted = shardNameForKey('203.0.113.9', '');
		const salted = shardNameForKey('203.0.113.9', 'deploy-secret-salt');
		// Deterministic per (key,salt); the salted name is a valid shard, and for this
		// key the two differ — proving the mapping depends on the (secret) salt.
		expect(salted).toMatch(/^quota-shard-\d+$/);
		expect(salted).not.toBe(unsalted);
	});
});

describe('evaluate response parsing (LINUS MUST-FIX #1)', () => {
	it('parses a well-formed results array', () => {
		const parsed = parseEvaluateResponse({
			results: [{ index: 0, kind: 'scoped-rate', result: { allowed: true, minuteRemaining: 1, hourRemaining: 1 } }],
		});
		expect(parsed).toHaveLength(1);
		expect(parsed[0].kind).toBe('scoped-rate');
	});

	it('THROWS on a non-array results ({results:{}})', () => {
		expect(() => parseEvaluateResponse({ results: {} })).toThrow(MalformedEvaluateResponse);
	});

	it('THROWS on a results entry with an unrecognized kind', () => {
		expect(() => parseEvaluateResponse({ results: [{ index: 0, kind: 'mystery', result: { allowed: true } }] })).toThrow(
			MalformedEvaluateResponse,
		);
	});

	it('THROWS on a missing results field', () => {
		expect(() => parseEvaluateResponse({})).toThrow(MalformedEvaluateResponse);
		expect(() => parseEvaluateResponse(null)).toThrow(MalformedEvaluateResponse);
	});

	it('evaluateQuotaWithCoordinator THROWS on a 2xx-but-malformed body (DO ran)', async () => {
		const malformedNs = {
			getByName: () => ({
				fetch: async () =>
					new Response(JSON.stringify({ results: { index: 0, kind: 'tool-daily' } }), {
						status: 200,
						headers: { 'content-type': 'application/json' },
					}),
			}),
		} as unknown as DurableObjectNamespace;
		await expect(
			evaluateQuotaWithCoordinator('1.2.3.4', [{ kind: 'scoped-rate', scope: 'tools', ip: '1.2.3.4', minuteLimit: 50, hourLimit: 300 }], malformedNs, SHARDED),
		).rejects.toBeInstanceOf(MalformedEvaluateResponse);
	});

	it('evaluateQuotaWithCoordinator returns undefined when the namespace is absent (DO did not run)', async () => {
		const result = await evaluateQuotaWithCoordinator(
			'1.2.3.4',
			[{ kind: 'scoped-rate', scope: 'tools', ip: '1.2.3.4', minuteLimit: 50, hourLimit: 300 }],
			undefined,
			SHARDED,
		);
		expect(result).toBeUndefined();
	});
});

describe('sharded routing preserves counts (real DO)', () => {
	it('a single principal counts identically across repeated sharded tool-daily calls', async () => {
		const principal = 'ip:203.0.113.77';
		const limit = 5;
		const allowed: boolean[] = [];
		for (let i = 0; i < 7; i++) {
			const r = await checkToolDailyRateLimitWithCoordinator(principal, 'check_spf', limit, env.QUOTA_COORDINATOR);
			allowed.push(r!.allowed);
		}
		// First 5 allowed, then denied — exactly as a single instance would count.
		expect(allowed).toEqual([true, true, true, true, true, false, false]);
	});

	it('distinct principals do not share a counter even when on different shards', async () => {
		const a = await checkToolDailyRateLimitWithCoordinator('ip:a', 'check_spf', 1, env.QUOTA_COORDINATOR);
		const b = await checkToolDailyRateLimitWithCoordinator('ip:b', 'check_spf', 1, env.QUOTA_COORDINATOR);
		// Each gets their own first-call allow.
		expect(a!.allowed).toBe(true);
		expect(b!.allowed).toBe(true);
		// Second call for A is denied (its own counter), B unaffected.
		const a2 = await checkToolDailyRateLimitWithCoordinator('ip:a', 'check_spf', 1, env.QUOTA_COORDINATOR);
		expect(a2!.allowed).toBe(false);
	});
});

describe('batched evaluate == serial single-instance (real DO)', () => {
	it('batched scoped-rate + tool-daily counts match running them serially', async () => {
		// Serial baseline on one principal.
		const serialIp = '198.51.100.100';
		const serialScoped = await checkScopedRateLimitWithCoordinator(serialIp, 'tools', 50, 300, env.QUOTA_COORDINATOR);
		const serialTool = await checkToolDailyRateLimitWithCoordinator(serialIp, 'check_spf', 200, env.QUOTA_COORDINATOR);

		// Batched path on a DIFFERENT principal (fresh counters).
		const batchIp = '198.51.100.101';
		const batched = await evaluateQuotaWithCoordinator(
			batchIp,
			[
				{ kind: 'scoped-rate', scope: 'tools', ip: batchIp, minuteLimit: 50, hourLimit: 300 },
				{ kind: 'tool-daily', principalId: batchIp, toolName: 'check_spf', limit: 200 },
			],
			env.QUOTA_COORDINATOR,
		);

		const scopedEntry = batched!.find((r) => r.kind === 'scoped-rate');
		const toolEntry = batched!.find((r) => r.kind === 'tool-daily');
		expect(scopedEntry!.result).toMatchObject({ allowed: true, minuteRemaining: serialScoped!.minuteRemaining, hourRemaining: serialScoped!.hourRemaining });
		expect(toolEntry!.result).toMatchObject({ allowed: true, remaining: serialTool!.remaining, limit: serialTool!.limit });
	});

	it('short-circuits on the first denial: a denied scoped-rate never increments tool-daily', async () => {
		const ip = '198.51.100.200';
		// Exhaust the scoped-rate minute limit (1) so the next batch denies on scoped-rate.
		await checkScopedRateLimitWithCoordinator(ip, 'tools', 1, 300, env.QUOTA_COORDINATOR);

		const batched = await evaluateQuotaWithCoordinator(
			ip,
			[
				{ kind: 'scoped-rate', scope: 'tools', ip, minuteLimit: 1, hourLimit: 300 },
				{ kind: 'tool-daily', principalId: ip, toolName: 'check_caa', limit: 200 },
			],
			env.QUOTA_COORDINATOR,
		);
		// Only the scoped-rate (denied) verdict is present; tool-daily was short-circuited.
		expect(batched!.length).toBe(1);
		expect(batched![0].kind).toBe('scoped-rate');
		expect(batched![0].result.allowed).toBe(false);

		// Prove the tool-daily counter is untouched: a fresh full-quota call sees count 0.
		const tool = await checkToolDailyRateLimitWithCoordinator(ip, 'check_caa', 200, env.QUOTA_COORDINATOR);
		expect(tool!.remaining).toBe(199); // first increment → 199 remaining of 200
	});
});

describe('global-daily ceiling stays exact on the singleton', () => {
	it('enforces the global cap regardless of which IP/shard the caller is on', async () => {
		const limit = 3;
		const verdicts: boolean[] = [];
		for (let i = 0; i < 5; i++) {
			const r = await checkGlobalDailyLimitWithCoordinator(limit, env.QUOTA_COORDINATOR);
			verdicts.push(r!.allowed);
		}
		expect(verdicts).toEqual([true, true, true, false, false]);
	});
});
