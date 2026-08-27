// @ts-expect-error cloudflare:test exports are injected by the Workers Vitest pool at runtime.
import { env } from 'cloudflare:test';
import { beforeEach, describe, it, expect } from 'vitest';
import { checkDistinctDomainDailyLimit, resetQuotaCoordinatorBreaker } from '../src/lib/rate-limiter';
import { resetQuotaCoordinatorState, type QuotaCoordinator } from '../src/lib/quota-coordinator';

function memKv() {
	const store = new Map<string, string>();
	return {
		get: async (k: string) => store.get(k) ?? null,
		put: async (k: string, v: string) => void store.set(k, v),
		delete: async (k: string) => void store.delete(k),
	} as unknown as KVNamespace;
}

describe('checkDistinctDomainDailyLimit', () => {
	beforeEach(async () => {
		resetQuotaCoordinatorBreaker();
		await resetQuotaCoordinatorState(env.QUOTA_COORDINATOR);
	});

	it('allows up to `limit` distinct domains, then denies a new one', async () => {
		const kv = memKv();
		const ip = '1.2.3.4';
		for (let i = 0; i < 3; i += 1) {
			const r = await checkDistinctDomainDailyLimit(ip, `d_${i}`, 3, kv);
			expect(r.allowed).toBe(true);
		}
		const denied = await checkDistinctDomainDailyLimit(ip, 'd_new', 3, kv);
		expect(denied.allowed).toBe(false);
		expect(denied.remaining).toBe(0);
	});

	it('does NOT consume budget for an already-seen domain', async () => {
		const kv = memKv();
		const ip = '1.2.3.4';
		await checkDistinctDomainDailyLimit(ip, 'd_a', 2, kv);
		await checkDistinctDomainDailyLimit(ip, 'd_b', 2, kv);
		const again = await checkDistinctDomainDailyLimit(ip, 'd_a', 2, kv);
		expect(again.allowed).toBe(true);
	});

	it('fails open when no KV is provided', async () => {
		const r = await checkDistinctDomainDailyLimit('1.2.3.4', 'd_x', 1, undefined);
		expect(r.allowed).toBe(true);
	});

	it('treats a non-finite limit as unlimited', async () => {
		const r = await checkDistinctDomainDailyLimit('1.2.3.4', 'd_x', Infinity, memKv());
		expect(r.allowed).toBe(true);
	});

	it('atomically permits exactly the limit under 96 concurrent distinct-domain requests', async () => {
		const limit = 12;
		const results = await Promise.all(
			Array.from({ length: 96 }, (_, index) =>
				checkDistinctDomainDailyLimit('203.0.113.96', `fingerprint-${index}`, limit, undefined, env.QUOTA_COORDINATOR),
			),
		);

		expect(results.filter((result) => result.allowed)).toHaveLength(limit);
		expect(results.filter((result) => !result.allowed)).toHaveLength(96 - limit);
	});

	it('does not consume more than one slot for 96 concurrent repeats of one domain', async () => {
		const repeated = await Promise.all(
			Array.from({ length: 96 }, () =>
				checkDistinctDomainDailyLimit('203.0.113.97', 'same-fingerprint', 1, undefined, env.QUOTA_COORDINATOR),
			),
		);
		expect(repeated.every((result) => result.allowed)).toBe(true);

		const fresh = await checkDistinctDomainDailyLimit('203.0.113.97', 'fresh-fingerprint', 1, undefined, env.QUOTA_COORDINATOR);
		expect(fresh.allowed).toBe(false);
	});

	it('fails closed without falling back when a configured coordinator errors', async () => {
		const failingCoordinator = {
			getByName: () => ({
				dispatch: async () => {
					throw new Error('coordinator unavailable');
				},
			}),
		} as unknown as DurableObjectNamespace<QuotaCoordinator>;
		const kv = memKv();

		const result = await checkDistinctDomainDailyLimit('203.0.113.98', 'fingerprint', 12, kv, failingCoordinator);

		expect(result).toMatchObject({ allowed: false, remaining: 0, limit: 12 });
		// Prove no legacy KV fallback wrote an attacker-bypassable counter.
		const dayWindow = Math.floor(Date.now() / 86_400_000);
		expect(await kv.get(`rl:day:ddc:count:203.0.113.98:${dayWindow}`)).toBeNull();
	});
});
