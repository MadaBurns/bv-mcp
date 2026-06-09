import { describe, it, expect } from 'vitest';
import { checkDistinctDomainDailyLimit } from '../src/lib/rate-limiter';

function memKv() {
	const store = new Map<string, string>();
	return {
		get: async (k: string) => store.get(k) ?? null,
		put: async (k: string, v: string) => void store.set(k, v),
		delete: async (k: string) => void store.delete(k),
	} as unknown as KVNamespace;
}

describe('checkDistinctDomainDailyLimit', () => {
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
});
