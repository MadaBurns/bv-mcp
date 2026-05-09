import { describe, it, expect, vi } from 'vitest';
import { tenantKV } from '../../src/csc/adapters/tenant-kv';

/**
 * Unit tests for the tenant-KV adapter.
 *
 * Per CSC-Scalable-Architecture-Design.md §2.3: KV bindings are typically
 * SHARED across tenants (rate-limit, session, scan-cache). The adapter
 * auto-stamps `<prefix>:` on every read/write so two tenants can't collide
 * on the same key (e.g. both writing `cache:example.com:check:spf`).
 *
 * Colon separator is used (KV convention in this repo: `cache:<domain>:check:<name>`)
 * rather than slash (R2 convention).
 */

function fakeKV() {
	const calls: { method: string; key?: string; opts?: unknown }[] = [];
	const binding = {
		put: vi.fn(async (key: string, _value: string, opts?: KVNamespacePutOptions) => {
			calls.push({ method: 'put', key, opts });
		}),
		get: vi.fn(async (key: string) => {
			calls.push({ method: 'get', key });
			return null;
		}),
		delete: vi.fn(async (key: string) => {
			calls.push({ method: 'delete', key });
		}),
		list: vi.fn(async (opts?: KVNamespaceListOptions) => {
			calls.push({ method: 'list', opts });
			return { keys: [], list_complete: true, cacheStatus: null } as unknown as KVNamespaceListResult<unknown>;
		}),
	} as unknown as KVNamespace;
	return { binding, calls };
}

describe('tenantKV adapter', () => {
	it('stamps tenant prefix on put/get/delete and composes list prefix', async () => {
		const { binding, calls } = fakeKV();
		const adapter = tenantKV(binding, 'csc');

		await adapter.put('cache:example.com', 'val', { expirationTtl: 60 });
		await adapter.get('cache:example.com');
		await adapter.delete('cache:example.com');
		await adapter.list({ prefix: 'cache:' });
		await adapter.list();

		expect(calls).toEqual([
			{ method: 'put', key: 'csc:cache:example.com', opts: { expirationTtl: 60 } },
			{ method: 'get', key: 'csc:cache:example.com' },
			{ method: 'delete', key: 'csc:cache:example.com' },
			{ method: 'list', opts: { prefix: 'csc:cache:' } },
			{ method: 'list', opts: { prefix: 'csc:' } },
		]);
	});

	it('rejects empty / unsafe prefix at construction (cross-tenant leak guard)', () => {
		const { binding } = fakeKV();
		expect(() => tenantKV(binding, '')).toThrow(/prefix/i);
		expect(() => tenantKV(binding, 'csc:sub')).toThrow(/prefix/i);
		expect(() => tenantKV(binding, 'csc/foo')).toThrow(/prefix/i);
	});

	it('rejects keys containing the prefix separator at the start (path-traversal guard)', async () => {
		const { binding, calls } = fakeKV();
		const adapter = tenantKV(binding, 'csc');

		await expect(adapter.put(':escape', 'v')).rejects.toThrow(/invalid key/i);
		await expect(adapter.get('')).rejects.toThrow(/invalid key/i);
		expect(calls).toEqual([]);
	});

	it('isolates two adapters with different prefixes', async () => {
		const { binding: b1, calls: c1 } = fakeKV();
		const { binding: b2, calls: c2 } = fakeKV();

		await tenantKV(b1, 'csc').put('quota', '1');
		await tenantKV(b2, 'acme').put('quota', '1');

		expect(c1[0]).toMatchObject({ method: 'put', key: 'csc:quota' });
		expect(c2[0]).toMatchObject({ method: 'put', key: 'acme:quota' });
	});

	it('forwards binding errors instead of swallowing them', async () => {
		const failing = {
			put: vi.fn(async () => {
				throw new Error('KV_ERROR: unavailable');
			}),
			get: vi.fn(),
			delete: vi.fn(),
			list: vi.fn(),
		} as unknown as KVNamespace;
		const adapter = tenantKV(failing, 'csc');
		await expect(adapter.put('k', 'v')).rejects.toThrow(/KV_ERROR/);
	});

	it('exposes the configured prefix and does not mutate the underlying binding', () => {
		const { binding } = fakeKV();
		const before = Object.keys(binding);
		const adapter = tenantKV(binding, 'csc');
		expect(adapter.prefix).toBe('csc');
		expect(Object.keys(binding)).toEqual(before);
	});
});
