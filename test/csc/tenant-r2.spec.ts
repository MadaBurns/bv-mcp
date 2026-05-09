import { describe, it, expect, vi } from 'vitest';
import { tenantR2 } from '../../src/csc/adapters/tenant-r2';

/**
 * Unit tests for the tenant-R2 adapter.
 *
 * Per CSC-Scalable-Architecture-Design.md §2.3: every read/write is
 * auto-stamped with `<prefix>/` so a bug in tenant code can't read another
 * tenant's objects. `list({ prefix: 'foo' })` is composed as
 * `<tenantPrefix>/foo`.
 */

function fakeR2() {
	const calls: { method: string; key?: string; opts?: unknown }[] = [];
	const binding = {
		put: vi.fn(async (key: string, _value: unknown) => {
			calls.push({ method: 'put', key });
			return { key } as unknown as R2Object;
		}),
		get: vi.fn(async (key: string) => {
			calls.push({ method: 'get', key });
			return null;
		}),
		delete: vi.fn(async (key: string) => {
			calls.push({ method: 'delete', key });
		}),
		list: vi.fn(async (opts?: R2ListOptions) => {
			calls.push({ method: 'list', opts });
			return { objects: [], truncated: false } as unknown as R2Objects;
		}),
	} as unknown as R2Bucket;
	return { binding, calls };
}

describe('tenantR2 adapter', () => {
	it('stamps tenant prefix on put/get/delete and composes list prefix', async () => {
		const { binding, calls } = fakeR2();
		const adapter = tenantR2(binding, 'csc');

		await adapter.put('reports/2026-05.json', new ReadableStream());
		await adapter.get('reports/2026-05.json');
		await adapter.delete('reports/2026-05.json');
		await adapter.list({ prefix: 'reports/' });
		await adapter.list();

		expect(calls).toEqual([
			{ method: 'put', key: 'csc/reports/2026-05.json' },
			{ method: 'get', key: 'csc/reports/2026-05.json' },
			{ method: 'delete', key: 'csc/reports/2026-05.json' },
			{ method: 'list', opts: { prefix: 'csc/reports/' } },
			{ method: 'list', opts: { prefix: 'csc/' } },
		]);
	});

	it('rejects empty / unsafe prefix at construction (cross-tenant leak guard)', () => {
		const { binding } = fakeR2();
		expect(() => tenantR2(binding, '')).toThrow(/prefix/i);
		expect(() => tenantR2(binding, '../escape')).toThrow(/prefix/i);
		expect(() => tenantR2(binding, 'csc/sub')).toThrow(/prefix/i);
	});

	it('rejects keys that escape the tenant namespace (path-traversal guard)', async () => {
		const { binding, calls } = fakeR2();
		const adapter = tenantR2(binding, 'csc');

		await expect(adapter.put('../other-tenant/leak', new ReadableStream())).rejects.toThrow(/invalid key/i);
		await expect(adapter.get('..')).rejects.toThrow(/invalid key/i);
		await expect(adapter.delete('foo/../../bar')).rejects.toThrow(/invalid key/i);
		expect(calls).toEqual([]);
	});

	it('isolates two adapters with different prefixes', async () => {
		const { binding: b1, calls: c1 } = fakeR2();
		const { binding: b2, calls: c2 } = fakeR2();

		await tenantR2(b1, 'csc').put('report.json', new ReadableStream());
		await tenantR2(b2, 'acme').put('report.json', new ReadableStream());

		expect(c1).toEqual([{ method: 'put', key: 'csc/report.json' }]);
		expect(c2).toEqual([{ method: 'put', key: 'acme/report.json' }]);
	});

	it('forwards binding errors instead of swallowing them', async () => {
		const failing = {
			put: vi.fn(async () => {
				throw new Error('R2_ERROR: bucket unavailable');
			}),
			get: vi.fn(),
			delete: vi.fn(),
			list: vi.fn(),
		} as unknown as R2Bucket;
		const adapter = tenantR2(failing, 'csc');
		await expect(adapter.put('a.json', new ReadableStream())).rejects.toThrow(/R2_ERROR/);
	});

	it('exposes the configured prefix and does not mutate the underlying binding', () => {
		const { binding } = fakeR2();
		const before = Object.keys(binding);
		const adapter = tenantR2(binding, 'csc');
		expect(adapter.prefix).toBe('csc');
		expect(Object.keys(binding)).toEqual(before);
	});
});
