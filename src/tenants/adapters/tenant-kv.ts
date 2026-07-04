// SPDX-License-Identifier: BUSL-1.1

/**
 * Tenant-prefix-stamping adapter for Cloudflare KV.
 *
 * KV bindings are typically SHARED across tenants (rate-limit, session,
 * scan-cache). The adapter auto-stamps `<prefix>:` on every read/write so two
 * tenants can't collide on the same key (e.g. both writing
 * `cache:example.com:check:spf`).
 *
 * Colon separator matches existing KV key conventions in this repo
 * (`cache:<domain>:check:<name>`, `fuzz:p:<id>:e:<bucket>:<kind>`, etc.).
 */

const SAFE_PREFIX = /^[A-Za-z0-9_-]+$/;

function assertSafeKey(key: string): void {
	if (typeof key !== 'string' || key === '' || key.startsWith(':')) {
		throw new Error(`tenantKV: invalid key "${key}"`);
	}
}

export interface TenantKV {
	readonly prefix: string;
	put(key: string, value: string | ArrayBuffer | ArrayBufferView | ReadableStream, options?: KVNamespacePutOptions): Promise<void>;
	get(key: string, options?: Partial<KVNamespaceGetOptions<undefined>>): Promise<string | null>;
	delete(key: string): Promise<void>;
	list<Metadata = unknown>(options?: KVNamespaceListOptions): Promise<KVNamespaceListResult<Metadata>>;
}

/**
 * Wrap a KV namespace binding with tenant-prefix-stamping.
 *
 * @param binding - underlying KV namespace binding
 * @param prefix - tenant identifier (must match `[A-Za-z0-9_-]+`, no `:` or `/`)
 * @throws if `prefix` is empty or contains unsafe characters
 */
export function tenantKV(binding: KVNamespace, prefix: string): TenantKV {
	if (!prefix || !SAFE_PREFIX.test(prefix)) {
		throw new Error(`tenantKV: invalid prefix "${prefix}" (must match [A-Za-z0-9_-]+)`);
	}

	const stamp = (k: string) => `${prefix}:${k}`;

	return {
		prefix,
		async put(key, value, options) {
			assertSafeKey(key);
			// KV.put signature varies by value type; cast to string is fine for
			// the underlying binding which accepts any of the supported types.
			return binding.put(stamp(key), value as string, options);
		},
		async get(key, options) {
			assertSafeKey(key);
			return binding.get(stamp(key), options as KVNamespaceGetOptions<undefined>);
		},
		async delete(key) {
			assertSafeKey(key);
			return binding.delete(stamp(key));
		},
		async list<Metadata = unknown>(options?: KVNamespaceListOptions): Promise<KVNamespaceListResult<Metadata>> {
			const innerPrefix = options?.prefix ?? '';
			return binding.list<Metadata>({ ...options, prefix: `${prefix}:${innerPrefix}` });
		},
	};
}
