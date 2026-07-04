// SPDX-License-Identifier: BUSL-1.1

/**
 * Tenant-prefix-stamping adapter for Cloudflare R2.
 *
 * Every read/write is auto-stamped with `<prefix>/` so a bug in tenant code
 * can't read another tenant's objects. `list({ prefix: 'foo' })` is composed
 * as `<tenantPrefix>/foo`.
 *
 * Path-traversal guard: keys containing `..` segments are rejected before
 * any I/O. Prefix must be a single safe identifier — slashes are not
 * permitted (one prefix per tenant; sub-namespacing is the caller's
 * responsibility).
 */

const SAFE_PREFIX = /^[A-Za-z0-9_-]+$/;

function assertSafeKey(key: string): void {
	if (typeof key !== 'string' || key === '' || key === '..') {
		throw new Error(`tenantR2: invalid key "${key}"`);
	}
	const segments = key.split('/');
	for (const seg of segments) {
		if (seg === '..') {
			throw new Error(`tenantR2: invalid key "${key}" (contains traversal segment)`);
		}
	}
}

export interface TenantR2 {
	readonly prefix: string;
	put(key: string, value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null, options?: R2PutOptions): Promise<R2Object | null>;
	get(key: string, options?: R2GetOptions): Promise<R2ObjectBody | null>;
	delete(key: string): Promise<void>;
	list(options?: R2ListOptions): Promise<R2Objects>;
}

/**
 * Wrap an R2 bucket binding with tenant-prefix-stamping.
 *
 * @param binding - underlying R2 bucket binding
 * @param prefix - tenant identifier (must match `[A-Za-z0-9_-]+`, no `/`)
 * @throws if `prefix` is empty, contains `/`, or contains traversal characters
 */
export function tenantR2(binding: R2Bucket, prefix: string): TenantR2 {
	if (!prefix || !SAFE_PREFIX.test(prefix)) {
		throw new Error(`tenantR2: invalid prefix "${prefix}" (must match [A-Za-z0-9_-]+)`);
	}

	const stamp = (k: string) => `${prefix}/${k}`;

	return {
		prefix,
		async put(key, value, options) {
			assertSafeKey(key);
			return binding.put(stamp(key), value as ReadableStream, options);
		},
		async get(key, options) {
			assertSafeKey(key);
			return binding.get(stamp(key), options);
		},
		async delete(key) {
			assertSafeKey(key);
			return binding.delete(stamp(key));
		},
		async list(options) {
			const innerPrefix = options?.prefix ?? '';
			return binding.list({ ...options, prefix: `${prefix}/${innerPrefix}` });
		},
	};
}
