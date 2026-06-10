// SPDX-License-Identifier: BUSL-1.1

/**
 * Resolve a `sub_tenant_id` to a per-tenant D1 binding + namespace prefixes.
 *
 * Each sub-tenant has its own D1 database, declared in `wrangler.jsonc` with a
 * deterministic binding name. The shared registry D1 (`TENANT_REGISTRY_DB`
 * binding) keeps the metadata row that confirms the tenant exists and is
 * active.
 *
 * Binding name convention:
 *   sub_tenant_id `tenant-1` →  `TENANT_DB_Tenant_ACME_CORP`
 *
 * Hyphens are converted to underscores because Cloudflare binding names must
 * match `[A-Za-z0-9_]`. The same transform is applied when constructing the
 * `tenantD1` adapter prefix so SQL string interpolation stays safe.
 *
 * Cache: in-memory per-isolate `Map<subTenantId, ResolvedTenant>` with a 5-min
 * TTL. Only **successful** resolutions are cached — caching "not found" would
 * make a freshly-provisioned tenant invisible for up to 5 min after creation.
 *
 * FINDING #7: a cache hit re-validates the registry `active` flag before serving
 * the cached binding/prefix work, so a tenant deactivated mid-TTL stops
 * resolving promptly instead of staying valid for up to the full 5 min. The
 * heavier resolution work (regex, binding-name derivation, prefix construction,
 * per-tenant binding presence) stays cached; only the cheap indexed `active`
 * lookup runs on a hit.
 *
 * Test surface: `resetTenantResolverCache()` clears the cache between specs.
 */

const CACHE_TTL_MS = 5 * 60 * 1000;
const TENANT_BINDING_PREFIX = 'TENANT_DB_';
const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, active FROM sub_tenants WHERE id = ? LIMIT 1';

/** Same regex enforced by `TENANT_ID_REGEX` in `src/schemas/tenant-internal.ts`. */
const TENANT_ID_REGEX = /^[a-z][a-z0-9_-]{0,63}$/;

export interface ResolvedTenant {
	subTenantId: string;
	superTenantId: string;
	/** Name of the per-tenant D1 binding declared in wrangler.jsonc. */
	dbBinding: string;
	/** Adapter-safe prefix (hyphens replaced with underscores). */
	prefix: string;
	/** R2 / KV namespace prefix derived from the sub-tenant id. */
	r2Prefix: string;
	kvPrefix: string;
	/**
	 * Quota tier — `'default'` unless an explicit override row appears in
	 * `tenant_keys.scope` (TODO: wire up when bv-web ships the override path).
	 * Consumed by `src/tenants/per-tenant-rate-limit.ts` to pick the right quota.
	 *
	 * Phase 6 keeps this additive: today every successfully-resolved tenant
	 * gets `'default'`; the only branch that returns a different tier is the
	 * forthcoming registry lookup that will read `tenant_keys.scope` for
	 * tier=enterprise rows. Adding the field now means callers compile
	 * unchanged when that lookup lands.
	 */
	tier: 'default' | 'enterprise';
}

interface CachedEntry {
	value: ResolvedTenant;
	expires: number;
}

const CACHE = new Map<string, CachedEntry>();

/** Test helper: reset the in-memory resolver cache. */
export function resetTenantResolverCache(): void {
	CACHE.clear();
}

/** Convert a hyphen-allowed sub-tenant id to an adapter-safe identifier. */
export function tenantIdToBindingSuffix(subTenantId: string): string {
	return subTenantId.replaceAll('-', '_').toUpperCase();
}

/** Convert a hyphen-allowed sub-tenant id to a tenantD1-safe prefix. */
export function tenantIdToPrefix(subTenantId: string): string {
	return subTenantId.replaceAll('-', '_').toLowerCase();
}

export interface ResolverEnv {
	TENANT_REGISTRY_DB?: D1Database;
	[k: string]: unknown;
}

/**
 * Resolve a sub-tenant id to its binding + namespacing prefixes.
 *
 * Throws `Error('Tenant not found: <id>')` when:
 *   - `TENANT_REGISTRY_DB` is not bound on the env (deployment misconfig — surfaced
 *     to the caller as 404 because from the client's perspective the tenant
 *     doesn't exist)
 *   - the sub_tenants row is missing or `active = false`
 *   - the per-tenant D1 binding (e.g. `TENANT_DB_<id>`) is not bound
 */
export async function resolveTenant(env: ResolverEnv, subTenantId: string): Promise<ResolvedTenant> {
	if (!TENANT_ID_REGEX.test(subTenantId)) {
		throw new Error('Invalid tenant identifier');
	}

	if (!env.TENANT_REGISTRY_DB) {
		throw new Error(`Tenant not found: ${subTenantId}`);
	}

	const cached = CACHE.get(subTenantId);
	if (cached && cached.expires > Date.now()) {
		// FINDING #7: re-validate the registry `active` flag on a cache hit so a
		// tenant deactivated mid-TTL stops resolving immediately. We keep the rest
		// of the cached resolution (binding name, prefixes, tier) and only pay for
		// the cheap indexed lookup. If the registry read throws, fall through to a
		// full re-resolution rather than serving a possibly-stale entry.
		try {
			const liveRow = await env.TENANT_REGISTRY_DB.prepare(REGISTRY_LOOKUP_SQL).bind(subTenantId).first<{ active: number | boolean }>();
			if (!liveRow || !liveRow.active) {
				CACHE.delete(subTenantId);
				throw new Error(`Tenant not found: ${subTenantId}`);
			}
			return cached.value;
		} catch (err) {
			if (err instanceof Error && err.message.startsWith('Tenant not found')) {
				throw err;
			}
			// Registry read failed — drop the cache entry and re-resolve below.
			CACHE.delete(subTenantId);
		}
	}

	const row = await env.TENANT_REGISTRY_DB.prepare(REGISTRY_LOOKUP_SQL).bind(subTenantId).first<{
		id: string;
		super_tenant_id: string;
		d1_db_id: string;
		active: number | boolean;
	}>();

	if (!row) {
		throw new Error(`Tenant not found: ${subTenantId}`);
	}
	if (!row.active) {
		throw new Error(`Tenant not found: ${subTenantId}`);
	}

	const suffix = tenantIdToBindingSuffix(subTenantId);
	const dbBinding = `${TENANT_BINDING_PREFIX}${suffix}`;
	const tenantDb = (env as Record<string, unknown>)[dbBinding];
	if (!tenantDb) {
		throw new Error(`Tenant not found: ${subTenantId}`);
	}

	const prefix = tenantIdToPrefix(subTenantId);
	const resolved: ResolvedTenant = {
		subTenantId,
		superTenantId: row.super_tenant_id,
		dbBinding,
		prefix,
		r2Prefix: prefix,
		kvPrefix: prefix,
		// Until tenant_keys.scope is read for an explicit override, every
		// resolved tenant defaults to the conservative `'default'` quota.
		tier: 'default',
	};

	CACHE.set(subTenantId, { value: resolved, expires: Date.now() + CACHE_TTL_MS });
	return resolved;
}
