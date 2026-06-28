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
 * per-tenant binding presence) stays cached; only a cheap single-column `active`
 * probe (`ACTIVE_PROBE_SQL`, not the full-row `REGISTRY_LOOKUP_SQL`) runs on a
 * hit — keeping the hot per-queue-message path cheap (FINDING #2).
 *
 * FINDING #3 (availability): the recheck is fail-OPEN on a thrown read. A
 * definitive "gone" (row missing / `active=false`) drops the entry and 404s; a
 * transient D1 read error serves the still-valid cached value rather than
 * dropping it and re-resolving into the same failing read.
 *
 * Test surface: `resetTenantResolverCache()` clears the cache between specs.
 */

import { resolveTenantRoutingMode } from '../lib/scaling-flags';
import { createExecBackedHandle, D1ByIdClient } from './d1-rest-client';

const CACHE_TTL_MS = 5 * 60 * 1000;
const TENANT_BINDING_PREFIX = 'TENANT_DB_';
const REGISTRY_LOOKUP_SQL = 'SELECT id, super_tenant_id, d1_db_id, routing_mode, active FROM sub_tenants WHERE id = ? LIMIT 1';
/**
 * Cheap, indexed (PK `id`) probe used ONLY on the cache-hit recheck path. It
 * reads a single column instead of the full row so the hot `queue-consumer`
 * loop (one `resolveTenant` per message) doesn't pay for `REGISTRY_LOOKUP_SQL`'s
 * full-row read on every cache hit — that is the FINDING #2 perf regression.
 */
const ACTIVE_PROBE_SQL = 'SELECT active FROM sub_tenants WHERE id = ? LIMIT 1';

/** Same regex enforced by `TENANT_ID_REGEX` in `src/schemas/tenant-internal.ts`. */
const TENANT_ID_REGEX = /^[a-z][a-z0-9_-]{0,63}$/;

/**
 * Which backend a {@link TenantDbHandle} routes to. Selected per-tenant by the
 * `sub_tenants.routing_mode` column (Phase 4):
 *   - `'convention'` — today's static `TENANT_DB_<ID>` env binding (default).
 *   - `'dispatch'`   — a Workers-for-Platforms user Worker (paid isolation).
 *   - `'rest'`       — the D1 REST-by-`d1_db_id` operator fallback.
 */
export type TenantDbBackend = 'convention' | 'dispatch' | 'rest';

/** The `op` a {@link TenantDbExecFn} performs for a single prepared statement. */
export type TenantDbExecOp = 'first' | 'all' | 'run';

/**
 * Single-statement executor backing the `dispatch` / `rest` handles. Given a SQL
 * string, its bound params, and the terminal op, returns a `D1Result`-shaped
 * payload. Implemented over dynamic dispatch (`tenant-resolver.ts`) and the D1
 * REST API (`d1-rest-client.ts`).
 */
export type TenantDbExecFn = (sql: string, params: unknown[], op: TenantDbExecOp) => Promise<D1Result>;

/**
 * Minimal slice of `D1PreparedStatement` the tenant call-sites actually use:
 * `bind().first()/.all()/.run()`. The static-binding backend returns the real
 * `D1PreparedStatement` (which structurally satisfies this); the dispatch / rest
 * backends synthesise it so all call-sites are backend-agnostic.
 */
export interface TenantPreparedStatement {
	bind(...values: unknown[]): TenantPreparedStatement;
	first<T = unknown>(colName?: string): Promise<T | null>;
	all<T = unknown>(): Promise<D1Result<T>>;
	run<T = unknown>(): Promise<D1Result<T>>;
}

/**
 * Opaque, `D1Database`-compatible handle returned by {@link resolveTenant}.
 * Callers use `prepare()` exclusively; `batch()` / `exec()` round out the D1
 * surface for completeness (only the static backend implements them — the
 * exec-backed backends throw, as no tenant call-site uses them). `backend` tags
 * the chosen route for logging / metrics.
 */
export interface TenantDbHandle {
	prepare(query: string): TenantPreparedStatement;
	batch<T = unknown>(statements: TenantPreparedStatement[]): Promise<D1Result<T>[]>;
	exec(query: string): Promise<D1ExecResult>;
	readonly backend: TenantDbBackend;
}

export interface ResolvedTenant {
	subTenantId: string;
	superTenantId: string;
	/**
	 * @deprecated Phase 4 — use {@link ResolvedTenant.db}. The convention-derived
	 * `TENANT_DB_<ID>` binding name, kept for logging / the static hot-set bridge.
	 * Callers no longer dereference it off `env`.
	 */
	dbBinding: string;
	/**
	 * Phase 4: opaque, backend-agnostic D1 handle. Callers issue SQL through this
	 * (`db.prepare(...)`) instead of dereferencing `env[dbBinding]`.
	 */
	db: TenantDbHandle;
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
	/** Phase 4 — Workers-for-Platforms dispatch namespace (paid per-tenant isolation). */
	TENANT_DISPATCH_NAMESPACE?: DispatchNamespace;
	/** Phase 4 — Cloudflare account id for the D1 REST-by-id fallback. */
	CF_ACCOUNT_ID?: string;
	/** Phase 4 — scoped API token (D1:Edit) for the D1 REST-by-id fallback. */
	CF_D1_API_TOKEN?: string;
	/** Phase 4 — env-level default routing mode (`'dispatch'` opts in; else convention). */
	TENANT_ROUTING_MODE?: string;
	[k: string]: unknown;
}

/**
 * Resolve the effective backend for a tenant: the per-tenant `routing_mode`
 * column wins; an absent/unknown value falls back to the env-level default
 * (`TENANT_ROUTING_MODE`, read via {@link resolveTenantRoutingMode}), which is
 * `'convention'` unless an operator opts into `'dispatch'`. Ship-dark: with
 * nothing set, every tenant resolves `'convention'` (today's behavior).
 */
function normalizeRoutingMode(raw: string | null | undefined, env: ResolverEnv): TenantDbBackend {
	if (raw === 'convention' || raw === 'dispatch' || raw === 'rest') return raw;
	return resolveTenantRoutingMode(env) === 'dispatch' ? 'dispatch' : 'convention';
}

/**
 * Wrap a real per-tenant `D1Database` static binding as a {@link TenantDbHandle}.
 * Delegates straight through to D1 — byte-for-byte today's behavior for the
 * enterprise hot-set. `D1PreparedStatement` structurally satisfies
 * {@link TenantPreparedStatement}, so `prepare()` passes through unchanged.
 */
function makeConventionHandle(db: D1Database): TenantDbHandle {
	return {
		backend: 'convention',
		prepare: (query: string) => db.prepare(query),
		batch: <T = unknown>(statements: TenantPreparedStatement[]) => db.batch<T>(statements as unknown as D1PreparedStatement[]),
		exec: (query: string) => db.exec(query),
	};
}

/**
 * Build a {@link TenantDbHandle} that runs SQL inside a Workers-for-Platforms
 * user Worker via dynamic dispatch. The user Worker owns the real `env.DB`
 * binding and answers `POST /query` with `{ sql, params, op }` — the tenant's
 * D1 id never appears in this platform Worker's env (the isolation win).
 *
 * A "Worker not found" on `ns.get()` (provisioning lag / wrong mode) surfaces as
 * `Tenant not found` so the existing route 404 / cron-skip / queue-ack paths
 * fire unchanged.
 */
function makeDispatchHandle(ns: DispatchNamespace, workerName: string): TenantDbHandle {
	const exec: TenantDbExecFn = async (sql, params, op) => {
		let stub: Fetcher;
		try {
			// Per-tenant blast-radius caps mirror the scan_domain subrequest budget.
			stub = ns.get(workerName, {}, { limits: { cpuMs: 200, subRequests: 50 } });
		} catch (err) {
			if (err instanceof Error && err.message.startsWith('Worker not found')) {
				throw new Error(`Tenant not found: ${workerName}`);
			}
			throw err;
		}
		const res = await stub.fetch(
			// Dispatch stubs ignore the request host; use the neutral placeholder host (the path/body carry the query).
			new Request('https://placeholder/query', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ sql, params, op }),
				signal: AbortSignal.timeout(10_000),
			}),
		);
		if (!res.ok) throw new Error(`tenant_db_dispatch_failed:${res.status}`);
		return (await res.json()) as D1Result;
	};
	return createExecBackedHandle(exec, 'dispatch');
}

/**
 * Choose + construct the per-tenant D1 handle from the registry row.
 *
 * Resolution: `routing_mode` column → env default → `'convention'`. The
 * `dispatch` / `rest` backends FAIL SAFE: when the needed binding/token is
 * absent (e.g. on a BSL self-host), they fall through to the `'convention'`
 * static-binding path rather than throwing — ship-dark. The convention path
 * preserves today's behavior exactly, throwing `Tenant not found` when the
 * `TENANT_DB_<ID>` binding is missing.
 */
function buildTenantDb(env: ResolverEnv, row: { d1_db_id: string; routing_mode: string | null }, subTenantId: string): TenantDbHandle {
	const mode = normalizeRoutingMode(row.routing_mode, env);

	if (mode === 'dispatch') {
		const ns = env.TENANT_DISPATCH_NAMESPACE;
		if (ns) return makeDispatchHandle(ns, `tenant-db-${tenantIdToPrefix(subTenantId)}`);
		// Binding absent → fall through to convention (fail-safe, dark).
	} else if (mode === 'rest') {
		const accountId = typeof env.CF_ACCOUNT_ID === 'string' && env.CF_ACCOUNT_ID ? env.CF_ACCOUNT_ID : undefined;
		const apiToken = typeof env.CF_D1_API_TOKEN === 'string' && env.CF_D1_API_TOKEN ? env.CF_D1_API_TOKEN : undefined;
		if (accountId && apiToken && row.d1_db_id) return new D1ByIdClient(row.d1_db_id, accountId, apiToken);
		// Token/account/id absent → fall through to convention (fail-safe, dark).
	}

	const suffix = tenantIdToBindingSuffix(subTenantId);
	const dbBinding = `${TENANT_BINDING_PREFIX}${suffix}`;
	const d1 = (env as Record<string, unknown>)[dbBinding] as D1Database | undefined;
	if (!d1) {
		throw new Error(`Tenant not found: ${subTenantId}`);
	}
	return makeConventionHandle(d1);
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
		// a cheap single-column `active` probe (FINDING #2 — not the full-row read).
		//
		// FINDING #3 (availability): a DEFINITIVE result — row missing or
		// `active = false` — means the tenant is genuinely gone/deactivated, so we
		// drop the entry and surface not-found. But a THROWN read (transient D1
		// hiccup) must NOT take down a tenant that was valid within its TTL: we
		// fail OPEN and serve the cached value, re-checking again on the next hit.
		try {
			const liveRow = await env.TENANT_REGISTRY_DB.prepare(ACTIVE_PROBE_SQL).bind(subTenantId).first<{ active: number | boolean }>();
			if (!liveRow || !liveRow.active) {
				CACHE.delete(subTenantId);
				throw new Error(`Tenant not found: ${subTenantId}`);
			}
			return cached.value;
		} catch (err) {
			if (err instanceof Error && err.message.startsWith('Tenant not found')) {
				throw err;
			}
			// Transient registry read failure — serve the still-valid cached entry
			// (fail-open) instead of dropping it and re-resolving into the same
			// failing read, which would 404 an otherwise-healthy tenant.
			return cached.value;
		}
	}

	const resolved = await loadResolvedTenant(env, subTenantId);
	CACHE.set(subTenantId, { value: resolved, expires: Date.now() + CACHE_TTL_MS });
	return resolved;
}

/**
 * Cache-BYPASSING resolution — the full registry lookup + handle construction
 * with no read/write of the per-isolate cache. Used by the cron handlers
 * (`src/tenants/scheduled-handlers.ts`), which deliberately must not populate
 * the request-scoped cache from a scheduled (non-request) context. One extra
 * registry read per tenant per tick — acceptable at cron cadence.
 *
 * Throws the same `'Tenant not found'` / `'Invalid tenant identifier'` errors as
 * {@link resolveTenant}.
 */
export async function resolveTenantUncached(env: ResolverEnv, subTenantId: string): Promise<ResolvedTenant> {
	if (!TENANT_ID_REGEX.test(subTenantId)) {
		throw new Error('Invalid tenant identifier');
	}
	if (!env.TENANT_REGISTRY_DB) {
		throw new Error(`Tenant not found: ${subTenantId}`);
	}
	return loadResolvedTenant(env, subTenantId);
}

/**
 * Shared cold-path: read the registry row, assert it exists + is active, build
 * the per-tenant {@link TenantDbHandle}, and assemble the {@link ResolvedTenant}.
 * Assumes the caller already validated the id regex + `TENANT_REGISTRY_DB`
 * presence. Does NOT touch the cache.
 */
async function loadResolvedTenant(env: ResolverEnv, subTenantId: string): Promise<ResolvedTenant> {
	const row = await env.TENANT_REGISTRY_DB!.prepare(REGISTRY_LOOKUP_SQL).bind(subTenantId).first<{
		id: string;
		super_tenant_id: string;
		d1_db_id: string;
		routing_mode: string | null;
		active: number | boolean;
	}>();

	if (!row) {
		throw new Error(`Tenant not found: ${subTenantId}`);
	}
	if (!row.active) {
		throw new Error(`Tenant not found: ${subTenantId}`);
	}

	// Build the routing handle (may throw `Tenant not found` if the convention
	// binding is absent — today's behavior preserved).
	const db = buildTenantDb(env, row, subTenantId);

	const suffix = tenantIdToBindingSuffix(subTenantId);
	const dbBinding = `${TENANT_BINDING_PREFIX}${suffix}`;
	const prefix = tenantIdToPrefix(subTenantId);
	return {
		subTenantId,
		superTenantId: row.super_tenant_id,
		dbBinding,
		db,
		prefix,
		r2Prefix: prefix,
		kvPrefix: prefix,
		// Until tenant_keys.scope is read for an explicit override, every
		// resolved tenant defaults to the conservative `'default'` quota.
		tier: 'default',
	};
}
