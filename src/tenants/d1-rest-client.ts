// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 4 (WFP routing) — D1 REST-by-`d1_db_id` client + the generic
 * exec-backed `TenantDbHandle` adapter shared with the dispatch path.
 *
 * {@link D1ByIdClient} is a minimal `D1Database`-compatible surface over the
 * Cloudflare D1 REST query API
 * (`POST /accounts/{acct}/d1/database/{d1_db_id}/query`). It exposes the exact
 * `prepare().bind().first()/.all()/.run()` shape the tenant call-sites already
 * use, so the resolver can hand it back interchangeably with the static-binding
 * handle. It is the **low-volume operator fallback** only — one API call per SQL
 * statement, subject to the global Cloudflare API rate ceiling (see the Phase-4
 * routing spike, §(e) "the REST wall").
 *
 * {@link createExecBackedHandle} wraps any single-statement `exec(sql, params,
 * op)` runner into the handle surface; it backs BOTH this REST client and the
 * dispatch handle in `tenant-resolver.ts`.
 *
 * Type-only imports from `./tenant-resolver` keep this module free of a runtime
 * dependency on the resolver (the resolver imports values from here), so there
 * is no import cycle at runtime.
 */

import type { TenantDbBackend, TenantDbExecFn, TenantDbHandle, TenantPreparedStatement } from './tenant-resolver';

/** Cloudflare D1 REST `/query` API base. */
const CF_API_BASE = 'https://api.cloudflare.com/client/v4';

/** Shape of the D1 REST `/query` success body (only the fields we read). */
interface D1RestQueryResponse {
	success?: boolean;
	result?: { results?: unknown[] }[];
}

/**
 * Build a `TenantDbHandle` from a single-statement executor.
 *
 * The returned `prepare()` accumulates the SQL string and any `bind()` params
 * immutably (each `bind()` returns a fresh statement), then dispatches to `exec`
 * on `first()` / `all()` / `run()`. `batch()` / `exec()` (the raw D1 surface)
 * are intentionally unsupported on the exec-backed backends — no tenant
 * call-site uses them, and a clear throw beats a silently-wrong multi-statement
 * round-trip over a single-statement transport.
 */
export function createExecBackedHandle(exec: TenantDbExecFn, backend: TenantDbBackend): TenantDbHandle {
	const makeStatement = (sql: string, params: readonly unknown[]): TenantPreparedStatement => {
		const stmt: TenantPreparedStatement = {
			bind: (...values: unknown[]) => makeStatement(sql, [...params, ...values]),
			first: async <T = unknown>(colName?: string): Promise<T | null> => {
				const res = await exec(sql, [...params], 'first');
				const row = res.results?.[0];
				if (row === null || row === undefined) return null;
				if (typeof colName === 'string') {
					const value = (row as Record<string, unknown>)[colName];
					return value === undefined ? null : (value as T);
				}
				return row as T;
			},
			all: async <T = unknown>(): Promise<D1Result<T>> => (await exec(sql, [...params], 'all')) as unknown as D1Result<T>,
			run: async <T = unknown>(): Promise<D1Result<T>> => (await exec(sql, [...params], 'run')) as unknown as D1Result<T>,
		};
		return stmt;
	};

	return {
		backend,
		prepare: (query: string) => makeStatement(query, []),
		batch: () => {
			throw new Error(`tenant_db_batch_unsupported:${backend}`);
		},
		exec: () => {
			throw new Error(`tenant_db_exec_unsupported:${backend}`);
		},
	};
}

/**
 * D1 REST-by-id client — talks the Cloudflare D1 REST query API directly,
 * keyed on the `d1_db_id` column the registry already stores.
 *
 * @param d1DbId   Cloudflare D1 database UUID (`sub_tenants.d1_db_id`).
 * @param accountId Cloudflare account id (`CF_ACCOUNT_ID`).
 * @param apiToken  Scoped API token with D1:Edit (`CF_D1_API_TOKEN`).
 * @param fetchImpl Injectable `fetch` (test seam; defaults to global `fetch`).
 */
export class D1ByIdClient implements TenantDbHandle {
	readonly backend: TenantDbBackend = 'rest';
	private readonly handle: TenantDbHandle;

	constructor(d1DbId: string, accountId: string, apiToken: string, fetchImpl: typeof fetch = fetch) {
		const url = `${CF_API_BASE}/accounts/${accountId}/d1/database/${d1DbId}/query`;
		const runner: TenantDbExecFn = async (sql, params) => {
			const res = await fetchImpl(url, {
				method: 'POST',
				headers: { authorization: `Bearer ${apiToken}`, 'content-type': 'application/json' },
				body: JSON.stringify({ sql, params }),
				signal: AbortSignal.timeout(10_000),
			});
			let body: D1RestQueryResponse;
			try {
				body = (await res.json()) as D1RestQueryResponse;
			} catch {
				throw new Error(`tenant_db_rest_failed:${res.status}`);
			}
			if (!res.ok || !body.success) {
				throw new Error(`tenant_db_rest_failed:${res.status}`);
			}
			// CF returns an array of per-statement results; we issue exactly one
			// statement, so normalise its `results` into a D1Result-shaped object.
			const results = body.result?.[0]?.results ?? [];
			return { success: true, results, meta: {} } as unknown as D1Result;
		};
		this.handle = createExecBackedHandle(runner, 'rest');
	}

	prepare(query: string): TenantPreparedStatement {
		return this.handle.prepare(query);
	}

	batch<T = unknown>(statements: TenantPreparedStatement[]): Promise<D1Result<T>[]> {
		return this.handle.batch<T>(statements);
	}

	exec(query: string): Promise<D1ExecResult> {
		return this.handle.exec(query);
	}
}
