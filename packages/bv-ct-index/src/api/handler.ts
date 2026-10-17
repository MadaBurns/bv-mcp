// SPDX-License-Identifier: BUSL-1.1
/**
 * The query API: the three routes bv-mcp's BV_CERTSTREAM binding calls, answered from an IndexReader.
 *
 * Response shapes follow what bv-mcp parses (SQ-338):
 *   /enumerate  src/tools/discover-subdomains.ts:645  { domain, subdomains[], certificateCount, timedOut, cached }
 *   /sans       src/tools/discover-subdomains.ts:656  { domain, names[], certificateCount, timedOut, truncated, cached }
 *               src/tenants/discovery/san-correlator.ts:151 (the same fields, minus `truncated`)
 *   /cert-meta  src/tools/scan/post-processing.ts:203-233  an object with a non-empty string `issuer`, no truthy `error`
 * Every other field here is additive. Errors are `{ error: string }`, which bv-mcp reads as a failed source.
 *
 * Fault rule: bv-mcp treats ANY non-null certstream answer as final, so a fault must never look like an
 * empty answer. A reader throw, a blown budget and a never-populated index all answer 503. Only a RangeError
 * (a bad domain or cursor) answers 400. An empty 200 means the index was read and holds nothing.
 */

import { apexOf, nameKey } from '../codec';
import type { Env } from '../index';
import type { IndexReader, SiblingObservation } from '../types';
import { isAuthorized } from './auth';

/** Page size, matching the 500-name display cap bv-mcp already applies. */
export const PAGE_LIMIT = 500;
/** Internal deadline. bv-mcp gives each route 8000 ms (/cert-meta 5000 ms) and shares one 24 s budget across sources. */
export const API_BUDGET_MS = 1500;
const COVERAGE_SOURCE = 'bv-ct-index';

export interface ApiDeps {
	reader: IndexReader;
	/** Test seam; production uses API_BUDGET_MS. */
	budgetMs?: number;
}

class BudgetExceededError extends Error {}
class IndexNotReadyError extends Error {}

type ReaderMeta = Awaited<ReturnType<IndexReader['meta']>>;

/**
 * The additive `coverage` object (contract v2). `historyWindow: 'forward-from'` says the index only holds
 * certificates logged since `indexStartedAt`, which no existing bv-mcp historyWindow value expresses.
 */
function coverageOf(meta: ReaderMeta, truncated: boolean) {
	return {
		source: COVERAGE_SOURCE,
		indexStartedAt: meta.indexStartedAt,
		freshThrough: meta.freshThrough,
		historyWindow: 'forward-from' as const,
		truncated,
	};
}

/** The reader's meta, or a throw when nothing was ever indexed: a never-populated index has measured nothing. */
function populated(meta: ReaderMeta): ReaderMeta {
	if (meta.indexStartedAt === null) throw new IndexNotReadyError('nothing indexed yet');
	return meta;
}

function isoOf(epochSeconds: number): string | null {
	const date = new Date(epochSeconds * 1000);
	return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

const LABEL = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$/;

/** A lowercase hostname with no wildcard, no trailing dot, labels of at most 63 characters; null when it is not one. */
export function parseDomain(raw: string | null): string | null {
	if (raw === null) return null;
	const domain = raw.trim().toLowerCase().replace(/\.$/, '');
	if (domain.length === 0 || domain.length > 253) return null;
	if (!domain.split('.').every((label) => label.length <= 63 && LABEL.test(label))) return null;
	try {
		nameKey(domain); // the codec's own storability check, so a name that parses here always has a key
	} catch {
		return null;
	}
	return domain;
}

async function enumerate(reader: IndexReader, domain: string, cursor: string | null) {
	const [page, meta] = await Promise.all([reader.scan(domain, { limit: PAGE_LIMIT, cursor }), reader.meta()]);
	populated(meta);
	// The index folds `*.x` into x with wildcard: true. bv-mcp counts wildcards from the `*.` prefix, so each
	// wildcard row also lists `*.x`; x itself stays listed because a cert may carry both.
	const subdomains = page.names.flatMap((row) => (row.wildcard ? [row.name, `*.${row.name}`] : [row.name]));
	return {
		domain,
		subdomains,
		// Distinct names read, not certificates: the index keeps one row per name.
		certificateCount: page.names.length,
		timedOut: false,
		cached: false,
		truncated: page.truncated,
		cursor: page.cursor,
		entries: page.names.map((row) => ({
			name: row.name,
			firstSeen: isoOf(row.firstSeen),
			notAfter: isoOf(row.notAfter),
			issuer: row.issuer,
			wildcard: row.wildcard,
		})),
		coverage: coverageOf(meta, page.truncated),
	};
}

async function sans(reader: IndexReader, domain: string) {
	// A public suffix such as govt.nz has no registrable apex, so no certificate has siblings of it.
	const apex = apexOf(domain);
	const [page, meta] = await Promise.all([
		apex === null
			? Promise.resolve({ siblings: [] as SiblingObservation[], truncated: false })
			: reader.siblings(apex, { limit: PAGE_LIMIT }),
		reader.meta(),
	]);
	populated(meta);
	return {
		domain,
		apex,
		names: page.siblings.map((row) => row.sibling),
		certificateCount: page.siblings.length,
		timedOut: false,
		cached: false,
		truncated: page.truncated,
		coverage: coverageOf(meta, page.truncated),
	};
}

async function certMeta(reader: IndexReader, domain: string) {
	const [page, meta] = await Promise.all([reader.scan(domain, { limit: 1 }), reader.meta()]);
	populated(meta);
	// The domain's own key sorts first in its range, so the first row is the exact name when it exists. It is
	// already merged across runs: the issuer is the one from the row with the largest notAfter.
	const exact = page.names.find((row) => row.name === domain);
	return {
		domain,
		issuer: exact?.issuer || null,
		firstSeen: exact ? isoOf(exact.firstSeen) : null,
		notAfter: exact ? isoOf(exact.notAfter) : null,
		wildcard: exact?.wildcard ?? false,
		coverage: coverageOf(meta, false),
	};
}

function withBudget<T>(work: Promise<T>, ms: number): Promise<T> {
	let timer: number | null = null;
	const deadline = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(new BudgetExceededError(`over ${ms} ms`)), ms);
	});
	work.catch(() => undefined); // the loser of the race must not surface as an unhandled rejection
	return Promise.race([work, deadline]).finally(() => clearTimeout(timer));
}

function failure(status: number, error: string): Response {
	return Response.json({ error }, { status });
}

function faultResponse(route: string, error: unknown): Response {
	if (error instanceof RangeError) return failure(400, `invalid_request: ${error.message}`);
	if (error instanceof BudgetExceededError) return failure(503, 'ct_index_timeout');
	if (error instanceof IndexNotReadyError) return failure(503, 'index_not_ready');
	console.error(JSON.stringify({ event: 'ct_index_api_fault', route, message: error instanceof Error ? error.message : String(error) }));
	return failure(503, 'ct_index_unavailable');
}

const ROUTES = new Set(['/enumerate', '/sans', '/cert-meta']);

/** Auth, routing and fault mapping for every path except /health (index.ts answers that one, unauthenticated). */
export async function handleApiRequest(request: Request, env: Pick<Env, 'CT_INDEX_ADMIN_KEY'>, deps: ApiDeps): Promise<Response> {
	if (!(await isAuthorized(request.headers.get('authorization'), env.CT_INDEX_ADMIN_KEY))) {
		return Response.json({ error: 'unauthorized' }, { status: 401, headers: { 'www-authenticate': 'Bearer' } });
	}
	const url = new URL(request.url);
	const route = url.pathname;
	if (!ROUTES.has(route)) return failure(404, 'not_found');
	if (request.method !== 'GET') return failure(405, 'method_not_allowed');
	const domain = parseDomain(url.searchParams.get('domain'));
	if (domain === null) return failure(400, 'invalid_request: domain must be a hostname');

	const { reader, budgetMs = API_BUDGET_MS } = deps;
	try {
		const work: Promise<object> =
			route === '/enumerate'
				? enumerate(reader, domain, url.searchParams.get('cursor'))
				: route === '/sans'
					? sans(reader, domain)
					: certMeta(reader, domain);
		return Response.json(await withBudget(work, budgetMs));
	} catch (error) {
		return faultResponse(route, error);
	}
}
