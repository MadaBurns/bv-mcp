// SPDX-License-Identifier: BUSL-1.1

/**
 * Multi-resolver DNS querying for consistency checking.
 *
 * Queries multiple public DoH resolvers in parallel and compares
 * answer sets to detect GeoDNS, split-horizon, or poisoning.
 */

import type { DnsAnswer, DohResponse, RecordTypeName } from './dns-types';
import { RecordType } from './dns-types';

/** Public DoH resolver endpoints. */
export const RESOLVERS = [
	{ name: 'Cloudflare', endpoint: 'https://cloudflare-dns.com/dns-query' },
	{ name: 'Google', endpoint: 'https://dns.google/resolve' },
	{ name: 'Quad9', endpoint: 'https://dns.quad9.net:5053/dns-query' },
	{ name: 'OpenDNS', endpoint: 'https://doh.opendns.com/dns-query' },
] as const;

/** Per-resolver timeout (ms). */
const RESOLVER_TIMEOUT_MS = 3_000;

/** Overall multi-resolver query timeout (ms). */
const MULTI_RESOLVER_TIMEOUT_MS = 5_000;

/** Result from a single resolver query. */
export interface ResolverAnswer {
	resolver: string;
	status: 'ok' | 'error' | 'timeout';
	answers: string[];
	ttl?: number;
}

/** Consistency classification for a record type. */
export type ConsistencyStatus = 'CONSISTENT' | 'SPLIT_HORIZON' | 'INCOMPLETE' | 'SUSPICIOUS';

/** Result from a multi-resolver consistency check for one record type. */
export interface ConsistencyResult {
	recordType: RecordTypeName;
	status: ConsistencyStatus;
	resolverAnswers: ResolverAnswer[];
	detail: string;
}

/** Build a DoH URL for a given endpoint, domain, and type. */
function buildUrl(endpoint: string, domain: string, type: RecordTypeName): string {
	const params = new URLSearchParams({ name: domain, type });
	return `${endpoint}?${params.toString()}`;
}

/** Fetch a DoH response from a single resolver with timeout. */
async function fetchResolver(
	resolverName: string,
	endpoint: string,
	domain: string,
	type: RecordTypeName,
): Promise<ResolverAnswer> {
	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), RESOLVER_TIMEOUT_MS);

	try {
		const url = buildUrl(endpoint, domain, type);
		const response = await fetch(url, {
			method: 'GET',
			headers: { Accept: 'application/dns-json' },
			signal: controller.signal,
		});

		if (!response.ok) {
			return { resolver: resolverName, status: 'error', answers: [] };
		}

		const data = await response.json() as DohResponse;
		if (typeof data?.Status !== 'number') {
			return { resolver: resolverName, status: 'error', answers: [] };
		}

		const typeCode = RecordType[type];
		const answers = (data.Answer ?? [])
			.filter((a: DnsAnswer) => a.type === typeCode)
			.map((a: DnsAnswer) => a.data.replace(/\.$/, '').toLowerCase())
			.sort();

		const ttl = data.Answer?.[0]?.TTL;

		return { resolver: resolverName, status: 'ok', answers, ttl };
	} catch {
		return { resolver: resolverName, status: 'timeout', answers: [] };
	} finally {
		clearTimeout(timeout);
	}
}

/** Classify consistency from resolver answers. */
function classifyConsistency(resolverAnswers: ResolverAnswer[], type: RecordTypeName): { status: ConsistencyStatus; detail: string } {
	const okAnswers = resolverAnswers.filter((r) => r.status === 'ok');
	const failedCount = resolverAnswers.length - okAnswers.length;

	if (okAnswers.length === 0) {
		return { status: 'INCOMPLETE', detail: `All ${resolverAnswers.length} resolvers failed to respond for ${type} records.` };
	}

	if (okAnswers.length === 1) {
		return { status: 'INCOMPLETE', detail: `Only 1 of ${resolverAnswers.length} resolvers responded for ${type} records.` };
	}

	// Normalize and compare answer sets
	const answerSets = okAnswers.map((r) => JSON.stringify(r.answers));
	const uniqueSets = new Set(answerSets);

	if (uniqueSets.size === 1) {
		const emptyResult = okAnswers[0].answers.length === 0;
		if (emptyResult) {
			return { status: 'CONSISTENT', detail: `No ${type} records found — all ${okAnswers.length} resolvers agree.` };
		}
		if (failedCount > 0) {
			return { status: 'CONSISTENT', detail: `${okAnswers.length} of ${resolverAnswers.length} resolvers returned identical ${type} records (${failedCount} unreachable).` };
		}
		return { status: 'CONSISTENT', detail: `All ${okAnswers.length} resolvers returned identical ${type} records.` };
	}

	// Check if the difference is just some resolvers having empty results
	const nonEmpty = okAnswers.filter((r) => r.answers.length > 0);
	const empty = okAnswers.filter((r) => r.answers.length === 0);

	if (empty.length > 0 && nonEmpty.length > 0) {
		const nonEmptySets = new Set(nonEmpty.map((r) => JSON.stringify(r.answers)));
		if (nonEmptySets.size === 1) {
			const emptyResolvers = empty.map((r) => r.resolver).join(', ');
			return {
				status: 'INCOMPLETE',
				detail: `${type} records missing from ${emptyResolvers} but present in ${nonEmpty.length} other resolvers. Possible propagation delay or blocking.`,
			};
		}
	}

	// Multiple different non-empty answer sets
	if (uniqueSets.size === 2) {
		return {
			status: 'SPLIT_HORIZON',
			detail: `${type} records differ between resolvers — likely GeoDNS or CDN steering. ${okAnswers.length} resolvers returned ${uniqueSets.size} distinct answer sets.`,
		};
	}

	// More than 2 different results — suspicious
	if (uniqueSets.size >= 3) {
		return {
			status: 'SUSPICIOUS',
			detail: `${type} records show ${uniqueSets.size} distinct answer sets across ${okAnswers.length} resolvers — unusual divergence. Possible DNS poisoning or misconfiguration.`,
		};
	}

	return {
		status: 'SPLIT_HORIZON',
		detail: `${type} records differ between resolvers (${uniqueSets.size} distinct sets).`,
	};
}

/**
 * Query multiple DoH resolvers for a domain and record type, comparing answers.
 *
 * @param domain - Domain to query
 * @param type - DNS record type
 * @returns Consistency result with per-resolver answers
 */
export async function queryMultiResolver(
	domain: string,
	type: RecordTypeName,
): Promise<ConsistencyResult> {
	const queries = RESOLVERS.map((r) =>
		fetchResolver(r.name, r.endpoint, domain, type),
	);

	const resolverAnswers = await Promise.race([
		Promise.all(queries),
		new Promise<ResolverAnswer[]>((resolve) =>
			setTimeout(() => {
				// Return whatever has completed so far
				resolve(
					Promise.all(
						queries.map((q) =>
							Promise.race([
								q,
								new Promise<ResolverAnswer>((r) =>
									setTimeout(() => r({ resolver: 'unknown', status: 'timeout', answers: [] }), 0),
								),
							]),
						),
					),
				);
			}, MULTI_RESOLVER_TIMEOUT_MS),
		),
	]);

	const { status, detail } = classifyConsistency(resolverAnswers, type);

	return { recordType: type, status, resolverAnswers, detail };
}

/**
 * Run multi-resolver consistency checks across multiple record types.
 *
 * @param domain - Domain to check
 * @param types - Record types to check (default: A, AAAA, MX, TXT, NS)
 * @returns Array of consistency results per record type
 */
export async function checkMultiResolverConsistency(
	domain: string,
	types: RecordTypeName[] = ['A', 'AAAA', 'MX', 'TXT', 'NS'],
): Promise<ConsistencyResult[]> {
	// Run all record type queries in parallel
	const results = await Promise.all(
		types.map((type) => queryMultiResolver(domain, type)),
	);

	return results;
}
