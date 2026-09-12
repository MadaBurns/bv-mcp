// SPDX-License-Identifier: BUSL-1.1

/**
 * Wildcard-DNS canary — record-family coverage and query budget (#942).
 *
 * WHY THIS FILE EXISTS.
 * The canary used to be a single `queryDNS(probeFqdn, 'A')`, and the `DNSQueryFunction`
 * projection FILTERS answers to the requested type. Two real wildcard shapes therefore
 * read as "no wildcard": a zone whose wildcard is AAAA-only, and a `*.zone CNAME
 * <dangling>` alias that yields no address (the A query's answer holds only the CNAME).
 * Both are fail-open in the expensive direction — a confident clean verdict for a zone
 * that answers for every name.
 *
 * The fix reads RAW answers (`rawQueryDNS`, which the Worker always supplies) and spends
 * the AAAA query ONLY when the A answer came back completely empty. These tests pin both
 * halves: the DETECTION (every family reaches the same one finding) and the BUDGET (the
 * v6 query is never issued on a zone whose A canary answered — `ns` is deliberately not a
 * bounded-parallelism candidate, and SCAN_DNS_CONCURRENCY is zero-sum across the 19 scan
 * categories, so an unconditional second query would be a real cost on every scan).
 *
 * The last case pins the fallback: `rawQueryDNS` is OPTIONAL, and direct package
 * consumers (bv-web-prod calls `checkNS` from the vendored tarball) may omit it. Those
 * callers must keep the historical A-only behaviour rather than degrade.
 *
 * Addresses are TEST-NET-2/TEST-NET-3 (RFC 5737) and 2001:db8::/32 (RFC 3849).
 */

import { describe, expect, it } from 'vitest';
import { checkNS } from '../../checks/check-ns';
import type { Finding, RawDNSResponse } from '../../types';

const RCODE_NOERROR = 0;
const DOMAIN = 'example.test';
const NS_RECORDS = ['ns1.provider-a.example', 'ns2.provider-b.example'];

const EMPTY: RawDNSResponse = { Status: RCODE_NOERROR, Answer: [] };
const NS_HOST_A_ANSWER = { type: 1, data: '198.51.100.53' };

interface ResolverOptions {
	/**
	 * DoH responses for the wildcard canary keyed by query TYPE (`raw[type]`); anything
	 * unlisted answers NOERROR/empty, the honest default for "no such record here".
	 */
	probe?: Partial<Record<string, RawDNSResponse>>;
	/** Canary answer for the `rawQueryDNS`-less fallback path, as the type-filtered projection sees it. */
	probeARecords?: string[];
	/** Omit `rawQueryDNS` entirely — the shape a direct package consumer may pass. */
	omitRaw?: boolean;
}

/**
 * Build a `checkNS` resolver pair. The canary label is random per call, so it is matched
 * by its `_bv-probe-` prefix rather than by an exact table key.
 */
function resolvers(opts: ResolverOptions = {}) {
	const queries: string[] = [];
	const queryDNS = (async (name: string, type: string) => {
		queries.push(`${type} ${name}`);
		if (type === 'NS' && name === DOMAIN) return NS_RECORDS;
		if (type === 'A' && name.startsWith('_bv-probe-')) return opts.probeARecords ?? [];
		return [];
	}) as never;
	const rawQueryDNS = (async (name: string, type: string): Promise<RawDNSResponse> => {
		queries.push(`${type} ${name}`);
		if (name.startsWith('_bv-probe-')) return opts.probe?.[type] ?? EMPTY;
		// Every delegated nameserver resolves — a healthy delegation. Lame delegation has
		// its own spec file and must not colour these cases.
		if (type === 'A' && NS_RECORDS.includes(name)) return { Status: RCODE_NOERROR, Answer: [NS_HOST_A_ANSWER] };
		return EMPTY;
	}) as never;
	return { queryDNS, rawQueryDNS: opts.omitRaw ? undefined : rawQueryDNS, queries };
}

function wildcardFinding(findings: Finding[]): Finding | undefined {
	return findings.find((f) => f.title === 'Wildcard DNS detected');
}

/** The canary's own queries, as `"<TYPE> <name>"`, in issue order. */
function canaryQueries(queries: string[]): string[] {
	return queries.filter((q) => q.includes('_bv-probe-')).map((q) => q.split(' ')[0]);
}

describe('wildcard canary record families (#942)', () => {
	it('detects an A wildcard and spends exactly one query', async () => {
		const { queryDNS, rawQueryDNS, queries } = resolvers({
			probe: { A: { Status: RCODE_NOERROR, Answer: [{ type: 1, data: '198.51.100.94' }] } },
		});

		const result = await checkNS(DOMAIN, queryDNS, { rawQueryDNS });
		const finding = wildcardFinding(result.findings);
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.metadata?.wildcardDetected).toBe(true);
		expect(finding!.metadata?.wildcardFamily).toBe('a');
		// The A answer settled it — no AAAA query.
		expect(canaryQueries(queries)).toEqual(['A']);
	});

	it('detects a dangling-CNAME wildcard from the A query it already issued', async () => {
		const { queryDNS, rawQueryDNS, queries } = resolvers({
			// A `*.zone CNAME gone.example.net` alias with no address: the type-filtered
			// projection returned `[]` here, so this shape used to read as "no wildcard".
			probe: { A: { Status: RCODE_NOERROR, Answer: [{ type: 5, data: 'gone.example.net.' }] } },
		});

		const result = await checkNS(DOMAIN, queryDNS, { rawQueryDNS });
		const finding = wildcardFinding(result.findings);
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.metadata?.wildcardFamily).toBe('cname');
		// Free: the CNAME rode in on the A answer.
		expect(canaryQueries(queries)).toEqual(['A']);
	});

	it('detects an AAAA-only wildcard, at the cost of one extra query', async () => {
		const { queryDNS, rawQueryDNS, queries } = resolvers({
			probe: { AAAA: { Status: RCODE_NOERROR, Answer: [{ type: 28, data: '2001:db8::94' }] } },
		});

		const result = await checkNS(DOMAIN, queryDNS, { rawQueryDNS });
		const finding = wildcardFinding(result.findings);
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
		expect(finding!.metadata?.wildcardFamily).toBe('aaaa');
		// SERIAL and CONDITIONAL: AAAA only after an empty A, never a parallel pair.
		expect(canaryQueries(queries)).toEqual(['A', 'AAAA']);
	});

	it('reports no wildcard when neither family answers, and stops at two queries', async () => {
		const { queryDNS, rawQueryDNS, queries } = resolvers();

		const result = await checkNS(DOMAIN, queryDNS, { rawQueryDNS });
		expect(wildcardFinding(result.findings)).toBeUndefined();
		expect(canaryQueries(queries)).toEqual(['A', 'AAAA']);
	});

	it('falls back to the A-only path when rawQueryDNS is omitted', async () => {
		const detected = resolvers({ omitRaw: true, probeARecords: ['198.51.100.94'] });
		const detectedResult = await checkNS(DOMAIN, detected.queryDNS, {});
		const finding = wildcardFinding(detectedResult.findings);
		expect(finding).toBeDefined();
		expect(finding!.metadata?.wildcardFamily).toBe('a');
		expect(canaryQueries(detected.queries)).toEqual(['A']);

		// ...and today's behaviour is preserved verbatim for the shapes the projection
		// hides: one A query, no finding, no AAAA probe a bare `DNSQueryFunction` consumer
		// never agreed to pay for.
		const absent = resolvers({ omitRaw: true });
		const absentResult = await checkNS(DOMAIN, absent.queryDNS, {});
		expect(wildcardFinding(absentResult.findings)).toBeUndefined();
		expect(canaryQueries(absent.queries)).toEqual(['A']);
	});
});
