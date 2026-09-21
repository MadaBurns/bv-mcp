// SPDX-License-Identifier: BUSL-1.1

/**
 * Root-server-set lane: fills `RootServerSetEvidence` from live queries against
 * a rotating sample of the 13 `ROOT_HINTS` servers, over one direct TCP session
 * per (root, address-family) pair. Mirrors the dependency-injection and
 * evidence-shape discipline of `delegation-probe.ts`'s `probeDelegationConsistency`.
 */

import { RecordType } from '../dns-types';
import { isGloballyRoutableIp, openDnsTcpSession, type DirectDnsResponse, type DnsTcpSessionFactory } from './dns-tcp';
import { ROOT_HINTS, ROOT_SERVER_NAMES } from './root-hints';
import type { RootServerSetEvidence } from './types';

/** How many of the 13 `ROOT_HINTS` entries this lane samples per call. */
const ROOT_SAMPLE_SIZE = 3;
/**
 * Max simultaneous TCP sessions. Story contract addendum (2026-09-21, binding,
 * amends frozen decisions 1 and 9): Cloudflare Workers cap simultaneous outgoing
 * connections at 6, shared with the calling MCP Worker and this sidecar's own DoH
 * fetches; capping at 4 here leaves headroom rather than exhausting the budget.
 */
const MAX_CONCURRENT_SESSIONS = 4;
/** Whole-lane deadline; shrinks the per-session timeout as sessions queue behind the concurrency cap. */
const DEFAULT_BUDGET_MS = 4000;
/**
 * Textual root-zone name. `dns-tcp.ts`'s `encodeName` used to throw on any name
 * that normalizes to the empty string, so a query for the literal root ('.')
 * always threw through the real `openDnsTcpSession` — fixed by e1155ee72
 * (single zero-length terminating octet, no labels), so this lane can now
 * successfully query a live root server.
 */
const ROOT_ZONE_NAME = '.';

type RootHintEntry = (typeof ROOT_HINTS)[number];
type Family = 'ipv4' | 'ipv6';

interface RootZoneQueryResult {
	ns?: DirectDnsResponse;
	soa?: DirectDnsResponse;
	dnskey?: DirectDnsResponse;
	/** True as soon as any of the three queries on this session returned a parsed response, regardless of rcode/AA. */
	answered: boolean;
}

interface RootSessionAttempt {
	rootName: string;
	family: Family;
	result: RootZoneQueryResult;
}

const ROOT_ZONE_QUERIES: readonly (readonly [key: 'ns' | 'soa' | 'dnskey', type: number])[] = [
	['ns', RecordType.NS],
	['soa', RecordType.SOA],
	['dnskey', RecordType.DNSKEY],
];

export interface RootSetProbeDependencies {
	/** Structurally compatible with `AuthoritativeProbeDependencies['openSession']` (SQ-126). */
	openSession?: DnsTcpSessionFactory;
	now?: () => Date;
}

export interface RootSetProbeOptions {
	budgetMs?: number;
}

function normalizeName(name: string): string {
	return name.replace(/\.$/, '').toLowerCase();
}

function uniqueSorted(values: string[]): string[] {
	return [...new Set(values.map(normalizeName).filter(Boolean))].sort();
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
	if (a.length !== b.length) return false;
	const normalizedB = new Set(b.map(normalizeName));
	return a.every((value) => normalizedB.has(normalizeName(value)));
}

/** Deterministic 3-of-13 sample, rotating by UTC hour so every root gets covered across a day. */
function sampleRoots(now: Date): RootHintEntry[] {
	const start = now.getUTCHours() % ROOT_HINTS.length;
	return Array.from({ length: ROOT_SAMPLE_SIZE }, (_, offset) => ROOT_HINTS[(start + offset) % ROOT_HINTS.length]);
}

async function runWithConcurrency<T>(factories: Array<() => Promise<T>>, limit: number): Promise<T[]> {
	const results: T[] = new Array(factories.length);
	let cursor = 0;
	const worker = async (): Promise<void> => {
		while (cursor < factories.length) {
			const index = cursor++;
			results[index] = await factories[index]();
		}
	};
	await Promise.all(Array.from({ length: Math.min(limit, factories.length) }, worker));
	return results;
}

async function runSession(
	openSession: DnsTcpSessionFactory,
	rootName: string,
	address: string,
	family: Family,
	deadline: number,
): Promise<RootSessionAttempt> {
	const remainingMs = deadline - Date.now();
	if (remainingMs <= 0 || !isGloballyRoutableIp(address)) {
		return { rootName, family, result: { answered: false } };
	}
	try {
		const session = await openSession(address, remainingMs);
		try {
			const result: RootZoneQueryResult = { answered: false };
			for (const [key, type] of ROOT_ZONE_QUERIES) {
				try {
					const response = await session.query(ROOT_ZONE_NAME, type, { dnssecOk: true });
					result[key] = response;
					result.answered = true;
				} catch {
					// Leave this query's field undefined; the session's other queries may still succeed.
				}
			}
			return { rootName, family, result };
		} finally {
			await session.close();
		}
	} catch {
		return { rootName, family, result: { answered: false } };
	}
}

function rootNsNames(response: DirectDnsResponse): string[] {
	return uniqueSorted(
		[...response.answers, ...response.authority].filter((record) => record.type === RecordType.NS && record.data).map((record) => record.data),
	);
}

/** NS names of `.` from an AA=1 answer only — "nothing verdict-shaped without an AA=1 answer behind it". */
function extractAa1NsNames(rootAttempts: RootSessionAttempt[]): string[] | undefined {
	for (const attempt of rootAttempts) {
		const response = attempt.result.ns;
		if (response?.aa !== true) continue;
		const names = rootNsNames(response);
		if (names.length > 0) return names;
	}
	return undefined;
}

function extractAa1SoaSerial(rootAttempts: RootSessionAttempt[]): number | undefined {
	for (const attempt of rootAttempts) {
		const response = attempt.result.soa;
		if (response?.aa !== true) continue;
		const record = [...response.answers, ...response.authority].find((entry) => entry.type === RecordType.SOA && entry.data);
		if (!record) continue;
		const serial = Number(record.data);
		if (Number.isFinite(serial)) return serial;
	}
	return undefined;
}

/**
 * Union the per-root NS-name sets when every sampled root that answered agrees;
 * otherwise report one of the sets that actually diverges from the canonical
 * 13-name list, so the analyzer's `sameStringSet` comparison fails it instead of
 * masking a real disagreement behind an accidental union that happens to match.
 */
function combineObservedRootServers(perRootSets: string[][]): string[] | undefined {
	if (perRootSets.length === 0) return undefined;
	const allIdentical = perRootSets.every((set) => sameSet(set, perRootSets[0]));
	if (allIdentical) return uniqueSorted(perRootSets.flatMap((set) => set));
	return perRootSets.find((set) => !sameSet(set, ROOT_SERVER_NAMES)) ?? perRootSets[0];
}

function expandIpv6(address: string): string {
	const lower = address.trim().toLowerCase();
	const halves = lower.split('::');
	const expandSide = (side: string): string[] => (side ? side.split(':') : []);
	if (halves.length === 1) return expandSide(halves[0]).map((group) => group.padStart(4, '0')).join(':');
	const left = expandSide(halves[0]);
	const right = expandSide(halves[1]);
	const missing = Math.max(0, 8 - left.length - right.length);
	return [...left, ...Array(missing).fill('0'), ...right].map((group) => group.padStart(4, '0')).join(':');
}

function addressEquals(actual: string, expected: string, type: number): boolean {
	if (type === RecordType.A) return actual.trim() === expected.trim();
	return expandIpv6(actual) === expandIpv6(expected);
}

/**
 * Every A/AAAA glue record in an AA=1 response's additional section, for a
 * name that matches a root server, must equal that name's official
 * ROOT_HINTS address. `undefined` when no glue was returned at all — TCP
 * responses may legitimately omit it.
 */
function checkGlueMatchesHints(attempts: RootSessionAttempt[]): boolean | undefined {
	const hintsByName = new Map<string, RootHintEntry>(ROOT_HINTS.map((hint) => [hint.name, hint]));
	let sawGlue = false;
	let allMatch = true;
	for (const attempt of attempts) {
		for (const response of [attempt.result.ns, attempt.result.soa, attempt.result.dnskey]) {
			if (!response || response.aa !== true) continue;
			for (const record of response.additional) {
				if (record.type !== RecordType.A && record.type !== RecordType.AAAA) continue;
				const hint = hintsByName.get(normalizeName(record.name));
				if (!hint) continue;
				sawGlue = true;
				const expected = record.type === RecordType.A ? hint.ipv4 : hint.ipv6;
				if (!addressEquals(record.data, expected, record.type)) allMatch = false;
			}
		}
	}
	return sawGlue ? allMatch : undefined;
}

export async function probeRootServerSet(
	deps: RootSetProbeDependencies = {},
	options: RootSetProbeOptions = {},
): Promise<RootServerSetEvidence> {
	const now = deps.now ?? (() => new Date());
	const openSession = deps.openSession ?? openDnsTcpSession;
	const budgetMs = options.budgetMs ?? DEFAULT_BUDGET_MS;
	const checkedAt = now().toISOString();
	const rootHints = [...ROOT_HINTS];
	const sampled = sampleRoots(now());
	const deadline = Date.now() + budgetMs;

	const tasks = sampled.flatMap((root) => [
		() => runSession(openSession, root.name, root.ipv4, 'ipv4', deadline),
		() => runSession(openSession, root.name, root.ipv6, 'ipv6', deadline),
	]);

	const attempts = await runWithConcurrency(tasks, MAX_CONCURRENT_SESSIONS);
	const anyAnswered = attempts.some((attempt) => attempt.result.answered);

	if (!anyAnswered) {
		return { hostname: '.', checkedAt, rootHints, errors: ['root_server_set_probe_no_contact'] };
	}

	// A session can "answer" (a TCP response was parsed) without that response being
	// authoritative — a middlebox transparently intercepting TCP/53 answers too. A single
	// vantage cannot distinguish that from a genuine root server, so "contact" for this
	// lane means an AA=1 answer, not merely a parsed TCP response (orchestrator live-smoke
	// finding, comment c_mubkwv04_a0fee8: an intercepted network answered REFUSED/AA=0/RA=1
	// and the lane returned no evidence AND no errors, which `analyzeRootServerSetEvidence`
	// then read as a self-consistent hints match and published a fabricated pass).
	const anyAuthoritative = attempts.some(
		(attempt) => attempt.result.ns?.aa === true || attempt.result.soa?.aa === true || attempt.result.dnskey?.aa === true,
	);
	if (!anyAuthoritative) {
		return { hostname: '.', checkedAt, rootHints, errors: ['root_server_set_probe_no_authoritative_answer'] };
	}

	const byRoot = new Map<string, RootSessionAttempt[]>();
	for (const attempt of attempts) {
		const existing = byRoot.get(attempt.rootName);
		if (existing) existing.push(attempt);
		else byRoot.set(attempt.rootName, [attempt]);
	}

	const perRootNsSets: string[][] = [];
	const serialsByRoot: Record<string, number> = {};
	for (const root of sampled) {
		const rootAttempts = byRoot.get(root.name) ?? [];
		const nsNames = extractAa1NsNames(rootAttempts);
		if (nsNames) perRootNsSets.push(nsNames);
		const serial = extractAa1SoaSerial(rootAttempts);
		if (serial !== undefined) serialsByRoot[root.name] = serial;
	}

	const observedRootServers = combineObservedRootServers(perRootNsSets);
	const parentChildDelegationMatches = perRootNsSets.length < 2 ? undefined : perRootNsSets.every((set) => sameSet(set, perRootNsSets[0]));
	const glueMatchesHints = checkGlueMatchesHints(attempts);

	return {
		hostname: '.',
		checkedAt,
		rootHints,
		observedRootServers,
		parentChildDelegationMatches,
		glueMatchesHints,
		...(Object.keys(serialsByRoot).length > 0 ? { serialsByRoot } : {}),
	};
}
