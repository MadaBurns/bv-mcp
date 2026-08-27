// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { FetchFunction } from './types';
import { readResponseTextCapped } from './response-body';

/**
 * Identifying User-Agent sent on every outbound request this package makes to a
 * scanned domain's own web server (HTTP/TLS checks, BIMI logo fetch, MTA-STS
 * policy fetch, subdomain-takeover probe). See /bot-policy on
 * blackveilsecurity.com — this is the SSOT the page's copy is derived from.
 */
export const SCANNER_USER_AGENT =
	'BlackVeil-Security-Scanner/1.0 (+https://www.blackveilsecurity.com/bot-policy; security@blackveilsecurity.com)';

const ROBOTS_FETCH_TIMEOUT_MS = 3_000;

/** Maximum robots.txt bytes retained for parsing. */
export const ROBOTS_MAX_BODY_BYTES = 512 * 1024;

/** Strict logical retained-byte ceiling for one robots decision cache. */
export const ROBOTS_CACHE_MAX_BYTES = 4 * 1024 * 1024;

const DEFAULT_ROBOTS_CACHE_MAX_ENTRIES = 256;
const DEFAULT_ROBOTS_CACHE_TTL_MS = 5 * 60_000;
const ROBOTS_CACHE_ENTRY_OVERHEAD_BYTES = 256;
const ROBOTS_CACHE_GROUP_OVERHEAD_BYTES = 128;
const ROBOTS_CACHE_AGENT_OVERHEAD_BYTES = 32;
const ROBOTS_CACHE_RULE_OVERHEAD_BYTES = 64;
// A pending fetch can decode a max-sized body to UTF-16 and retain a selected
// rule string of the same length. Reserve both until its exact outcome settles.
const ROBOTS_CACHE_PENDING_BODY_BYTES = ROBOTS_MAX_BODY_BYTES * 4;

/**
 * Which robots.txt group produced the disallow.
 * - `blanket` — a `User-agent: *` group. The site blocks EVERY crawler and has
 *   said nothing about us specifically. This is the overwhelmingly common case.
 * - `named`  — a group whose `User-agent` list contains our own product token,
 *   i.e. the operator deliberately singled this scanner out.
 *
 * The distinction is user-visible: attributing a blanket block to us by name
 * misrepresents an ordinary site-wide no-crawl policy as a targeted one.
 */
export type RobotsDisallowScope = 'blanket' | 'named';

/** Thrown by a `withRobotsGate`-wrapped fetch when the target's robots.txt disallows our UA for the requested path. */
export class RobotsDisallowedError extends Error {
	constructor(
		public readonly url: string,
		/**
		 * Defaults to `blanket`, the non-accusatory reading: absent positive
		 * evidence that a site named this scanner, never claim that it did.
		 */
		public readonly scope: RobotsDisallowScope = 'blanket',
	) {
		super(
			scope === 'named'
				? `robots.txt names and disallows BlackVeil-Security-Scanner for ${url}`
				: `robots.txt disallows all crawlers (User-agent: *) for ${url}`,
		);
		this.name = 'RobotsDisallowedError';
	}
}

/**
 * The clause a finding uses to describe WHO a robots.txt block applies to.
 * Kept here, next to the scope it renders, so the three checks that abstain on
 * a robots block cannot drift into three different accounts of the same fact.
 */
export function describeRobotsScope(scope: RobotsDisallowScope): string {
	return scope === 'named' ? 'disallows BlackVeil-Security-Scanner by name' : 'disallows all automated crawlers';
}

/**
 * Metadata stamped on every finding produced by a robots.txt abstention.
 *
 * `notAssessedReason` exists because `checkStatus` cannot express this: its
 * union is `'completed' | 'timeout' | 'error'`, so a deliberate, polite
 * abstention is reported with the same token as a probe that genuinely broke.
 * Widening that union is a breaking change for downstream consumers (which
 * compare it by equality and cast it into their own unions), so the
 * distinction is carried additively here instead.
 *
 * `confidence` is pinned rather than left to `inferFindingConfidence`, whose
 * fallback classifies a finding by keyword-scanning its own title and detail —
 * a copy edit must never be able to silently reclassify an abstention.
 */
export function robotsAbstentionMetadata(scope: RobotsDisallowScope): {
	notAssessedReason: 'robots_disallowed';
	robotsScope: RobotsDisallowScope;
	confidence: 'deterministic';
} {
	return { notAssessedReason: 'robots_disallowed', robotsScope: scope, confidence: 'deterministic' };
}

/**
 * Which branch of the gate decided a single gated request (issue #745).
 *
 * The gate is FAIL-OPEN on any unusable robots.txt, which is deliberate — a
 * broken or unreachable robots.txt must never itself block a scan. But that
 * makes a scan's verdict depend on whether the target's web server answered
 * inside a ~3s window, and until now nothing recorded which branch fired: a
 * scored result and an abstention for the same domain were indistinguishable
 * after the fact. These tokens are that record.
 *
 * - `allowed`     — robots.txt was fetched and read, and nothing in it disallows
 *                   the requested path. A positive, reproducible measurement.
 * - `disallowed`  — fetched and read; the path is disallowed (the abstention
 *                   path, already described by {@link RobotsDisallowScope}).
 * - `no_policy`   — the origin answered definitively that there is no robots.txt
 *                   (404/410). Also reproducible: the site published no policy.
 * - `unreachable` — the fetch failed or the origin returned an error status, so
 *                   the policy is UNKNOWN and the request proceeded fail-open.
 * - `timeout`     — the robots.txt fetch exceeded `timeoutMs`; policy unknown,
 *                   proceeded fail-open.
 *
 * Only `unreachable` and `timeout` are fail-open guesses — see
 * {@link RobotsResolutionRecord.failOpen}.
 */
export type RobotsResolution = 'allowed' | 'disallowed' | 'no_policy' | 'unreachable' | 'timeout';

/** One gated request's robots.txt decision, with enough provenance to reproduce it. */
export interface RobotsResolutionRecord {
	/** Hostname whose robots.txt governed the request. */
	host: string;
	/** Path that was evaluated against the policy. */
	path: string;
	/** Which branch fired — see {@link RobotsResolution}. */
	resolution: RobotsResolution;
	/**
	 * True when the policy could NOT be read and the request proceeded anyway.
	 * This is the single field that distinguishes "we know we were allowed" from
	 * "we never found out": two scans of the same domain that differ only here
	 * are not comparable, and this makes that visible in the stored record.
	 */
	failOpen: boolean;
	/** HTTP status of the robots.txt fetch, when one was received at all. */
	status?: number;
	/** Which group matched, when a policy was read and a group applied to us. */
	scope?: RobotsDisallowScope;
	/** `error.name` of the failed robots.txt fetch (`unreachable`/`timeout` only). */
	errorName?: string;
}

/** Outcome of resolving one host's robots.txt — memoized per host inside the gate. */
type RobotsOutcome =
	| { kind: 'policy'; selected: SelectedGroup | null; status: number; sourceLength: number }
	| { kind: 'no_policy'; status: number }
	| { kind: 'unreachable'; status?: number; errorName?: string }
	| { kind: 'timeout'; errorName: string };

/** Statuses that mean "this origin has no robots.txt", as opposed to "we could not read it". */
const ABSENT_ROBOTS_STATUSES = new Set([404, 410]);

/**
 * Opaque, caller-owned robots.txt decision cache.
 *
 * Exists so a caller can build a FRESH gate per invocation (which is what makes
 * per-invocation provenance possible — {@link WithRobotsGateOptions.onRobotsResolution}
 * is a construction-time callback) without giving up the cross-invocation
 * memoization an isolate-lifetime gate used to provide. Entries are internal to
 * this module; never read or construct them yourself.
 */
export interface RobotsGroupCache {
	readonly entries: Map<string, Promise<unknown>>;
}

export interface CreateRobotsGroupCacheOptions {
	/** Maximum host/namespace entries retained. Defaults to 256. */
	maxEntries?: number;
	/** Strict retained policy budget in bytes. Defaults to 4 MiB. */
	maxBytes?: number;
	/** Entry lifetime in milliseconds. Defaults to five minutes. */
	ttlMs?: number;
	/** Clock injection for deterministic tests. */
	now?: () => number;
}

interface RobotsGroupCacheState {
	readonly maxEntries: number;
	readonly maxBytes: number;
	readonly ttlMs: number;
	readonly now: () => number;
	readonly expiresAt: Map<string, number>;
	readonly weights: Map<string, number>;
	retainedBytes: number;
}

const ROBOTS_GROUP_CACHE_STATE = new WeakMap<RobotsGroupCache, RobotsGroupCacheState>();

/** Create a bounded TTL/LRU cache. Share one instance across gates that should share fetches. */
export function createRobotsGroupCache(options: CreateRobotsGroupCacheOptions = {}): RobotsGroupCache {
	const maxEntries = options.maxEntries ?? DEFAULT_ROBOTS_CACHE_MAX_ENTRIES;
	const maxBytes = options.maxBytes ?? ROBOTS_CACHE_MAX_BYTES;
	const ttlMs = options.ttlMs ?? DEFAULT_ROBOTS_CACHE_TTL_MS;
	if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) throw new RangeError('maxEntries must be a positive safe integer');
	if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new RangeError('maxBytes must be a positive safe integer');
	if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new RangeError('ttlMs must be positive');
	const cache: RobotsGroupCache = { entries: new Map() };
	ROBOTS_GROUP_CACHE_STATE.set(cache, {
		maxEntries,
		maxBytes,
		ttlMs,
		now: options.now ?? Date.now,
		expiresAt: new Map(),
		weights: new Map(),
		retainedBytes: 0,
	});
	return cache;
}

function getRobotsGroupCacheState(cache: RobotsGroupCache): RobotsGroupCacheState {
	let state = ROBOTS_GROUP_CACHE_STATE.get(cache);
	if (!state) {
		state = {
			maxEntries: DEFAULT_ROBOTS_CACHE_MAX_ENTRIES,
			maxBytes: ROBOTS_CACHE_MAX_BYTES,
			ttlMs: DEFAULT_ROBOTS_CACHE_TTL_MS,
			now: Date.now,
			expiresAt: new Map(),
			weights: new Map(),
			retainedBytes: 0,
		};
		ROBOTS_GROUP_CACHE_STATE.set(cache, state);
	}
	return state;
}

function pendingCacheWeight(key: string): number {
	return ROBOTS_CACHE_ENTRY_OVERHEAD_BYTES + key.length * 2 + ROBOTS_CACHE_PENDING_BODY_BYTES;
}

function deleteCacheEntry(cache: RobotsGroupCache, state: RobotsGroupCacheState, key: string, expected?: Promise<unknown>): boolean {
	if (expected && cache.entries.get(key) !== expected) return false;
	const deleted = cache.entries.delete(key);
	if (!deleted) return false;
	state.retainedBytes = Math.max(0, state.retainedBytes - (state.weights.get(key) ?? 0));
	state.weights.delete(key);
	state.expiresAt.delete(key);
	return true;
}

/** Reconcile opaque-map mutations, TTL expiry, count, and bytes before every operation. */
function reconcileCacheState(cache: RobotsGroupCache, state: RobotsGroupCacheState, now: number): void {
	for (const key of state.weights.keys()) {
		if (!cache.entries.has(key)) {
			state.retainedBytes = Math.max(0, state.retainedBytes - (state.weights.get(key) ?? 0));
			state.weights.delete(key);
			state.expiresAt.delete(key);
		}
	}
	for (const key of cache.entries.keys()) {
		if (!state.weights.has(key)) {
			const weight = pendingCacheWeight(key);
			state.weights.set(key, weight);
			state.retainedBytes += weight;
		}
		if (!state.expiresAt.has(key)) state.expiresAt.set(key, now + state.ttlMs);
	}
	for (const key of cache.entries.keys()) {
		if ((state.expiresAt.get(key) ?? 0) <= now) deleteCacheEntry(cache, state, key);
	}
	while (cache.entries.size > state.maxEntries || state.retainedBytes > state.maxBytes) {
		const oldest = cache.entries.keys().next().value;
		if (oldest === undefined) break;
		deleteCacheEntry(cache, state, oldest);
	}
}

export interface RobotsGroupCacheStats {
	entries: number;
	retainedBytes: number;
	maxEntries: number;
	maxBytes: number;
}

/** Inspect the cache's enforced logical byte/count bounds; also prunes expired entries. */
export function getRobotsGroupCacheStats(cache: RobotsGroupCache): RobotsGroupCacheStats {
	const state = getRobotsGroupCacheState(cache);
	reconcileCacheState(cache, state, state.now());
	return {
		entries: cache.entries.size,
		retainedBytes: state.retainedBytes,
		maxEntries: state.maxEntries,
		maxBytes: state.maxBytes,
	};
}

interface RobotsRule {
	path: string;
	allow: boolean;
}

interface RobotsGroup {
	agents: string[];
	rules: RobotsRule[];
}

/**
 * Parse a robots.txt body into `User-agent` groups (RFC 9309 §2.1-2.2). Unknown
 * directives (Crawl-delay, Sitemap, Host, ...) are ignored — only User-agent /
 * Allow / Disallow are recognized, which is all the opt-out claim depends on.
 * Consecutive `User-agent:` lines with no intervening rule belong to the SAME
 * group (the standard "these agents share these rules" idiom).
 */
export function parseRobotsGroups(text: string): RobotsGroup[] {
	const groups: RobotsGroup[] = [];
	let current: RobotsGroup | null = null;
	let sawRuleSinceAgent = true;

	for (const rawLine of text.split(/\r\n|\r|\n/)) {
		const line = rawLine.split('#', 1)[0]!.trim();
		if (!line) continue;
		const colonIndex = line.indexOf(':');
		if (colonIndex === -1) continue;
		const field = line.slice(0, colonIndex).trim().toLowerCase();
		const value = line.slice(colonIndex + 1).trim();

		if (field === 'user-agent') {
			if (!current || sawRuleSinceAgent) {
				current = { agents: [], rules: [] };
				groups.push(current);
				sawRuleSinceAgent = false;
			}
			current.agents.push(value.toLowerCase());
		} else if (field === 'allow' || field === 'disallow') {
			if (!current) continue;
			current.rules.push({ path: value, allow: field === 'allow' });
			sawRuleSinceAgent = true;
		}
	}

	return groups;
}

/** A selected group plus how it was selected — see {@link RobotsDisallowScope}. */
interface SelectedGroup {
	group: RobotsGroup;
	scope: RobotsDisallowScope;
}

/** Most-specific group for `userAgentToken` (an exact agent-token match beats the `*` fallback). Null = no group applies. */
function selectGroup(groups: RobotsGroup[], userAgentToken: string): SelectedGroup | null {
	const named = groups.find((g) => g.agents.includes(userAgentToken));
	if (named) return { group: named, scope: 'named' };
	const wildcard = groups.find((g) => g.agents.includes('*'));
	return wildcard ? { group: wildcard, scope: 'blanket' } : null;
}

/** Conservative logical heap weight for one settled cache entry. */
function settledCacheWeight(key: string, outcome: RobotsOutcome): number {
	let bytes = ROBOTS_CACHE_ENTRY_OVERHEAD_BYTES + key.length * 2;
	if (outcome.kind !== 'policy' || !outcome.selected) return bytes;

	// Charge the full decoded source because engine substring representations may
	// retain it, then separately charge selected strings and collection objects.
	bytes += outcome.sourceLength * 2 + ROBOTS_CACHE_GROUP_OVERHEAD_BYTES;
	for (const agent of outcome.selected.group.agents) {
		bytes += ROBOTS_CACHE_AGENT_OVERHEAD_BYTES + agent.length * 2;
	}
	for (const rule of outcome.selected.group.rules) {
		bytes += ROBOTS_CACHE_RULE_OVERHEAD_BYTES + rule.path.length * 2;
	}
	return bytes;
}

/** Compare one literal pattern chunk at an exact UTF-16 offset. */
function literalMatchesAt(value: string, literal: string, start: number): boolean {
	if (start < 0 || start + literal.length > value.length) return false;
	for (let index = 0; index < literal.length; index += 1) {
		if (value.charCodeAt(start + index) !== literal.charCodeAt(index)) return false;
	}
	return true;
}

/**
 * Find a non-empty literal chunk within `[start, end)` using Knuth-Morris-Pratt.
 * The failure table and scan are both linear; no path character is revisited by
 * a wildcard backtracking engine.
 */
function findLiteral(value: string, literal: string, start: number, end: number): number {
	if (literal.length > end - start) return -1;

	const failure = new Uint32Array(literal.length);
	let matched = 0;
	for (let index = 1; index < literal.length; index += 1) {
		const current = literal.charCodeAt(index);
		while (matched > 0 && current !== literal.charCodeAt(matched)) {
			matched = failure[matched - 1]!;
		}
		if (current === literal.charCodeAt(matched)) matched += 1;
		failure[index] = matched;
	}

	matched = 0;
	for (let index = start; index < end; index += 1) {
		const current = value.charCodeAt(index);
		while (matched > 0 && current !== literal.charCodeAt(matched)) {
			matched = failure[matched - 1]!;
		}
		if (current === literal.charCodeAt(matched)) matched += 1;
		if (matched === literal.length) return index - literal.length + 1;
	}
	return -1;
}

/**
 * Match robots.txt path syntax without compiling attacker-controlled regular
 * expressions. Patterns are anchored at the start, `*` matches any sequence,
 * and only a terminal `$` anchors the end; without `$`, a matched prefix wins.
 *
 * Literal chunks are disjoint and found in order with KMP. Their failure tables
 * total O(pattern.length), while the monotonically advancing cursor scans at
 * most O(path.length), so even hostile wildcard patterns run in linear time.
 */
function matchesRobotsPattern(pattern: string, path: string): boolean {
	const hasEndAnchor = pattern.endsWith('$');
	const body = hasEndAnchor ? pattern.slice(0, -1) : pattern;
	if (body.length === 0) return !hasEndAnchor || path.length === 0;

	const startsWithWildcard = body.startsWith('*');
	const endsWithWildcard = body.endsWith('*');
	const literals = body.split('*').filter((literal) => literal.length > 0);
	if (literals.length === 0) return true;

	let cursor = 0;
	let firstLiteral = 0;
	let lastLiteral = literals.length;
	let searchEnd = path.length;

	if (!startsWithWildcard) {
		const prefix = literals[0]!;
		if (!literalMatchesAt(path, prefix, 0)) return false;
		cursor = prefix.length;
		firstLiteral = 1;
	}

	if (hasEndAnchor && !endsWithWildcard) {
		const suffixIndex = literals.length - 1;
		// With no wildcard, the one literal is both prefix and suffix.
		if (!startsWithWildcard && suffixIndex === 0) return cursor === path.length;
		const suffix = literals[suffixIndex]!;
		const suffixStart = path.length - suffix.length;
		if (suffixStart < cursor || !literalMatchesAt(path, suffix, suffixStart)) return false;
		searchEnd = suffixStart;
		lastLiteral = suffixIndex;
	}

	for (let index = firstLiteral; index < lastLiteral; index += 1) {
		const literal = literals[index]!;
		const foundAt = findLiteral(path, literal, cursor, searchEnd);
		if (foundAt === -1) return false;
		cursor = foundAt + literal.length;
	}
	return true;
}

/**
 * True when `path` is disallowed by `group`. Longest matching rule wins; an
 * exact-length tie favors Allow (RFC 9309 §2.2.2). A `Disallow:` with an empty
 * value means "allow everything" and never matches.
 */
export function isPathDisallowed(group: RobotsGroup | null, path: string): boolean {
	if (!group) return false;
	let best: RobotsRule | null = null;
	for (const rule of group.rules) {
		if (rule.path === '') continue;
		if (!matchesRobotsPattern(rule.path, path)) continue;
		if (!best || rule.path.length > best.path.length) {
			best = rule;
		} else if (rule.path.length === best.path.length && rule.allow) {
			best = rule;
		}
	}
	return best !== null && !best.allow;
}

interface WithRobotsGateOptions {
	/** Defaults to SCANNER_USER_AGENT. */
	userAgent?: string;
	/** robots.txt fetch timeout in ms. Defaults to 3000. */
	timeoutMs?: number;
	/**
	 * Called once per gated request with the branch that decided it (issue #745),
	 * INCLUDING the fail-open branches, and including requests served from the
	 * per-host memo — the record describes the decision applied to this request,
	 * not the network fetch that produced it.
	 *
	 * Purely observational: the callback cannot change the decision, and a
	 * callback that throws is swallowed so instrumentation can never break a scan.
	 */
	onRobotsResolution?: (record: RobotsResolutionRecord) => void;
	/**
	 * Reuse a caller-owned decision cache across gates (see {@link RobotsGroupCache}).
	 * Defaults to a private cache scoped to the returned function, i.e. the
	 * previous behaviour.
	 */
	groupCache?: RobotsGroupCache;
	/** Static namespace for transport-role isolation inside a shared byte budget. */
	cacheNamespace?: string;
}

/**
 * Wrap a FetchFunction so every call (a) carries `userAgent` in the User-Agent
 * header unless the caller already set one, and (b) is rejected with
 * `RobotsDisallowedError` when the target's robots.txt disallows that UA for
 * the requested path. robots.txt is fetched at most once per live cache entry
 * (memoized in a TTL/LRU cache bounded by count and retained bytes); any failure
 * to fetch, read, or parse it is FAIL-OPEN (treated as no restriction) — a broken
 * or unreachable robots.txt must never itself block a scan. `/robots.txt`
 * requests are never routed through the gate.
 *
 * The fail-open POLICY is unchanged by issue #745 — what changed is that every
 * branch, fail-open included, is reported to `opts.onRobotsResolution` so a
 * stored scan carries positive evidence of why it was scored or skipped.
 */
export function withRobotsGate(fetchFn: FetchFunction, opts: WithRobotsGateOptions = {}): FetchFunction {
	const userAgent = opts.userAgent ?? SCANNER_USER_AGENT;
	const productToken = userAgent.split('/')[0]!.toLowerCase();
	const timeoutMs = opts.timeoutMs ?? ROBOTS_FETCH_TIMEOUT_MS;
	const onResolution = opts.onRobotsResolution;
	const cache = opts.groupCache ?? createRobotsGroupCache();
	const cacheState = getRobotsGroupCacheState(cache);
	const groupCache = cache.entries as Map<string, Promise<RobotsOutcome>>;
	const cacheKeyFor = (host: string): string =>
		opts.cacheNamespace === undefined ? host : `${opts.cacheNamespace.length}:${opts.cacheNamespace}:${host}`;

	function cacheGet(key: string): Promise<RobotsOutcome> | undefined {
		const now = cacheState.now();
		reconcileCacheState(cache, cacheState, now);
		const outcome = groupCache.get(key);
		if (!outcome) return undefined;
		// Touch on hit: Map insertion order is the LRU order.
		groupCache.delete(key);
		groupCache.set(key, outcome);
		return outcome;
	}

	function cacheInsert(key: string, outcome: Promise<RobotsOutcome>, weight: number): boolean {
		const now = cacheState.now();
		reconcileCacheState(cache, cacheState, now);
		if (groupCache.has(key)) return false;
		if (weight > cacheState.maxBytes) return false;
		while (groupCache.size >= cacheState.maxEntries || cacheState.retainedBytes + weight > cacheState.maxBytes) {
			const oldest = groupCache.keys().next().value;
			if (oldest === undefined) break;
			deleteCacheEntry(cache, cacheState, oldest);
		}
		groupCache.set(key, outcome);
		cacheState.weights.set(key, weight);
		cacheState.retainedBytes += weight;
		cacheState.expiresAt.set(key, now + cacheState.ttlMs);
		return true;
	}

	function cacheResize(key: string, outcome: Promise<RobotsOutcome>, weight: number): void {
		if (groupCache.get(key) !== outcome) return;
		if (weight > cacheState.maxBytes) {
			deleteCacheEntry(cache, cacheState, key, outcome);
			return;
		}
		const previousWeight = cacheState.weights.get(key) ?? 0;
		while (cacheState.retainedBytes - previousWeight + weight > cacheState.maxBytes) {
			let evicted = false;
			for (const candidate of groupCache.keys()) {
				if (candidate === key) continue;
				deleteCacheEntry(cache, cacheState, candidate);
				evicted = true;
				break;
			}
			if (!evicted) {
				deleteCacheEntry(cache, cacheState, key, outcome);
				return;
			}
		}
		cacheState.weights.set(key, weight);
		cacheState.retainedBytes += weight - previousWeight;
	}

	async function resolveOutcome(host: string): Promise<RobotsOutcome> {
		const cacheKey = cacheKeyFor(host);
		let pending = cacheGet(cacheKey);
		if (!pending) {
			pending = (async (): Promise<RobotsOutcome> => {
				try {
					const res = await fetchFn(`https://${host}/robots.txt`, {
						headers: { 'User-Agent': userAgent },
						signal: AbortSignal.timeout(timeoutMs),
						redirect: 'manual',
					});
					if (!res.ok) {
						void res.body?.cancel();
						// A 404/410 is a MEASUREMENT ("no policy published"); any other
						// error status leaves the policy unknown. Both proceed — only the
						// record distinguishes them.
						return ABSENT_ROBOTS_STATUSES.has(res.status)
							? { kind: 'no_policy', status: res.status }
							: { kind: 'unreachable', status: res.status };
					}
					const text = await readResponseTextCapped(res, ROBOTS_MAX_BODY_BYTES);
					if (text === null) {
						return { kind: 'unreachable', status: res.status, errorName: 'RobotsBodyTooLargeError' };
					}
					return {
						kind: 'policy',
						selected: selectGroup(parseRobotsGroups(text), productToken),
						status: res.status,
						sourceLength: text.length,
					};
				} catch (err) {
					const errorName = err instanceof Error ? err.name : 'Error';
					// `AbortSignal.timeout` rejects with a `TimeoutError`; a composed
					// caller signal aborts with `AbortError`. Both mean "we ran out of
					// time", which is the branch this issue is about.
					return errorName === 'TimeoutError' || errorName === 'AbortError'
						? { kind: 'timeout', errorName }
						: { kind: 'unreachable', errorName };
				}
			})();
			const created = pending;
			const cachedPending = cacheInsert(cacheKey, created, pendingCacheWeight(cacheKey));
			void created.then((outcome) => {
				const weight = settledCacheWeight(cacheKey, outcome);
				if (cachedPending) cacheResize(cacheKey, created, weight);
				else cacheInsert(cacheKey, created, weight);
			});
		}
		return pending;
	}

	/** Report one gated request's decision, fail-soft: instrumentation never breaks a scan. */
	function report(record: RobotsResolutionRecord): void {
		if (!onResolution) return;
		try {
			onResolution(record);
		} catch {
			/* ignore */
		}
	}

	return async (url, init) => {
		const parsed = new URL(url);
		const headers = new Headers(init?.headers);
		if (!headers.has('User-Agent')) headers.set('User-Agent', userAgent);
		const nextInit: RequestInit = { ...init, headers };

		if (parsed.pathname !== '/robots.txt') {
			const outcome = await resolveOutcome(parsed.hostname);
			const base = { host: parsed.hostname, path: parsed.pathname };
			if (outcome.kind === 'policy') {
				const disallowed = outcome.selected !== null && isPathDisallowed(outcome.selected.group, parsed.pathname);
				report({
					...base,
					resolution: disallowed ? 'disallowed' : 'allowed',
					failOpen: false,
					status: outcome.status,
					...(outcome.selected ? { scope: outcome.selected.scope } : {}),
				});
				if (disallowed) throw new RobotsDisallowedError(url, outcome.selected!.scope);
			} else if (outcome.kind === 'no_policy') {
				report({ ...base, resolution: 'no_policy', failOpen: false, status: outcome.status });
			} else {
				// FAIL-OPEN. Policy unknown; the request proceeds exactly as before —
				// the only change is that the guess is now on the record.
				report({
					...base,
					resolution: outcome.kind,
					failOpen: true,
					...(outcome.kind === 'unreachable' && outcome.status !== undefined ? { status: outcome.status } : {}),
					...(outcome.errorName ? { errorName: outcome.errorName } : {}),
				});
			}
		}

		return fetchFn(url, nextInit);
	};
}
