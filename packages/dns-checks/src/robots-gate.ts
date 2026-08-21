// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { FetchFunction } from './types';

/**
 * Identifying User-Agent sent on every outbound request this package makes to a
 * scanned domain's own web server (HTTP/TLS checks, BIMI logo fetch, MTA-STS
 * policy fetch, subdomain-takeover probe). See /bot-policy on
 * blackveilsecurity.com — this is the SSOT the page's copy is derived from.
 */
export const SCANNER_USER_AGENT =
	'BlackVeil-Security-Scanner/1.0 (+https://www.blackveilsecurity.com/bot-policy; security@blackveilsecurity.com)';

const ROBOTS_FETCH_TIMEOUT_MS = 3_000;

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
		public readonly scope: RobotsDisallowScope = 'blanket'
	) {
		super(
			scope === 'named'
				? `robots.txt names and disallows BlackVeil-Security-Scanner for ${url}`
				: `robots.txt disallows all crawlers (User-agent: *) for ${url}`
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
	return scope === 'named'
		? 'disallows BlackVeil-Security-Scanner by name'
		: 'disallows all automated crawlers';
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
	| { kind: 'policy'; selected: SelectedGroup | null; status: number }
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

/** Create an empty {@link RobotsGroupCache}. Share one instance across gates that should share fetches. */
export function createRobotsGroupCache(): RobotsGroupCache {
	return { entries: new Map() };
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

/** Convert a robots.txt path pattern (`*` wildcard, trailing `$` end-anchor) into a prefix-matching RegExp. */
function patternToRegExp(pattern: string): RegExp {
	const hasEndAnchor = pattern.endsWith('$');
	const body = hasEndAnchor ? pattern.slice(0, -1) : pattern;
	const escaped = body.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
	return new RegExp(`^${escaped}${hasEndAnchor ? '$' : ''}`);
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
		if (!patternToRegExp(rule.path).test(path)) continue;
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
}

/**
 * Wrap a FetchFunction so every call (a) carries `userAgent` in the User-Agent
 * header unless the caller already set one, and (b) is rejected with
 * `RobotsDisallowedError` when the target's robots.txt disallows that UA for
 * the requested path. robots.txt is fetched at most once per hostname for the
 * lifetime of the returned function (memoized in a closure over `fetchFn`);
 * any failure to fetch, read, or parse it is FAIL-OPEN (treated as no
 * restriction) — a broken or unreachable robots.txt must never itself block a
 * scan. `/robots.txt` requests are never routed through the gate.
 *
 * The fail-open POLICY is unchanged by issue #745 — what changed is that every
 * branch, fail-open included, is reported to `opts.onRobotsResolution` so a
 * stored scan carries positive evidence of why it was scored or skipped.
 */
export function withRobotsGate(
	fetchFn: FetchFunction,
	opts: WithRobotsGateOptions = {}
): FetchFunction {
	const userAgent = opts.userAgent ?? SCANNER_USER_AGENT;
	const productToken = userAgent.split('/')[0]!.toLowerCase();
	const timeoutMs = opts.timeoutMs ?? ROBOTS_FETCH_TIMEOUT_MS;
	const onResolution = opts.onRobotsResolution;
	const groupCache = (opts.groupCache?.entries ?? new Map()) as Map<string, Promise<RobotsOutcome>>;

	async function resolveOutcome(host: string): Promise<RobotsOutcome> {
		let pending = groupCache.get(host);
		if (!pending) {
			pending = (async (): Promise<RobotsOutcome> => {
				try {
					const res = await fetchFn(`https://${host}/robots.txt`, {
						headers: { 'User-Agent': userAgent },
						signal: AbortSignal.timeout(timeoutMs),
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
					const text = await res.text();
					return { kind: 'policy', selected: selectGroup(parseRobotsGroups(text), productToken), status: res.status };
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
			groupCache.set(host, pending);
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
