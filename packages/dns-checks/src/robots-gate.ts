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

/** Thrown by a `withRobotsGate`-wrapped fetch when the target's robots.txt disallows our UA for the requested path. */
export class RobotsDisallowedError extends Error {
	constructor(public readonly url: string) {
		super(`robots.txt disallows BlackVeil-Security-Scanner for ${url}`);
		this.name = 'RobotsDisallowedError';
	}
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

/** Most-specific group for `userAgentToken` (an exact agent-token match beats the `*` fallback). Null = no group applies. */
function selectGroup(groups: RobotsGroup[], userAgentToken: string): RobotsGroup | null {
	const named = groups.find((g) => g.agents.includes(userAgentToken));
	if (named) return named;
	return groups.find((g) => g.agents.includes('*')) ?? null;
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
 */
export function withRobotsGate(
	fetchFn: FetchFunction,
	opts: WithRobotsGateOptions = {}
): FetchFunction {
	const userAgent = opts.userAgent ?? SCANNER_USER_AGENT;
	const productToken = userAgent.split('/')[0]!.toLowerCase();
	const timeoutMs = opts.timeoutMs ?? ROBOTS_FETCH_TIMEOUT_MS;
	const groupCache = new Map<string, Promise<RobotsGroup | null>>();

	async function resolveGroup(host: string): Promise<RobotsGroup | null> {
		let pending = groupCache.get(host);
		if (!pending) {
			pending = (async () => {
				try {
					const res = await fetchFn(`https://${host}/robots.txt`, {
						headers: { 'User-Agent': userAgent },
						signal: AbortSignal.timeout(timeoutMs),
					});
					if (!res.ok) {
						void res.body?.cancel();
						return null;
					}
					const text = await res.text();
					return selectGroup(parseRobotsGroups(text), productToken);
				} catch {
					return null;
				}
			})();
			groupCache.set(host, pending);
		}
		return pending;
	}

	return async (url, init) => {
		const parsed = new URL(url);
		const headers = new Headers(init?.headers);
		if (!headers.has('User-Agent')) headers.set('User-Agent', userAgent);
		const nextInit: RequestInit = { ...init, headers };

		if (parsed.pathname !== '/robots.txt') {
			const group = await resolveGroup(parsed.hostname);
			if (isPathDisallowed(group, parsed.pathname)) {
				throw new RobotsDisallowedError(url);
			}
		}

		return fetchFn(url, nextInit);
	};
}
