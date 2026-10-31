// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * Pure Content-Security-Policy evaluator for the non-scoring `csp_quality` check.
 *
 * Token-based, in the manner of Google's CSP Evaluator: a policy is parsed into directives and
 * source lists, and each rule reads the parsed form. This is deliberately separate from the
 * substring-based `analyzeCspQuality` in `http-security-analysis.ts`, which feeds the SCORED
 * `http_security` category and is left untouched.
 *
 * The "effective script directive" is `script-src-elem`, else `script-src`, else `default-src`.
 * Allowlist-style findings (wildcards, scheme sources, `http:` hosts, bypassable hosts) are not
 * raised against it when the policy is a strict one: a nonce or hash plus `'strict-dynamic'`
 * makes a supporting browser ignore host and scheme sources, so they are only a CSP2 fallback.
 *
 * Runtime-agnostic: no `node:` imports, no DOM.
 */

import type { Severity } from '../types';

export type CspDelivery = 'header' | 'meta';

export type CspRule =
	| 'missing-script-src'
	| 'unsafe-inline'
	| 'unsafe-eval'
	| 'wildcard-source'
	| 'scheme-source'
	| 'http-source'
	| 'allowlist-bypass'
	| 'strict-dynamic-ineffective'
	| 'missing-object-src'
	| 'missing-base-uri'
	| 'missing-frame-ancestors'
	| 'report-uri-deprecated'
	| 'unknown-directive'
	| 'unquoted-keyword'
	| 'meta-ignored-directive';

export interface CspIssue {
	rule: CspRule;
	severity: Severity;
	/** The directive the issue was found in, or the one that is missing. */
	directive: string;
	/** The offending source expression, when the issue is about one token. */
	token?: string;
	title: string;
	detail: string;
}

export interface EvaluateCspOptions {
	/** `meta` for a `<meta http-equiv>` policy: `frame-ancestors` is not required there. Default `header`. */
	delivery?: CspDelivery;
}

// ── Vocabulary ───────────────────────────────────────────────────────────────

/** Directives whose value is a source list. */
const SOURCE_LIST_DIRECTIVES: ReadonlySet<string> = new Set([
	'default-src',
	'script-src',
	'script-src-elem',
	'script-src-attr',
	'style-src',
	'style-src-elem',
	'style-src-attr',
	'img-src',
	'font-src',
	'connect-src',
	'media-src',
	'object-src',
	'frame-src',
	'child-src',
	'worker-src',
	'manifest-src',
	'prefetch-src',
	'base-uri',
	'form-action',
	'frame-ancestors',
]);

/** Every directive name a current browser (or a deprecated-but-known directive) recognises. */
const KNOWN_DIRECTIVES: ReadonlySet<string> = new Set([
	...SOURCE_LIST_DIRECTIVES,
	'sandbox',
	'report-uri',
	'report-to',
	'upgrade-insecure-requests',
	'block-all-mixed-content',
	'require-trusted-types-for',
	'trusted-types',
	'plugin-types',
	'referrer',
]);

/** Directives a `<meta>` policy cannot carry (CSP3 §3.3: ignored when delivered in a meta element). */
const META_IGNORED_DIRECTIVES: ReadonlySet<string> = new Set(['frame-ancestors', 'report-uri', 'sandbox']);

/** Source-list keywords that must be single-quoted. A bare `self` is a hostname, not the keyword. */
const QUOTED_KEYWORDS: ReadonlySet<string> = new Set([
	'self',
	'none',
	'unsafe-inline',
	'unsafe-eval',
	'unsafe-hashes',
	'strict-dynamic',
	'report-sample',
	'wasm-unsafe-eval',
]);

/**
 * Hosts commonly allowlisted in `script-src` that serve JSONP endpoints or AngularJS builds, so
 * an allowlist naming them can be bypassed for script execution.
 *
 * Seeded from Google's CSP Evaluator data (Apache-2.0), fetched 2026-10-31:
 * - https://github.com/google/csp-evaluator/blob/master/allowlist_bypasses/jsonp.ts
 * - https://github.com/google/csp-evaluator/blob/master/allowlist_bypasses/angular.ts
 * That data lists concrete URLs; this keeps the hosts, and the two wildcard patterns collapse its
 * `*.googleapis.com` (ajax., maps., translate., mts0.) and `*.gstatic.com` (www.gstatic.com) rows.
 * It is a seed, not an exhaustive list.
 */
const BYPASSABLE_ALLOWLIST_HOSTS: readonly string[] = [
	'*.googleapis.com',
	'*.gstatic.com',
	'cdnjs.cloudflare.com',
	'cdn.jsdelivr.net',
	'www.google.com',
	'accounts.google.com',
];

/** Hosts whose JSONP bypass only works when `'unsafe-eval'` is also allowed (CSP Evaluator `NEEDS_EVAL`). */
const BYPASSABLE_WITH_EVAL_HOSTS: readonly string[] = [
	'googletagmanager.com',
	'www.googletagmanager.com',
	'google-analytics.com',
	'www.google-analytics.com',
	'ssl.google-analytics.com',
	'www.googleadservices.com',
];

const NONCE_SOURCE = /^'nonce-[A-Za-z0-9+/_-]+=*'$/i;
const HASH_SOURCE = /^'sha(?:256|384|512)-[A-Za-z0-9+/_-]+=*'$/i;
const SCHEME_ONLY_SOURCE = /^(?:https?|data):$/i;
const HTTP_HOST_SOURCE = /^http:\/\//i;
const TYPO_DISTANCE = 2;

// ── Parsing ──────────────────────────────────────────────────────────────────

/**
 * Parse one serialized policy into `directive-name -> source tokens`.
 *
 * Directive names are lower-cased; tokens keep their case. When a directive repeats, the first
 * occurrence wins and later ones are dropped, as the spec requires.
 */
export function parseCsp(policy: string): Map<string, string[]> {
	const directives = new Map<string, string[]>();
	for (const part of policy.split(';')) {
		const [name, ...tokens] = part.trim().split(/\s+/);
		const key = name?.toLowerCase();
		if (key && !directives.has(key)) directives.set(key, tokens);
	}
	return directives;
}

// ── Token predicates ─────────────────────────────────────────────────────────

function hasKeyword(tokens: readonly string[], keyword: string): boolean {
	return tokens.some((t) => t.toLowerCase() === `'${keyword}'`);
}

function hasNonceOrHash(tokens: readonly string[]): boolean {
	return tokens.some((t) => NONCE_SOURCE.test(t) || HASH_SOURCE.test(t));
}

/** True when the lowercased token names a host: not a keyword, scheme, nonce or hash. */
function isHostSource(token: string): boolean {
	return !token.startsWith("'") && !token.endsWith(':') && token !== '*';
}

/** The bare host of a host-source expression: scheme, port and path removed. */
function hostOf(token: string): string {
	return token
		.toLowerCase()
		.replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
		.replace(/[/:?#].*$/, '');
}

/** True when `pattern` (a host or a `*.suffix` wildcard) covers `host` (itself possibly a wildcard). */
function hostCovers(pattern: string, host: string): boolean {
	return pattern === host || (pattern.startsWith('*.') && host.endsWith(pattern.slice(1)));
}

function isBypassHost(token: string, hosts: readonly string[]): boolean {
	const host = hostOf(token);
	return hosts.some((entry) => hostCovers(entry, host) || hostCovers(host, entry));
}

/** Levenshtein distance, early-exiting once the row minimum passes `limit`. */
function editDistance(a: string, b: string, limit: number): number {
	let previous = Array.from({ length: b.length + 1 }, (_, j) => j);
	for (let i = 1; i <= a.length; i++) {
		const row = [i];
		for (let j = 1; j <= b.length; j++) {
			row.push(Math.min(previous[j]! + 1, row[j - 1]! + 1, previous[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1)));
		}
		if (Math.min(...row) > limit) return limit + 1;
		previous = row;
	}
	return previous[b.length]!;
}

function closestKnownDirective(name: string): string | undefined {
	return [...KNOWN_DIRECTIVES].find((known) => editDistance(name, known, TYPO_DISTANCE) <= TYPO_DISTANCE);
}

// ── Evaluation context ───────────────────────────────────────────────────────

interface Context {
	directives: ReadonlyMap<string, string[]>;
	delivery: CspDelivery;
	/** The effective script directive, or `null` when the policy restricts scripts through none. */
	script: { name: string; tokens: string[] } | null;
	/** True for a nonce or hash plus `'strict-dynamic'`: host and scheme sources are ignored by the browser. */
	strict: boolean;
}

type Rule = (ctx: Context) => CspIssue[];

function effectiveScript(directives: ReadonlyMap<string, string[]>): Context['script'] {
	const name = ['script-src-elem', 'script-src', 'default-src'].find((candidate) => directives.has(candidate));
	return name === undefined ? null : { name, tokens: directives.get(name)! };
}

function buildContext(policy: string, delivery: CspDelivery): Context {
	const directives = parseCsp(policy);
	const script = effectiveScript(directives);
	const strict = script !== null && hasKeyword(script.tokens, 'strict-dynamic') && hasNonceOrHash(script.tokens);
	return { directives, delivery, script, strict };
}

function issue(rule: CspRule, severity: Severity, directive: string, title: string, detail: string, token?: string): CspIssue {
	return { rule, severity, directive, title, detail, ...(token === undefined ? {} : { token }) };
}

// ── Rules ────────────────────────────────────────────────────────────────────

const ruleMissingScriptSrc: Rule = ({ script }) =>
	script === null
		? [
				issue(
					'missing-script-src',
					'medium',
					'script-src',
					'CSP does not restrict script sources',
					"The policy has no script-src, script-src-elem or default-src, so scripts load from anywhere. A policy that only sets frame-ancestors or similar is valid, but it gives no protection against injected scripts.",
				),
			]
		: [];

const ruleUnsafeInline: Rule = ({ script }) => {
	if (script === null || !hasKeyword(script.tokens, 'unsafe-inline')) return [];
	// CSP3: a nonce, hash or 'strict-dynamic' in the same list makes a supporting browser ignore 'unsafe-inline'.
	const neutralised = hasNonceOrHash(script.tokens) || hasKeyword(script.tokens, 'strict-dynamic');
	if (neutralised) return [];
	return [
		issue(
			'unsafe-inline',
			'high',
			script.name,
			"CSP allows 'unsafe-inline' scripts",
			`${script.name} contains 'unsafe-inline' with no nonce, hash or 'strict-dynamic' to neutralise it, so any injected inline script runs.`,
			"'unsafe-inline'",
		),
	];
};

const ruleUnsafeEval: Rule = ({ script }) =>
	script !== null && hasKeyword(script.tokens, 'unsafe-eval')
		? [
				issue(
					'unsafe-eval',
					'medium',
					script.name,
					"CSP allows 'unsafe-eval'",
					`${script.name} contains 'unsafe-eval', which lets eval() and similar string-to-code calls run.`,
					"'unsafe-eval'",
				),
			]
		: [];

const ruleBroadScriptSources: Rule = ({ script, strict }) => {
	if (script === null || strict) return [];
	return script.tokens.flatMap((token) => {
		if (token === '*') {
			return [issue('wildcard-source', 'high', script.name, 'CSP allows scripts from any origin', `${script.name} contains the wildcard "*".`, token)];
		}
		if (SCHEME_ONLY_SOURCE.test(token)) {
			return [
				issue('scheme-source', 'high', script.name, 'CSP allows scripts from a whole scheme', `${script.name} contains the scheme-only source "${token}", which matches every URL of that scheme.`, token),
			];
		}
		return [];
	});
};

const ruleHttpSources: Rule = ({ directives, script, strict }) =>
	[...directives.entries()]
		.filter(([name]) => SOURCE_LIST_DIRECTIVES.has(name) && !(strict && name === script?.name))
		.flatMap(([name, tokens]) =>
			tokens
				.filter((token) => HTTP_HOST_SOURCE.test(token))
				.map((token) => issue('http-source', 'medium', name, 'CSP allows plain-HTTP sources', `${name} names the http: source "${token}", which a network attacker can tamper with.`, token)),
		);

const ruleAllowlistBypass: Rule = ({ script, strict }) => {
	if (script === null || strict) return [];
	const withEval = hasKeyword(script.tokens, 'unsafe-eval');
	return script.tokens
		.filter(isHostSource)
		.filter((token) => isBypassHost(token, BYPASSABLE_ALLOWLIST_HOSTS) || (withEval && isBypassHost(token, BYPASSABLE_WITH_EVAL_HOSTS)))
		.map((token) =>
			issue(
				'allowlist-bypass',
				'medium',
				script.name,
				'Script allowlist bypassable',
				`${script.name} allowlists "${token}", a host known to serve JSONP endpoints or AngularJS, which can be used to run attacker-controlled script despite the allowlist.`,
				token,
			),
		);
};

const ruleStrictDynamic: Rule = ({ script }) =>
	script !== null && hasKeyword(script.tokens, 'strict-dynamic') && !hasNonceOrHash(script.tokens)
		? [
				issue(
					'strict-dynamic-ineffective',
					'info',
					script.name,
					"'strict-dynamic' is ineffective without a nonce or hash",
					`${script.name} has 'strict-dynamic' but no nonce or hash source, so a browser has nothing to extend trust from and the keyword does nothing useful.`,
					"'strict-dynamic'",
				),
			]
		: [];

const ruleObjectSrc: Rule = ({ directives }) => {
	if (directives.has('object-src')) return [];
	const fallback = directives.get('default-src') ?? [];
	if (hasKeyword(fallback, 'none') || hasKeyword(fallback, 'self')) return [];
	return [
		issue(
			'missing-object-src',
			'medium',
			'object-src',
			"CSP does not set 'object-src'",
			"No object-src, and no default-src of 'none' or 'self' to cover it, so plugin content (object, embed) is unrestricted.",
		),
	];
};

const ruleBaseUri: Rule = ({ directives }) =>
	directives.has('base-uri')
		? []
		: [
				issue(
					'missing-base-uri',
					'medium',
					'base-uri',
					"CSP does not set 'base-uri'",
					'base-uri does not fall back to default-src. Without it an injected <base> tag can redirect every relative script URL to an attacker host.',
				),
			];

const ruleFrameAncestors: Rule = ({ directives, delivery }) =>
	delivery === 'header' && !directives.has('frame-ancestors')
		? [
				issue(
					'missing-frame-ancestors',
					'low',
					'frame-ancestors',
					"CSP does not set 'frame-ancestors'",
					'Without frame-ancestors the page can be framed by any site (clickjacking). X-Frame-Options is the legacy alternative; frame-ancestors is not set by default-src.',
				),
			]
		: [];

const ruleReportUri: Rule = ({ directives, delivery }) =>
	delivery === 'header' && directives.has('report-uri') && !directives.has('report-to')
		? [
				issue(
					'report-uri-deprecated',
					'info',
					'report-uri',
					"CSP uses deprecated 'report-uri' without 'report-to'",
					'report-uri is deprecated in CSP3. Add report-to (with a Reporting-Endpoints header) so current browsers report violations.',
				),
			]
		: [];

const ruleUnknownDirectives: Rule = ({ directives }) =>
	[...directives.keys()]
		.filter((name) => !KNOWN_DIRECTIVES.has(name))
		.map((name) => {
			const suggestion = closestKnownDirective(name);
			const hint = suggestion === undefined ? '' : ` Did you mean "${suggestion}"?`;
			return issue('unknown-directive', 'low', name, 'CSP has an unknown directive', `"${name}" is not a CSP directive, so browsers ignore it.${hint}`, name);
		});

const ruleUnquotedKeywords: Rule = ({ directives }) =>
	[...directives.entries()]
		.filter(([name]) => SOURCE_LIST_DIRECTIVES.has(name))
		.flatMap(([name, tokens]) =>
			tokens
				.filter((token) => QUOTED_KEYWORDS.has(token.toLowerCase()))
				.map((token) =>
					issue('unquoted-keyword', 'low', name, 'CSP keyword is missing its quotes', `${name} has "${token}" without quotes, which a browser reads as a hostname, not the keyword '${token.toLowerCase()}'.`, token),
				),
		);

const ruleMetaIgnored: Rule = ({ directives, delivery }) =>
	delivery === 'meta'
		? [...directives.keys()]
				.filter((name) => META_IGNORED_DIRECTIVES.has(name))
				.map((name) => issue('meta-ignored-directive', 'low', name, 'CSP directive is ignored in a <meta> policy', `${name} has no effect when the policy is delivered in a <meta> element; it needs the Content-Security-Policy header.`, name))
		: [];

const RULES: readonly Rule[] = [
	ruleMissingScriptSrc,
	ruleUnsafeInline,
	ruleUnsafeEval,
	ruleBroadScriptSources,
	ruleHttpSources,
	ruleAllowlistBypass,
	ruleStrictDynamic,
	ruleObjectSrc,
	ruleBaseUri,
	ruleFrameAncestors,
	ruleReportUri,
	ruleUnknownDirectives,
	ruleUnquotedKeywords,
	ruleMetaIgnored,
];

/**
 * Evaluate one serialized policy and return every issue found, in rule order.
 *
 * Pure and total: any string is a valid input, including an empty one (which reads as a policy
 * with no directives).
 */
export function evaluateCsp(policy: string, opts: EvaluateCspOptions = {}): CspIssue[] {
	const ctx = buildContext(policy, opts.delivery ?? 'header');
	return RULES.flatMap((rule) => rule(ctx));
}
