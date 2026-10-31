// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * Pure analysis for the non-scoring `web_content` check.
 *
 * Reads one {@link CappedPage} (cookies from `Set-Cookie`, references from the HTML body) and
 * returns findings. No fetching and no clock: the check in `check-web-content.ts` owns both.
 *
 * Cookie VALUES are never read into a finding: only names, and only the first 64 characters of a name.
 */

import type { Finding, Severity } from '../types';
import { createFinding, isSubdomainOf } from '../check-utils';
import { extractHtmlRefs } from './html-refs';
import type { HtmlRefs } from './html-refs';
import type { CappedPage } from './page-fetch';
import { isBlockedProbeStatus } from './ssl-analysis';

/** Cookies itemized one finding each; further flagged cookies fold into one summary finding. */
export const MAX_COOKIE_FINDINGS = 20;

/** URLs spelled out in one finding; the rest are counted. */
export const MAX_LISTED_URLS = 10;

const MAX_URL_CHARS = 120;
const MAX_COOKIE_NAME_CHARS = 64;
const SESSION_COOKIE_NAME = /sess|sid|auth|token|jwt/i;
/** One SRI hash-expression: `sha256-` / `sha384-` / `sha512-`, base64 digest, optional `?options`. */
const SRI_TOKEN = /^sha(?:256|384|512)-[A-Za-z0-9+/_-]+={0,2}(?:\?\S*)?$/i;
const NO_CONTENT_STATUSES = new Set([204, 205]);
const SEVERITY_ORDER: readonly Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** What the analysis needs to know about the page besides its content. */
export interface PageContext {
	/** Host the caller asked for. Labels every finding. */
	host: string;
	/** Host of the page actually read (after redirects). The origin that SRI compares against. */
	pageHost: string;
	/** The checked domain. Its subdomains count as same-site. */
	domain: string;
	/** False when the page itself came over `http:` (only possible with a caller-supplied page). */
	isHttps: boolean;
}

export function pageContext(page: CappedPage, domain: string): PageContext {
	const requested = URL.parse(page.requestedUrl);
	const final = URL.parse(page.finalUrl);
	return {
		host: requested ? requested.host : domain,
		pageHost: final ? final.hostname : domain,
		domain,
		isHttps: final ? final.protocol === 'https:' : true,
	};
}

function webFinding(ctx: PageContext, severity: Severity, title: string, detail: string, metadata: Record<string, unknown> = {}): Finding {
	return createFinding('web_content', title, severity, `${ctx.host}: ${detail}`, { host: ctx.host, ...metadata });
}

/** A host that could not be measured. Never `missingControl`: nothing was observed, so nothing is claimed absent. */
export function notAssessedFinding(ctx: PageContext, reason: string, errorKind: string): Finding {
	return webFinding(ctx, 'info', 'Web content not assessed', `not assessed: ${reason}.`, { inconclusive: true, errorKind });
}

/** A host whose redirect landed on a page the other host already covered. Analysed once, not twice. */
export function duplicatePageFinding(ctx: PageContext, finalUrl: string): Finding {
	return webFinding(ctx, 'info', 'Same page as the other host', `it redirects to ${finalUrl}, which is analysed once under the other host.`, { duplicateOf: 'other_host' });
}

function severityRank(severity: Severity): number {
	return SEVERITY_ORDER.indexOf(severity);
}

function maxSeverity(severities: readonly Severity[]): Severity {
	return severities.reduce((top, next) => (severityRank(next) > severityRank(top) ? next : top), 'info' as Severity);
}

// ── Cookies ──────────────────────────────────────────────────────────────────

export interface ParsedCookie {
	name: string;
	secure: boolean;
	httpOnly: boolean;
	/** Lower-cased `SameSite` value; `null` when absent. */
	sameSite: string | null;
	path: string | null;
	hasDomain: boolean;
}

interface CookieIssue {
	code: string;
	severity: Severity;
	text: string;
}

type CookieRule = (cookie: ParsedCookie, pageIsHttps: boolean) => CookieIssue | null;

function parseCookieAttributes(segments: readonly string[]): Map<string, string> {
	const attrs = new Map<string, string>();
	for (const segment of segments) {
		const eq = segment.indexOf('=');
		const key = (eq < 0 ? segment : segment.slice(0, eq)).trim().toLowerCase();
		attrs.set(key, eq < 0 ? '' : segment.slice(eq + 1).trim());
	}
	return attrs;
}

/** Parse one `Set-Cookie` header value. The cookie value is discarded. `null` when there is no name. */
export function parseSetCookie(raw: string): ParsedCookie | null {
	const [pair, ...segments] = raw.split(';');
	const name = pair.split('=')[0].trim();
	if (!name) return null;
	const attrs = parseCookieAttributes(segments);
	return {
		name,
		secure: attrs.has('secure'),
		httpOnly: attrs.has('httponly'),
		sameSite: attrs.get('samesite')?.toLowerCase() || null,
		path: attrs.get('path') ?? null,
		hasDomain: attrs.has('domain'),
	};
}

function issue(code: string, severity: Severity, text: string): CookieIssue {
	return { code, severity, text };
}

const missingSecure: CookieRule = (cookie, pageIsHttps) =>
	pageIsHttps && !cookie.secure ? issue('missing_secure', 'medium', 'set over https without the Secure flag') : null;

const missingHttpOnly: CookieRule = (cookie) => {
	if (cookie.httpOnly) return null;
	const severity = SESSION_COOKIE_NAME.test(cookie.name) ? 'medium' : 'low';
	return issue('missing_httponly', severity, 'no HttpOnly flag (script can read it)');
};

const absentSameSite: CookieRule = (cookie) => (cookie.sameSite ? null : issue('samesite_absent', 'low', 'no SameSite attribute'));

const sameSiteNoneWithoutSecure: CookieRule = (cookie) =>
	cookie.sameSite === 'none' && !cookie.secure ? issue('samesite_none_insecure', 'medium', 'SameSite=None without Secure (browsers reject it)') : null;

const hostPrefixViolation: CookieRule = (cookie) => {
	if (!/^__host-/i.test(cookie.name)) return null;
	const unmet = [!cookie.secure && 'Secure', cookie.path !== '/' && 'Path=/', cookie.hasDomain && 'no Domain attribute'].filter(
		(requirement): requirement is string => typeof requirement === 'string',
	);
	return unmet.length > 0 ? issue('host_prefix', 'medium', `__Host- prefix not honoured: requires ${unmet.join(', ')}`) : null;
};

const securePrefixViolation: CookieRule = (cookie) =>
	/^__secure-/i.test(cookie.name) && !cookie.secure ? issue('secure_prefix', 'medium', '__Secure- prefix not honoured: requires Secure') : null;

const COOKIE_RULES: readonly CookieRule[] = [
	missingSecure,
	missingHttpOnly,
	absentSameSite,
	sameSiteNoneWithoutSecure,
	hostPrefixViolation,
	securePrefixViolation,
];

function cookieIssues(cookie: ParsedCookie, pageIsHttps: boolean): CookieIssue[] {
	return COOKIE_RULES.map((rule) => rule(cookie, pageIsHttps)).filter((found): found is CookieIssue => found !== null);
}

interface FlaggedCookie {
	cookie: ParsedCookie;
	issues: CookieIssue[];
}

function flagCookie(raw: string, pageIsHttps: boolean): FlaggedCookie[] {
	const cookie = parseSetCookie(raw);
	const issues = cookie ? cookieIssues(cookie, pageIsHttps) : [];
	return cookie && issues.length > 0 ? [{ cookie, issues }] : [];
}

function cookieFinding(ctx: PageContext, { cookie, issues }: FlaggedCookie): Finding {
	const name = cookie.name.slice(0, MAX_COOKIE_NAME_CHARS);
	return webFinding(ctx, maxSeverity(issues.map((found) => found.severity)), `Cookie "${name}" has weak attributes`, issues.map((found) => found.text).join('; '), {
		cookie: name,
		issues: issues.map((found) => found.code),
	});
}

function cookieSummaryFinding(ctx: PageContext, omitted: readonly FlaggedCookie[]): Finding {
	const severity = maxSeverity(omitted.flatMap((flagged) => flagged.issues.map((found) => found.severity)));
	return webFinding(ctx, severity, 'More cookies with weak attributes', `${omitted.length} further cookies have weak attributes; only the first ${MAX_COOKIE_FINDINGS} are itemized.`, {
		omittedCookies: omitted.length,
	});
}

/** One finding per cookie that has a weakness (names only, never values), capped, then a summary. */
export function analyzeCookies(setCookies: readonly string[], ctx: PageContext): Finding[] {
	const flagged = setCookies.flatMap((raw) => flagCookie(raw, ctx.isHttps));
	const itemized = flagged.slice(0, MAX_COOKIE_FINDINGS).map((entry) => cookieFinding(ctx, entry));
	const omitted = flagged.slice(MAX_COOKIE_FINDINGS);
	return omitted.length > 0 ? [...itemized, cookieSummaryFinding(ctx, omitted)] : itemized;
}

// ── URL findings ─────────────────────────────────────────────────────────────

function displayUrl(url: string): string {
	const parsed = URL.parse(url);
	const shown = parsed ? `${parsed.origin}${parsed.pathname}` : url;
	return shown.length > MAX_URL_CHARS ? `${shown.slice(0, MAX_URL_CHARS)}...` : shown;
}

/** Up to {@link MAX_LISTED_URLS} distinct URLs without query or fragment, then a count of the rest. */
function listUrls(urls: readonly string[]): string {
	const unique = [...new Set(urls.map(displayUrl))];
	const shown = unique.slice(0, MAX_LISTED_URLS).join(', ');
	return unique.length > MAX_LISTED_URLS ? `${shown} (+${unique.length - MAX_LISTED_URLS} more)` : shown;
}

/** One finding listing `urls`, or none when the list is empty. */
function urlFinding(ctx: PageContext, urls: readonly string[], severity: Severity, title: string, explanation: string): Finding[] {
	if (urls.length === 0) return [];
	return [webFinding(ctx, severity, title, `${urls.length} reference(s): ${listUrls(urls)}. ${explanation}`, { count: urls.length })];
}

function isHttpUrl(url: string): boolean {
	return url.startsWith('http://');
}

// ── Mixed content ────────────────────────────────────────────────────────────

/** http: scripts, stylesheets and frames/objects are active mixed content; http: media is passive. */
export function analyzeMixedContent(refs: HtmlRefs, ctx: PageContext): Finding[] {
	if (!ctx.isHttps) {
		return [webFinding(ctx, 'info', 'Mixed-content analysis skipped', 'the page itself is served over http, so mixed content does not apply to it.')];
	}
	const active = [...refs.scripts.map((script) => script.src), ...refs.stylesheets.map((sheet) => sheet.href), ...refs.active.map((ref) => ref.url)];
	const passive = refs.passive.map((ref) => ref.url);
	return [
		...urlFinding(ctx, active.filter(isHttpUrl), 'high', 'Active mixed content', 'scripts, stylesheets or frames loaded over http on an https page can be rewritten by anyone on the network path.'),
		...urlFinding(ctx, passive.filter(isHttpUrl), 'low', 'Passive mixed content', 'images or media loaded over http on an https page can be replaced in transit.'),
	];
}

// ── Subresource Integrity ────────────────────────────────────────────────────

interface Subresource {
	kind: 'script' | 'stylesheet';
	url: string;
	/** Trimmed `integrity` value; `null` when absent or blank. */
	integrity: string | null;
	crossorigin: string | null;
}

function integrityOrNull(value: string | null): string | null {
	return value?.trim() || null;
}

function collectSubresources(refs: HtmlRefs): Subresource[] {
	const scripts = refs.scripts.map((script) => ({ kind: 'script' as const, url: script.src, integrity: integrityOrNull(script.integrity), crossorigin: script.crossorigin }));
	const sheets = refs.stylesheets.map((sheet) => ({ kind: 'stylesheet' as const, url: sheet.href, integrity: integrityOrNull(sheet.integrity), crossorigin: sheet.crossorigin }));
	return [...scripts, ...sheets];
}

function hasValidIntegrity(integrity: string): boolean {
	return integrity.split(/\s+/).some((token) => SRI_TOKEN.test(token));
}

function isCrossOrigin(url: string, ctx: PageContext): boolean {
	const host = URL.parse(url)?.hostname;
	return host !== undefined && host !== ctx.pageHost && !isSubdomainOf(host, ctx.domain);
}

function urlOf(subresource: Subresource): string {
	return subresource.url;
}

function lacksIntegrity(subresource: Subresource): boolean {
	return subresource.integrity === null;
}

function hasMalformedIntegrity(subresource: Subresource): boolean {
	return subresource.integrity !== null && !hasValidIntegrity(subresource.integrity);
}

function isScriptWithIntegrityButNoCors(subresource: Subresource): boolean {
	return subresource.kind === 'script' && subresource.integrity !== null && subresource.crossorigin === null;
}

/** Cross-origin loads without SRI, malformed integrity values, and cross-origin scripts whose integrity cannot verify. */
export function analyzeSubresourceIntegrity(refs: HtmlRefs, ctx: PageContext): Finding[] {
	const subresources = collectSubresources(refs);
	const crossOrigin = subresources.filter((subresource) => isCrossOrigin(subresource.url, ctx));
	return [
		...urlFinding(ctx, crossOrigin.filter(lacksIntegrity).map(urlOf), 'low', 'Cross-origin resource without Subresource Integrity', 'a compromised third-party host could change what runs or styles this page.'),
		...urlFinding(ctx, subresources.filter(hasMalformedIntegrity).map(urlOf), 'medium', 'Malformed integrity attribute', 'the value has no sha256-, sha384- or sha512- hash, so browsers ignore it and the resource is unprotected.'),
		...urlFinding(ctx, crossOrigin.filter(isScriptWithIntegrityButNoCors).map(urlOf), 'low', 'Cross-origin script has integrity but no crossorigin attribute', 'without crossorigin the browser cannot read the response to verify the hash, so it blocks the script.'),
	];
}

// ── Outbound http links ──────────────────────────────────────────────────────

export function analyzeOutboundHttpLinks(refs: HtmlRefs, ctx: PageContext): Finding[] {
	return [
		...urlFinding(ctx, refs.forms.map((form) => form.action).filter(isHttpUrl), 'medium', 'Form submits to an http URL', 'anything typed into the form, credentials included, travels in cleartext.'),
		...urlFinding(ctx, refs.anchors.map((anchor) => anchor.href).filter(isHttpUrl), 'info', 'Links to http URLs', 'links that send visitors to unencrypted pages.'),
	];
}

// ── One page ─────────────────────────────────────────────────────────────────

/** Why this response says nothing about the site's own page, or `null` when it can be analysed. */
function unassessableReason(status: number): string | null {
	if (status >= 300 && status < 400) return `the redirect chain stopped on HTTP ${status} before reaching a page`;
	if (NO_CONTENT_STATUSES.has(status)) return `it answered HTTP ${status} with no content`;
	if (isBlockedProbeStatus(status)) return `it answered HTTP ${status}, an edge, WAF, rate-limit or server-error response rather than the site's own page`;
	return null;
}

function isHtml(page: CappedPage): boolean {
	const contentType = page.headers.get('content-type');
	return contentType === null || /html/i.test(contentType);
}

function readRefs(page: CappedPage): HtmlRefs | null {
	return page.body !== null && page.body !== '' && isHtml(page) ? extractHtmlRefs(page.body, page.finalUrl) : null;
}

function truncationFinding(page: CappedPage, ctx: PageContext): Finding {
	const kib = Math.ceil(new TextEncoder().encode(page.body ?? '').length / 1024);
	return webFinding(ctx, 'info', 'Page analysis truncated', `the page body was longer than the read cap, so analysis covered the first ${kib} KiB.`, { truncated: true });
}

function allClearFinding(ctx: PageContext, readHtml: boolean, truncated: boolean): Finding {
	const scope = readHtml ? 'cookies, mixed content, Subresource Integrity and outbound http links' : 'cookies (the response had no HTML body to read)';
	const caveats = `${ctx.isHttps ? '' : ' The page itself is served over http.'}${truncated ? ' Only the first part of the page was read.' : ''}`;
	return webFinding(ctx, 'info', 'No web content issues found', `checked ${scope}; no issues found.${caveats}`);
}

/** Every finding for one fetched page. A response that is not the site's own page is reported as not assessed. */
export function analyzeWebContentPage(page: CappedPage, domain: string): Finding[] {
	const ctx = pageContext(page, domain);
	const reason = unassessableReason(page.status);
	if (reason !== null) return [notAssessedFinding(ctx, reason, 'unassessable_response')];
	const refs = readRefs(page);
	const findings = [
		...analyzeCookies(page.setCookies, ctx),
		...(refs ? [...analyzeMixedContent(refs, ctx), ...analyzeSubresourceIntegrity(refs, ctx), ...analyzeOutboundHttpLinks(refs, ctx)] : []),
		...(page.truncated ? [truncationFinding(page, ctx)] : []),
	];
	return findings.some((found) => found.severity !== 'info') ? findings : [...findings, allClearFinding(ctx, refs !== null, page.truncated)];
}
