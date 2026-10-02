// SPDX-License-Identifier: BUSL-1.1

/**
 * llms.txt link-integrity check.
 *
 * `/llms.txt` and `/llms-full.txt` are documents a site publishes for AI agents
 * to read and act on. Everything they link to or tell a reader to install is
 * therefore trusted by whoever consumes them. This check looks for the three
 * ways that trust can be inherited by someone else:
 *
 *  1. a linked host whose DNS still points at a deprovisioned third-party
 *     service (dangling CNAME / provider "resource gone" fingerprint), reusing
 *     the `@blackveil/dns-checks` subdomain-takeover sweep on the link hosts;
 *  2. an install command naming a package that is not registered (a claimable
 *     name);
 *  3. an install command naming a package that OSV lists under a malicious-package
 *     (`MAL-`) advisory.
 *
 * Detection only: nothing is ever claimed, registered, or installed. A provider
 * fingerprint is dangling-service evidence, not proof the name can be claimed,
 * and registry existence is never reported as "safe" (an attacker-claimed name
 * resolves too). Whatever was not measured is listed in `notAssessed`.
 *
 * Standalone intelligence tool: out-of-union category, not scored, not in
 * scan_domain. Every egress goes through `safeFetch` (https-only, outbound URL
 * validation) under one shared fetch budget.
 */

import { checkSubdomainTakeover as sweepTakeover, withRobotsGate } from '@blackveil/dns-checks';
import type { FetchFunction } from '@blackveil/dns-checks';
import { HTTPS_TIMEOUT_MS } from '../lib/config';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import { createFetchBudget } from '../lib/fetch-budget';
import { disposeUnreadResponseBody, readJsonResponseCapped, readTextResponseCappedDetailed } from '../lib/response-body';
import { safeFetch } from '../lib/safe-fetch';
import { validateDomain } from '../lib/sanitize';
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckCategory, CheckResult, Finding } from '../lib/scoring';
import { SUBJECT_TERMS_METADATA_KEY } from '@blackveil/dns-checks/scoring';
import { isCompletedCheck } from '../lib/ungraded-display';

const CATEGORY = 'llms_txt' as CheckCategory;

/** The documents fetched — two, well inside check_agent_discovery's 10-document fan-out ceiling. */
const DOCUMENT_PATHS = ['/llms.txt', '/llms-full.txt'] as const;

/** Per-fetch timeout and body cap: the bounds check_agent_discovery applies to attacker-hosted documents. */
const FETCH_TIMEOUT_MS = 5_000;
const MAX_DOCUMENT_BYTES = 256 * 1024;

/** Unique links assessed per call; the rest are reported as not assessed. */
const MAX_LINKS = 200;
/** Unique external hosts handed to the takeover sweep. */
const MAX_EXTERNAL_HOSTS = 50;
/** Unique package references checked against their registry and OSV. */
const MAX_PACKAGES = 20;
/** Links longer than this are dropped rather than echoed back. */
const MAX_URL_LENGTH = 2_048;

/**
 * Hosts (in sweep order) that also get the takeover sweep's A/AAAA-only vector, which
 * costs an HTTPS probe plus a robots.txt fetch per host. Every host always gets the
 * CNAME leg; this only bounds third-party HTTP fan-out from an attacker-supplied list.
 */
const A_RECORD_VECTOR_SAMPLE_CAP = 10;

/**
 * One wall-clock budget for every fetch this check makes, kept well inside the 28s
 * tools/call timeout. DoH lookups carry their own timeouts, so the second phase is
 * also raced against a hard deadline a little past the budget.
 */
const FETCH_BUDGET_MS = 18_000;
const PHASE_DEADLINE_SLACK_MS = 3_000;

/** OSV querybatch returns vulnerability ids only, so this cap is generous. */
const OSV_MAX_BYTES = 256 * 1024;
const OSV_QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';

export type LlmsDocumentStatus = 'found' | 'redirect' | 'not_found' | 'transport_error' | 'too_large';

export interface LlmsDocumentFetch {
	path: string;
	url: string;
	status: LlmsDocumentStatus;
	httpStatus?: number;
	/** Redirect target (not followed). */
	location?: string;
	bytes?: number;
	/** A 200 whose body is an HTML page (SPA catch-all / soft 404), not a text document. */
	softNotFound?: boolean;
	error?: string;
}

export interface LlmsLink {
	url: string;
	scope: 'same-origin' | 'external';
}

export type PackageEcosystem = 'npm' | 'PyPI';

export interface LlmsPackageReference {
	ecosystem: PackageEcosystem;
	name: string;
	registry: 'present' | 'missing' | 'not_assessed';
	osv: 'malicious_advisory' | 'no_malicious_advisory' | 'not_assessed';
	maliciousIds?: string[];
}

export interface NotAssessedItem {
	target: string;
	reason: string;
}

export interface LlmsTxtCheckResult extends CheckResult {
	documents: LlmsDocumentFetch[];
	links: LlmsLink[];
	linkSummary: { discovered: number; assessed: number; truncated: boolean; sameOrigin: number; external: number };
	externalHosts: { discovered: number; swept: string[]; truncated: boolean };
	packages: LlmsPackageReference[];
	/** Everything this call did not measure, and why. Never read an absence of findings past it. */
	notAssessed: NotAssessedItem[];
}

// ── Fetch ────────────────────────────────────────────────────────────────────

const HTML_BODY = /^\s*(?:<!doctype\s+html|<html[\s>]|<head[\s>])/i;

async function fetchDocument(domain: string, path: string, fetchFn: FetchFunction): Promise<{ doc: LlmsDocumentFetch; text?: string }> {
	const url = `https://${domain}${path}`;
	try {
		const resp = await fetchFn(url, { redirect: 'manual', signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
		const httpStatus = resp.status;
		if (httpStatus >= 300 && httpStatus < 400) {
			await disposeUnreadResponseBody(resp);
			const location = resolveHttpUrl(resp.headers.get('location'), url);
			return { doc: { path, url, status: 'redirect', httpStatus, ...(location ? { location } : {}) } };
		}
		if (httpStatus === 404 || httpStatus === 410) {
			await disposeUnreadResponseBody(resp);
			return { doc: { path, url, status: 'not_found', httpStatus } };
		}
		if (!resp.ok) {
			// Neither the document nor a measured absence — grouped with the transport failures.
			await disposeUnreadResponseBody(resp);
			return { doc: { path, url, status: 'transport_error', httpStatus, error: `HTTP ${httpStatus}` } };
		}
		const read = await readTextResponseCappedDetailed(resp, MAX_DOCUMENT_BYTES);
		if (read.overflowed) return { doc: { path, url, status: 'too_large', httpStatus } };
		if (read.errored) return { doc: { path, url, status: 'transport_error', httpStatus, error: 'body read failed' } };
		const text = read.text ?? '';
		if (HTML_BODY.test(text)) return { doc: { path, url, status: 'not_found', httpStatus, softNotFound: true } };
		return { doc: { path, url, status: 'found', httpStatus, bytes: read.bytesRead }, text };
	} catch (err) {
		return { doc: { path, url, status: 'transport_error', error: errorText(err) } };
	}
}

function resolveHttpUrl(raw: string | null, base: string): string | undefined {
	if (!raw) return undefined;
	try {
		const u = new URL(raw, base);
		if (u.protocol !== 'https:' && u.protocol !== 'http:') return undefined;
		return u.href.length <= MAX_URL_LENGTH ? u.href : undefined;
	} catch {
		return undefined;
	}
}

function errorText(err: unknown): string {
	return (err instanceof Error ? err.message : 'fetch failed').slice(0, 200);
}

// ── Links ────────────────────────────────────────────────────────────────────

/**
 * Every quantifier is bounded and confined to one line. The document is attacker-supplied,
 * and the unbounded forms backtrack quadratically: measured 2.2s of CPU on a 64 KiB run of
 * `[`, which extrapolates to ~35s at the 256 KiB cap. A URL that reaches its bound is longer
 * than MAX_URL_LENGTH and is dropped after normalisation.
 */
const MARKDOWN_LINK =
	/\[[^\]\n]{0,512}\]\([ \t]{0,16}<?([^()\s<>]{1,2048})>?(?:[ \t]{1,16}(?:"[^"\n]{0,512}"|'[^'\n]{0,512}'))?[ \t]{0,16}\)/g;
const BARE_URL = /\bhttps?:\/\/[^\s<>()[\]{}"'`|\\^]{1,2048}/gi;
const TRAILING_PUNCTUATION = '.,;:!?*_~';

/** Strip sentence punctuation after a bare URL (a loop, not a `[…]+$` regex, which is quadratic on a long run). */
function trimTrailingPunctuation(raw: string): string {
	let end = raw.length;
	while (end > 0 && TRAILING_PUNCTUATION.includes(raw[end - 1])) end--;
	return raw.slice(0, end);
}

/** Markdown links (relative ones resolved against the document) and bare URLs, normalised and deduped in document order. */
function extractLinks(text: string, documentUrl: string, seen: Set<string>, out: string[]): void {
	const candidates: Array<{ index: number; raw: string }> = [];
	for (const m of text.matchAll(MARKDOWN_LINK)) candidates.push({ index: m.index ?? 0, raw: m[1] });
	for (const m of text.matchAll(BARE_URL)) candidates.push({ index: m.index ?? 0, raw: trimTrailingPunctuation(m[0]) });
	candidates.sort((a, b) => a.index - b.index);
	for (const { raw } of candidates) {
		if (raw.startsWith('#')) continue;
		let u: URL;
		try {
			u = new URL(raw, documentUrl);
		} catch {
			continue;
		}
		if (u.protocol !== 'https:' && u.protocol !== 'http:') continue;
		u.hash = '';
		const href = u.href;
		if (href.length > MAX_URL_LENGTH || seen.has(href)) continue;
		seen.add(href);
		out.push(href);
	}
}

// ── Package references ───────────────────────────────────────────────────────

/**
 * Install commands are read from code only — fenced blocks and inline code spans. Prose
 * ("run npm install to get started") would otherwise yield words as package names, and
 * an unregistered word would be reported as a claimable name.
 *
 * Fences are tracked line by line: a multiline fence regex rescans to the end of the text
 * for every unclosed opener, which is quadratic on an attacker-supplied document. An
 * unclosed fence runs to the end of the document, as in CommonMark.
 */
function codeFragments(text: string): string[] {
	const fragments: string[] = [];
	let fence: string | null = null;
	for (const line of text.split('\n')) {
		const marker = /^[ \t]*(```|~~~)/.exec(line)?.[1];
		if (fence === null) {
			if (marker) fence = marker;
			else for (const m of line.matchAll(/`([^`]{1,2048})`/g)) fragments.push(m[1]);
		} else if (marker === fence && line.trim() === fence) {
			fence = null;
		} else {
			fragments.push(line);
		}
	}
	return fragments;
}

const INSTALL_COMMAND =
	/(?:^|[\s;&|(`$>])(npm\s+(?:i|install|add)|npx|pnpm\s+add|yarn\s+add|pip3?\s+install|uv\s+add|pipx\s+install)(?=\s)([^\n;&|`)#]*)/g;

/** Flags whose next token is a value, not a package (a miss here only skips a package, never invents one). */
const VALUE_FLAGS = new Set([
	'-r',
	'--requirement',
	'-c',
	'--constraint',
	'-e',
	'--editable',
	'-i',
	'--index-url',
	'--extra-index-url',
	'-f',
	'--find-links',
	'-t',
	'--target',
	'--prefix',
	'--root',
	'--python',
	'-p',
	'--registry',
	'--tag',
	'-w',
	'--workspace',
	'--filter',
	'-C',
	'--dir',
	'--index',
	'--group',
	'--optional',
	'--call',
]);

const NPM_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;
const PYPI_NAME = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/i;

function npmPackageName(token: string): string | null {
	if (token.includes(':') || /\.(?:tgz|tar\.gz)$/i.test(token)) return null;
	const at = token.lastIndexOf('@');
	const name = at > 0 ? token.slice(0, at) : token;
	return name.length <= 214 && NPM_NAME.test(name) ? name : null;
}

function pypiPackageName(token: string): string | null {
	if (token.includes('/') || token.includes(':') || /\.(?:whl|zip|tar\.gz)$/i.test(token)) return null;
	const name = token.split(/[\s[;@=<>!~]/)[0];
	// PEP 503 normalisation, so the registry and OSV see the canonical project name.
	return PYPI_NAME.test(name) ? name.toLowerCase().replace(/[-_.]+/g, '-') : null;
}

function extractPackages(text: string): Array<{ ecosystem: PackageEcosystem; name: string }> {
	const found: Array<{ ecosystem: PackageEcosystem; name: string }> = [];
	for (const fragment of codeFragments(text)) {
		for (const m of fragment.matchAll(INSTALL_COMMAND)) {
			const command = m[1].split(/\s+/)[0];
			const ecosystem: PackageEcosystem = /^(?:pip3?|uv|pipx)$/.test(command) ? 'PyPI' : 'npm';
			const isNpx = command === 'npx';
			const tokens = m[2]
				.trim()
				.split(/\s+/)
				.map((t) => t.replace(/^["']|["']$/g, ''))
				.filter(Boolean);
			for (let i = 0; i < tokens.length; i++) {
				const token = tokens[i];
				if (token.startsWith('-')) {
					const [flag, inlineValue] = token.split('=', 2);
					const isNpxPackageFlag = isNpx && (flag === '-p' || flag === '--package');
					const value = inlineValue ?? (VALUE_FLAGS.has(flag) || isNpxPackageFlag ? tokens[++i] : undefined);
					if (isNpxPackageFlag && value) {
						const name = npmPackageName(value);
						if (name) found.push({ ecosystem, name });
					}
					continue;
				}
				const name = ecosystem === 'npm' ? npmPackageName(token) : pypiPackageName(token);
				if (name) found.push({ ecosystem, name });
				// npx runs its first positional; everything after it is that command's arguments.
				if (isNpx) break;
			}
		}
	}
	return found;
}

async function registryPresence(
	pkg: { ecosystem: PackageEcosystem; name: string },
	fetchFn: FetchFunction,
): Promise<'present' | 'missing' | { error: string }> {
	// The registry host is a constant and the name matched a strict pattern, so the path is not attacker-shaped.
	// Redirects are not followed: a followed hop would be egress safeFetch never validated.
	const url =
		pkg.ecosystem === 'npm'
			? `https://registry.npmjs.org/${pkg.name.startsWith('@') ? `@${encodeURIComponent(pkg.name.slice(1))}` : encodeURIComponent(pkg.name)}`
			: `https://pypi.org/pypi/${encodeURIComponent(pkg.name)}/json`;
	try {
		const resp = await fetchFn(url, {
			redirect: 'manual',
			signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
			headers: { accept: pkg.ecosystem === 'npm' ? 'application/vnd.npm.install-v1+json' : 'application/json' },
		});
		await disposeUnreadResponseBody(resp);
		if (resp.status === 200) return 'present';
		if (resp.status === 404) return 'missing';
		return { error: `registry returned HTTP ${resp.status}` };
	} catch (err) {
		return { error: errorText(err) };
	}
}

interface OsvBatchResponse {
	results?: Array<{ vulns?: Array<{ id?: unknown }>; next_page_token?: unknown }>;
}

/**
 * One OSV `querybatch` call for every package. It takes the same `{package:{name,ecosystem}}`
 * query as `/v1/query` but returns vulnerability ids only — all a `MAL-` match needs —
 * where `/v1/query` returns full records whose size for a popular package outruns any
 * sane body cap (measured: 321 vulnerabilities for PyPI django).
 */
async function queryOsv(
	pkgs: ReadonlyArray<{ ecosystem: PackageEcosystem; name: string }>,
	fetchFn: FetchFunction,
): Promise<Array<{ maliciousIds: string[]; paged: boolean }> | { error: string }> {
	try {
		const resp = await fetchFn(OSV_QUERYBATCH_URL, {
			method: 'POST',
			redirect: 'manual',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ queries: pkgs.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem } })) }),
			signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
		});
		if (!resp.ok) {
			await disposeUnreadResponseBody(resp);
			return { error: `OSV returned HTTP ${resp.status}` };
		}
		const json = await readJsonResponseCapped<OsvBatchResponse>(resp, OSV_MAX_BYTES);
		const results = json?.results;
		if (!Array.isArray(results) || results.length !== pkgs.length) return { error: 'OSV response unreadable, oversized, or mismatched' };
		return results.map((r) => ({
			maliciousIds: (Array.isArray(r?.vulns) ? r.vulns : [])
				.map((v) => (typeof v?.id === 'string' ? v.id : ''))
				.filter((id) => /^MAL-[A-Za-z0-9-]{1,64}$/.test(id)),
			paged: typeof r?.next_page_token === 'string' && r.next_page_token.length > 0,
		}));
	} catch (err) {
		return { error: errorText(err) };
	}
}

// ── Phase deadline ───────────────────────────────────────────────────────────

const DEADLINE = Symbol('deadline');

async function beforeDeadline<T>(work: Promise<T>, ms: number): Promise<T | typeof DEADLINE> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<typeof DEADLINE>((resolve) => {
		timer = setTimeout(() => resolve(DEADLINE), Math.max(0, ms));
	});
	try {
		return await Promise.race([work, deadline]);
	} finally {
		clearTimeout(timer);
	}
}

// ── Check ────────────────────────────────────────────────────────────────────

function describeDocument(doc: LlmsDocumentFetch): string {
	switch (doc.status) {
		case 'found':
			return `${doc.path}: found (${doc.bytes ?? 0} bytes)`;
		case 'not_found':
			return doc.softNotFound
				? `${doc.path}: not found (HTTP ${doc.httpStatus} served an HTML page, not a text document)`
				: `${doc.path}: not found (HTTP ${doc.httpStatus})`;
		case 'redirect':
			return `${doc.path}: redirect (HTTP ${doc.httpStatus}${doc.location ? ` to ${doc.location}` : ''}), not followed`;
		case 'too_large':
			return `${doc.path}: larger than the ${MAX_DOCUMENT_BYTES}-byte read cap`;
		default:
			return `${doc.path}: fetch failed (${doc.error ?? 'transport error'})`;
	}
}

function notAssessedReason(doc: LlmsDocumentFetch): string {
	switch (doc.status) {
		case 'redirect': {
			const host = doc.location ? new URL(doc.location).hostname : undefined;
			return host
				? `redirect (HTTP ${doc.httpStatus}) not followed; re-run check_llms_txt against ${host} to assess the target`
				: `redirect (HTTP ${doc.httpStatus}) not followed`;
		}
		case 'too_large':
			return `exceeds the ${MAX_DOCUMENT_BYTES}-byte read cap`;
		default:
			return `fetch failed (${doc.error ?? 'transport error'})`;
	}
}

/**
 * Inspect a domain's published llms.txt / llms-full.txt for dangling link hosts,
 * unregistered package names, and packages under an OSV malicious-package advisory.
 *
 * @param domain     Validated domain whose `https://<domain>/llms.txt` is inspected.
 * @param dnsOptions DoH transport options threaded from the runtime.
 */
export async function checkLlmsTxt(domain: string, dnsOptions?: QueryDnsOptions): Promise<LlmsTxtCheckResult> {
	const startedAt = Date.now();
	const budget = createFetchBudget(FETCH_BUDGET_MS);
	const fetchFn: FetchFunction = budget.wrap(safeFetch);
	const findings: Finding[] = [];
	const notAssessed: NotAssessedItem[] = [];
	let transient = false;

	// 1. Fetch both documents, classified separately.
	const fetched = await Promise.all(DOCUMENT_PATHS.map((path) => fetchDocument(domain, path, fetchFn)));
	const documents = fetched.map((f) => f.doc);
	for (const doc of documents) {
		if (doc.status === 'found' || doc.status === 'not_found') continue;
		notAssessed.push({ target: doc.path, reason: notAssessedReason(doc) });
		if (doc.status === 'transport_error') transient = true;
	}
	const anyFound = documents.some((d) => d.status === 'found');
	const allNotFound = documents.every((d) => d.status === 'not_found');
	findings.push(
		createFinding(
			CATEGORY,
			anyFound ? 'llms.txt published' : allNotFound ? 'No llms.txt published' : 'llms.txt could not be assessed',
			'info',
			`${domain}: ${documents.map(describeDocument).join('; ')}.`,
			{ documents: documents.map((d) => ({ path: d.path, status: d.status, httpStatus: d.httpStatus })) },
		),
	);

	// 2. Links: normalised, deduped, capped, tagged.
	const seen = new Set<string>();
	const hrefs: string[] = [];
	const packageRefs: Array<{ ecosystem: PackageEcosystem; name: string }> = [];
	for (const { doc, text } of fetched) {
		if (text === undefined) continue;
		extractLinks(text, doc.url, seen, hrefs);
		packageRefs.push(...extractPackages(text));
	}
	const origin = `https://${domain}`;
	const links: LlmsLink[] = hrefs
		.slice(0, MAX_LINKS)
		.map((url) => ({ url, scope: new URL(url).origin === origin ? 'same-origin' : 'external' }));
	const linksTruncated = hrefs.length > MAX_LINKS;
	if (linksTruncated) {
		notAssessed.push({
			target: 'links',
			reason: `${hrefs.length - MAX_LINKS} of ${hrefs.length} unique links beyond the ${MAX_LINKS}-link cap`,
		});
	}
	const externalCount = links.filter((l) => l.scope === 'external').length;
	if (anyFound) {
		findings.push(
			createFinding(
				CATEGORY,
				`${links.length} link(s) parsed (${links.length - externalCount} same-origin, ${externalCount} external)`,
				'info',
				`Parsed ${hrefs.length} unique link(s) from the published document(s); ${links.length} assessed.`,
				{ discovered: hrefs.length, assessed: links.length, truncated: linksTruncated },
			),
		);
	}

	// 3. External hosts for the takeover sweep. Only public DNS names are swept; the scanned host itself is not "external".
	const hostSet = new Set<string>();
	let unsweepable = 0;
	for (const link of links) {
		if (link.scope !== 'external') continue;
		const host = new URL(link.url).hostname;
		if (host === domain || hostSet.has(host)) continue;
		if (!validateDomain(host).valid) {
			unsweepable++;
			continue;
		}
		hostSet.add(host);
	}
	if (unsweepable > 0) {
		notAssessed.push({ target: 'hosts', reason: `${unsweepable} link host(s) are IP literals or non-public names and were not swept` });
	}
	const allHosts = [...hostSet];
	const hosts = allHosts.slice(0, MAX_EXTERNAL_HOSTS);
	if (allHosts.length > MAX_EXTERNAL_HOSTS) {
		notAssessed.push({
			target: 'hosts',
			reason: `${allHosts.length - MAX_EXTERNAL_HOSTS} of ${allHosts.length} external hosts beyond the ${MAX_EXTERNAL_HOSTS}-host cap`,
		});
	}
	if (hosts.length > A_RECORD_VECTOR_SAMPLE_CAP) {
		notAssessed.push({
			target: 'hosts',
			reason: `A/AAAA-only shared-hosting fingerprint checked on the first ${A_RECORD_VECTOR_SAMPLE_CAP} of ${hosts.length} hosts (every host gets the dangling-CNAME check)`,
		});
	}

	// 4. Package references (deduped, capped).
	const packageKeys = new Set<string>();
	const uniquePackages: Array<{ ecosystem: PackageEcosystem; name: string }> = [];
	for (const p of packageRefs) {
		const key = `${p.ecosystem}:${p.name}`;
		if (packageKeys.has(key)) continue;
		packageKeys.add(key);
		uniquePackages.push(p);
	}
	const checkedPackages = uniquePackages.slice(0, MAX_PACKAGES);
	if (uniquePackages.length > MAX_PACKAGES) {
		notAssessed.push({
			target: 'packages',
			reason: `${uniquePackages.length - MAX_PACKAGES} of ${uniquePackages.length} package references beyond the ${MAX_PACKAGES}-package cap`,
		});
	}

	// Takeover probes cut short by the shared budget are recorded rather than read as clean.
	let probeCut = false;
	const observingFetch: FetchFunction = async (url, init) => {
		try {
			return await fetchFn(url, init);
		} catch (err) {
			if (!url.endsWith('/robots.txt') && !budget.canIssueRequest()) probeCut = true;
			throw err;
		}
	};

	const phaseDeadlineMs = startedAt + FETCH_BUDGET_MS + PHASE_DEADLINE_SLACK_MS - Date.now();
	const [sweep, registry, osv] = await Promise.all([
		hosts.length === 0
			? Promise.resolve(null)
			: beforeDeadline(
					sweepTakeover(domain, makeQueryDNS(dnsOptions), {
						timeout: dnsOptions?.timeoutMs ?? HTTPS_TIMEOUT_MS,
						fetchFn: withRobotsGate(observingFetch),
						subdomains: hosts,
						aRecordVectorSampleCap: A_RECORD_VECTOR_SAMPLE_CAP,
					}),
					phaseDeadlineMs,
				),
		beforeDeadline(Promise.all(checkedPackages.map((p) => registryPresence(p, fetchFn))), phaseDeadlineMs),
		checkedPackages.length === 0 ? Promise.resolve(null) : beforeDeadline(queryOsv(checkedPackages, fetchFn), phaseDeadlineMs),
	]);

	// Dangling link hosts.
	if (sweep === DEADLINE) {
		transient = true;
		notAssessed.push({ target: 'hosts', reason: `takeover sweep of ${hosts.length} host(s) did not finish inside the time budget` });
	} else if (sweep) {
		if (!isCompletedCheck(sweep)) {
			transient = true;
			notAssessed.push({ target: 'hosts', reason: `takeover sweep of ${hosts.length} host(s) failed: every DNS probe errored` });
		} else {
			let evidenceCount = 0;
			for (const f of sweep.findings) {
				const meta = (f.metadata ?? {}) as Record<string, unknown>;
				if (f.severity !== 'info') {
					evidenceCount++;
					const host = /^Subdomain (\S+)/.exec(f.detail)?.[1];
					findings.push(
						createFinding(
							CATEGORY,
							host && !f.title.includes(host) ? `Linked host ${host}: ${f.title}` : `Linked host: ${f.title}`,
							f.severity,
							`A link in the published llms.txt document(s) points at ${host ?? 'this host'}, so any reader or AI agent that follows it reaches whatever now answers for that name. ${f.detail} This is dangling-service evidence, not proof that the name can be claimed.`,
							{ ...meta, linkedHost: host, evidenceSource: 'subdomain_takeover' },
						),
					);
				} else if (meta.inconclusive === true) {
					transient = true;
					notAssessed.push({ target: 'host', reason: f.title });
				}
				if (Array.isArray(meta.subdomainsUnmeasured)) {
					transient = true;
					for (const h of meta.subdomainsUnmeasured)
						notAssessed.push({ target: String(h), reason: 'DNS lookup failed; not assessed for takeover' });
				}
			}
			if (evidenceCount === 0) {
				findings.push(
					createFinding(
						CATEGORY,
						`No dangling-host signal on ${hosts.length} linked external host(s)`,
						'info',
						`Swept ${hosts.length} external host(s) linked from llms.txt for dangling CNAMEs against a known third-party service list and, on A/AAAA-only hosts, an unmapped shared-hosting fingerprint. Other takeover vectors are not modelled, and this says nothing about whether the linked content itself is trustworthy.`,
						{ hostsSwept: hosts.length },
					),
				);
			}
		}
		if (probeCut) {
			transient = true;
			notAssessed.push({ target: 'hosts', reason: 'at least one takeover fingerprint probe was cut short by the time budget' });
		}
	}

	// Package references.
	const osvFailed = osv === DEADLINE ? 'OSV query did not finish inside the time budget' : osv && 'error' in osv ? osv.error : null;
	if (osvFailed) {
		transient = true;
		notAssessed.push({ target: 'osv', reason: `malicious-package lookup unavailable: ${osvFailed}` });
	}
	const packages: LlmsPackageReference[] = checkedPackages.map((p, i) => {
		const presence = registry === DEADLINE ? { error: 'registry lookup did not finish inside the time budget' } : registry[i];
		const osvResult = osvFailed || !Array.isArray(osv) ? null : osv[i];
		const maliciousIds = osvResult?.maliciousIds ?? [];
		const ref: LlmsPackageReference = {
			ecosystem: p.ecosystem,
			name: p.name,
			registry: typeof presence === 'string' ? presence : 'not_assessed',
			osv: !osvResult
				? 'not_assessed'
				: maliciousIds.length > 0
					? 'malicious_advisory'
					: osvResult.paged
						? 'not_assessed'
						: 'no_malicious_advisory',
			...(maliciousIds.length > 0 ? { maliciousIds } : {}),
		};
		if (typeof presence !== 'string') {
			transient = true;
			notAssessed.push({ target: `${p.ecosystem}:${p.name}`, reason: `registry lookup failed (${presence.error})` });
		}
		if (osvResult?.paged && ref.osv === 'not_assessed') {
			notAssessed.push({ target: `${p.ecosystem}:${p.name}`, reason: 'OSV result was paginated; only the first page was read' });
		}
		return ref;
	});

	for (const ref of packages) {
		const label = `${ref.ecosystem}:${ref.name}`;
		if (ref.osv === 'malicious_advisory') {
			const advisoryIds = (ref.maliciousIds ?? []).join(', ');
			findings.push(
				createFinding(
					CATEGORY,
					`Referenced package has a malicious-package advisory: ${label}`,
					'critical',
					`An install command in llms.txt names ${ref.ecosystem} package "${ref.name}", which OSV lists under malicious-package advisory ${advisoryIds}. Anyone, human or AI agent, following the documented install step would run code the advisory identifies as malicious. Remove or correct the reference.`,
					{
						ecosystem: ref.ecosystem,
						package: ref.name,
						osvIds: ref.maliciousIds,
						[SUBJECT_TERMS_METADATA_KEY]: [label, ref.ecosystem, ref.name, advisoryIds],
					},
				),
			);
		}
		if (ref.registry === 'missing') {
			findings.push(
				createFinding(
					CATEGORY,
					`Referenced package is not registered: ${label}`,
					'high',
					`An install command in llms.txt names ${ref.ecosystem} package "${ref.name}", but ${ref.ecosystem === 'npm' ? 'the npm registry' : 'PyPI'} returned 404 for it. An unregistered name can be claimed by anyone, and the documented install step would then run their code. Correct the reference or register the name.`,
					{
						ecosystem: ref.ecosystem,
						package: ref.name,
						registryStatus: 404,
						[SUBJECT_TERMS_METADATA_KEY]: [label, ref.ecosystem, ref.name],
					},
				),
			);
		}
	}
	const unflagged = packages.filter((p) => p.registry === 'present' && p.osv === 'no_malicious_advisory');
	if (unflagged.length > 0) {
		findings.push(
			createFinding(
				CATEGORY,
				`${unflagged.length} referenced package(s) registered, no OSV malicious-package advisory on record`,
				'info',
				`${unflagged.map((p) => `${p.ecosystem}:${p.name}`).join(', ')}. Registry existence is not a safety signal (a name an attacker has already claimed resolves too), and no MAL- advisory only means none is on record.`,
				{ packages: unflagged.map((p) => `${p.ecosystem}:${p.name}`) },
			),
		);
	}

	if (notAssessed.length > 0) {
		const shown = notAssessed.slice(0, 20).map((n) => `${n.target}: ${n.reason}`);
		findings.push(
			createFinding(
				CATEGORY,
				`Not assessed: ${notAssessed.length} item(s)`,
				'info',
				`${shown.join('; ')}${notAssessed.length > shown.length ? `; +${notAssessed.length - shown.length} more` : ''}. Nothing here was measured, so no absence of findings should be read from it.`,
				{ inconclusive: true, notAssessedCount: notAssessed.length },
			),
		);
	}

	// No document was obtained and at least one fetch was not a measured absence: there is no verdict to give.
	const unmeasured = !anyFound && !allNotFound;
	const base = unmeasured
		? { ...buildCheckResult(CATEGORY, findings), score: 0, passed: false, checkStatus: 'error' as const, partial: true }
		: { ...buildCheckResult(CATEGORY, findings), ...(transient ? { partial: true } : {}) };

	return {
		...base,
		documents,
		links,
		linkSummary: {
			discovered: hrefs.length,
			assessed: links.length,
			truncated: linksTruncated,
			sameOrigin: links.length - externalCount,
			external: externalCount,
		},
		externalHosts: { discovered: allHosts.length, swept: hosts, truncated: allHosts.length > MAX_EXTERNAL_HOSTS },
		packages,
		notAssessed,
	};
}
