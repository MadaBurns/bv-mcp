// SPDX-License-Identifier: BUSL-1.1

/**
 * Bounded, sampled Content-Security-Policy header consistency audit.
 *
 * This is deliberately an unregistered beta primitive: it does not synthesize a
 * policy, execute page content, authenticate, leave the target origin, or affect
 * scoring. Every production fetch flows through the existing safe-fetch,
 * robots, fetch-budget, and bounded-body primitives.
 */

import {
	RobotsDisallowedError,
	SCANNER_USER_AGENT,
	createRobotsGroupCache,
	withRobotsGate,
	type FetchFunction,
} from '@blackveil/dns-checks';

import { createFetchBudget } from '../lib/fetch-budget';
import { createRobotsFetchMemo, withRobotsFetchMemo, type RobotsFetchMemo } from '../lib/robots-memo';
import { createRobotsProvenance, type RobotsResolutionStamp } from '../lib/robots-provenance';
import { safeFetch } from '../lib/safe-fetch';
import { readTextResponseCappedDetailed, disposeUnreadResponseBody } from '../lib/response-body';
import { sanitizeDomain, validateDomain } from '../lib/sanitize';

export const CSP_CRAWL_LIMITS = Object.freeze({
	maxPages: 10,
	maxRedirectsPerPage: 3,
	maxPageBytes: 256 * 1024,
	maxTotalBytes: 2 * 1024 * 1024,
	maxLinksPerPage: 256,
	budgetMs: 10_000,
});

export type MeasurementStatus = 'measured' | 'partial' | 'not-assessed';

export type CspPageNotAssessedReason = 'fetch_failed' | 'http_error' | 'redirect_invalid' | 'redirect_limit' | 'robots_disallowed';

export type CspDiscoveryStatus = 'measured' | 'not-assessed';

export type CspDiscoveryNotAssessedReason = 'body_too_large' | 'body_unreadable' | 'body_budget_exhausted' | 'non_html';

export interface CspPageObservation {
	url: string;
	status: 'measured' | 'not-assessed';
	httpStatus?: number;
	notAssessedReason?: CspPageNotAssessedReason;
	enforcingPolicy?: string;
	reportOnlyPolicy?: string;
	unsafeTokens: string[];
	discovery: {
		status: CspDiscoveryStatus;
		notAssessedReason?: CspDiscoveryNotAssessedReason;
	};
}

export interface CspCoverageSummary {
	measuredPages: number;
	pagesWithEnforcingPolicy: number;
	pagesWithReportOnlyPolicy: number;
	distinctHeaderProfiles: number;
	headersConsistent: boolean;
	unsafeTokens: string[];
}

export interface CspCoverageResult {
	schemaVersion: '1.0';
	probe: 'csp_header_consistency';
	domain: string;
	status: MeasurementStatus;
	observedAt: string;
	scope: 'sampled_same_origin';
	nonScoring: true;
	limits: typeof CSP_CRAWL_LIMITS;
	pagesAttempted: number;
	pages: CspPageObservation[];
	summary?: CspCoverageSummary;
	partialReasons: string[];
	robotsResolution?: RobotsResolutionStamp;
}

export interface AuditCspCoverageOptions {
	/** Test seam. Production callers omit this so safeFetch remains mandatory. */
	fetchFn?: FetchFunction;
	/** One caller-owned memo; defaults to a fresh per-audit memo. */
	robotsMemo?: RobotsFetchMemo;
	budgetMs?: number;
	now?: () => string;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const UNSAFE_TOKENS = ["'unsafe-eval'", "'unsafe-inline'", "'wasm-unsafe-eval'"] as const;

function normalizePolicy(value: string | null): string | undefined {
	if (!value) return undefined;
	const normalized = value
		.split(';')
		.map((directive) => directive.trim().replace(/\s+/g, ' '))
		.filter(Boolean)
		.join('; ');
	return normalized || undefined;
}

function unsafeTokensFrom(...policies: Array<string | undefined>): string[] {
	const combined = policies.filter(Boolean).join(' ').toLowerCase();
	return UNSAFE_TOKENS.filter((token) => combined.includes(token));
}

function canonicalSameOriginUrl(raw: string, base: URL, origin: string): URL | null {
	let candidate: URL;
	try {
		candidate = new URL(raw.replace(/&amp;/gi, '&'), base);
	} catch {
		return null;
	}
	if (candidate.protocol !== 'https:' || candidate.origin !== origin || candidate.username || candidate.password || candidate.search)
		return null;
	candidate.hash = '';
	return candidate;
}

/** Extract a conservative subset of anchor hrefs, sorted for deterministic BFS. */
export function extractSameOriginLinks(html: string, baseUrl: string): string[] {
	const base = new URL(baseUrl);
	const found = new Set<string>();
	const hrefPattern = /<a\b[^>]*\bhref\s*=\s*(["'])(.*?)\1/giu;
	for (const match of html.matchAll(hrefPattern)) {
		const candidate = canonicalSameOriginUrl(match[2] ?? '', base, base.origin);
		if (!candidate) continue;
		found.add(candidate.href);
		if (found.size >= CSP_CRAWL_LIMITS.maxLinksPerPage) break;
	}
	return [...found].sort((a, b) => a.localeCompare(b));
}

interface FetchPageOutcome {
	response?: Response;
	url: string;
	reason?: CspPageNotAssessedReason;
}

async function fetchWithSameOriginRedirects(fetchFn: FetchFunction, requestedUrl: string, origin: string): Promise<FetchPageOutcome> {
	let current = new URL(requestedUrl);
	for (let redirects = 0; ; redirects++) {
		let response: Response;
		try {
			response = await fetchFn(current.href, { method: 'GET', redirect: 'manual', credentials: 'omit' });
		} catch (error) {
			return { url: current.href, reason: error instanceof RobotsDisallowedError ? 'robots_disallowed' : 'fetch_failed' };
		}

		if (!REDIRECT_STATUSES.has(response.status)) return { response, url: current.href };
		if (redirects >= CSP_CRAWL_LIMITS.maxRedirectsPerPage) {
			await disposeUnreadResponseBody(response);
			return { url: current.href, reason: 'redirect_limit' };
		}
		const location = response.headers.get('location');
		const next = location ? canonicalSameOriginUrl(location, current, origin) : null;
		await disposeUnreadResponseBody(response);
		if (!next) return { url: current.href, reason: 'redirect_invalid' };
		current = next;
	}
}

function pageHeaderProfile(page: CspPageObservation): string {
	return `${page.enforcingPolicy ?? '<absent>'}\n${page.reportOnlyPolicy ?? '<absent>'}`;
}

function summarizePages(pages: CspPageObservation[]): CspCoverageSummary | undefined {
	const measured = pages.filter((page) => page.status === 'measured');
	if (measured.length === 0) return undefined;
	const profiles = new Set(measured.map(pageHeaderProfile));
	return {
		measuredPages: measured.length,
		pagesWithEnforcingPolicy: measured.filter((page) => page.enforcingPolicy !== undefined).length,
		pagesWithReportOnlyPolicy: measured.filter((page) => page.reportOnlyPolicy !== undefined).length,
		distinctHeaderProfiles: profiles.size,
		headersConsistent: profiles.size === 1,
		unsafeTokens: [...new Set(measured.flatMap((page) => page.unsafeTokens))].sort(),
	};
}

/**
 * Audit at most ten same-origin HTTPS pages using a deterministic breadth-first
 * traversal. Query-bearing URLs are excluded to avoid crawling unbounded state.
 */
export async function auditCspCoverage(domainInput: string, options: AuditCspCoverageOptions = {}): Promise<CspCoverageResult> {
	const validation = validateDomain(domainInput);
	if (!validation.valid) throw new Error(`Invalid domain: ${validation.error ?? 'validation failed'}`);
	const domain = sanitizeDomain(domainInput);
	const origin = `https://${domain}`;
	const seed = `${origin}/`;
	const now = options.now ?? (() => new Date().toISOString());
	const budget = createFetchBudget(options.budgetMs ?? CSP_CRAWL_LIMITS.budgetMs);
	const provenance = createRobotsProvenance(domain);
	const memo = options.robotsMemo ?? createRobotsFetchMemo();
	const baseFetch = options.fetchFn ?? ((url: string, init?: RequestInit) => safeFetch(url, init));
	const guardedFetch = withRobotsGate(withRobotsFetchMemo(budget.wrap(baseFetch), memo), {
		userAgent: SCANNER_USER_AGENT,
		groupCache: createRobotsGroupCache(),
		cacheNamespace: 'csp-sampled-crawl',
		onRobotsResolution: provenance.onResolution,
	});

	const queue = [seed];
	const queued = new Set(queue);
	const visited = new Set<string>();
	const pages: CspPageObservation[] = [];
	const partialReasons = new Set<string>();
	let retainedBodyBytes = 0;

	while (queue.length > 0 && pages.length < CSP_CRAWL_LIMITS.maxPages) {
		if (!budget.canIssueRequest()) {
			partialReasons.add('fetch_budget_exhausted');
			break;
		}
		const requestedUrl = queue.shift()!;
		queued.delete(requestedUrl);
		if (visited.has(requestedUrl)) continue;
		visited.add(requestedUrl);
		const fetched = await fetchWithSameOriginRedirects(guardedFetch, requestedUrl, origin);
		if (!fetched.response) {
			pages.push({
				url: fetched.url,
				status: 'not-assessed',
				notAssessedReason: fetched.reason,
				unsafeTokens: [],
				discovery: { status: 'not-assessed', notAssessedReason: 'non_html' },
			});
			partialReasons.add(fetched.reason ?? 'fetch_failed');
			continue;
		}
		visited.add(fetched.url);

		const response = fetched.response;
		if (response.status < 200 || response.status >= 400) {
			await disposeUnreadResponseBody(response);
			pages.push({
				url: fetched.url,
				status: 'not-assessed',
				httpStatus: response.status,
				notAssessedReason: 'http_error',
				unsafeTokens: [],
				discovery: { status: 'not-assessed', notAssessedReason: 'non_html' },
			});
			partialReasons.add('http_error');
			continue;
		}

		const enforcingPolicy = normalizePolicy(response.headers.get('content-security-policy'));
		const reportOnlyPolicy = normalizePolicy(response.headers.get('content-security-policy-report-only'));
		const page: CspPageObservation = {
			url: fetched.url,
			status: 'measured',
			httpStatus: response.status,
			enforcingPolicy,
			reportOnlyPolicy,
			unsafeTokens: unsafeTokensFrom(enforcingPolicy, reportOnlyPolicy),
			discovery: { status: 'measured' },
		};

		const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
		if (!contentType.includes('text/html')) {
			await disposeUnreadResponseBody(response);
			page.discovery = { status: 'not-assessed', notAssessedReason: 'non_html' };
			partialReasons.add('non_html');
			pages.push(page);
			continue;
		}

		const remainingBytes = CSP_CRAWL_LIMITS.maxTotalBytes - retainedBodyBytes;
		if (remainingBytes <= 0) {
			await disposeUnreadResponseBody(response);
			page.discovery = { status: 'not-assessed', notAssessedReason: 'body_budget_exhausted' };
			partialReasons.add('body_budget_exhausted');
			pages.push(page);
			break;
		}
		const readCap = Math.min(CSP_CRAWL_LIMITS.maxPageBytes, remainingBytes);
		const read =
			response.body === null
				? { text: '', bytesRead: 0, overflowed: false, errored: false }
				: await readTextResponseCappedDetailed(response, readCap);
		retainedBodyBytes += read.bytesRead;
		if (read.text === null) {
			const reason = read.overflowed ? 'body_too_large' : 'body_unreadable';
			page.discovery = { status: 'not-assessed', notAssessedReason: reason };
			partialReasons.add(reason);
			pages.push(page);
			if (retainedBodyBytes >= CSP_CRAWL_LIMITS.maxTotalBytes) {
				partialReasons.add('body_budget_exhausted');
				break;
			}
			continue;
		}
		for (const link of extractSameOriginLinks(read.text, fetched.url)) {
			if (!visited.has(link) && !queued.has(link)) {
				queue.push(link);
				queued.add(link);
			}
		}
		pages.push(page);
	}

	if (queue.length > 0 && pages.length >= CSP_CRAWL_LIMITS.maxPages) partialReasons.add('max_pages_reached');
	const robotsResolution = provenance.summarize();
	if (robotsResolution?.failOpen) partialReasons.add('robots_fail_open');
	const summary = summarizePages(pages);
	const status: MeasurementStatus = !summary ? 'not-assessed' : partialReasons.size > 0 ? 'partial' : 'measured';
	return {
		schemaVersion: '1.0',
		probe: 'csp_header_consistency',
		domain,
		status,
		observedAt: now(),
		scope: 'sampled_same_origin',
		nonScoring: true,
		limits: CSP_CRAWL_LIMITS,
		pagesAttempted: pages.length,
		pages,
		...(summary ? { summary } : {}),
		partialReasons: [...partialReasons].sort(),
		...(robotsResolution ? { robotsResolution } : {}),
	};
}
