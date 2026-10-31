// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

/**
 * `csp_quality`: a non-scoring read of the Content-Security-Policy a site actually serves.
 *
 * Reads the `content-security-policy` and `content-security-policy-report-only` headers and any
 * `<meta http-equiv="Content-Security-Policy">` tag of the apex and `www` home pages, and
 * evaluates each policy with the token-based evaluator in `./csp-evaluator`. The scored
 * `http_security` category keeps its own substring-based CSP analysis; nothing here feeds it.
 *
 * - A report-only policy is evaluated too, but its findings are `info` and titled "not enforced".
 * - Several policies on one host are evaluated one by one and say so: a request must satisfy all
 *   of them, so the effective policy is their intersection.
 * - Identical findings on the apex and `www` are merged into one finding listing both hosts.
 * - A host that gave no usable answer is NOT a policy-free host. When no host answers, the check
 *   abstains with the not-assessed shape rather than reporting "no CSP".
 */

import type { CheckResult, FetchFunction, Finding, Severity } from '../types';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';
import { fetchPageCapped } from './page-fetch';
import type { CappedPage } from './page-fetch';
import { extractHtmlRefs } from './html-refs';
import { evaluateCsp } from './csp-evaluator';
import type { CspDelivery, CspIssue } from './csp-evaluator';

/** Findings kept in a result. The most severe survive; `metadata.findingsTruncated` counts the rest. */
export const CSP_QUALITY_MAX_FINDINGS = 25;

export interface CheckCspQualityOptions {
	/** Time budget (ms) for each page fetch. */
	timeout?: number;
	/** Pages already fetched by the caller. A host left `undefined` is fetched here; `null` means that fetch failed. */
	pages?: { apex?: CappedPage | null; www?: CappedPage | null };
}

interface PolicyText {
	text: string;
	delivery: CspDelivery;
}

interface HostObservation {
	host: string;
	page: CappedPage | null;
}

interface HostPolicies {
	host: string;
	enforced: PolicyText[];
	reportOnly: PolicyText[];
}

/** A finding before the apex and `www` copies are merged; `key` identifies the same finding across hosts. */
interface Draft {
	key: string;
	severity: Severity;
	title: string;
	detail: string;
	metadata: Record<string, unknown>;
	hosts: string[];
}

const SEVERITY_RANK: Readonly<Record<Severity, number>> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/**
 * Evaluate the CSP of `domain` (apex and `www`).
 *
 * @param fetchFn The injected fetch; the page fetch returns `null` when it throws.
 */
export async function checkCspQuality(domain: string, fetchFn: FetchFunction, opts: CheckCspQualityOptions = {}): Promise<CheckResult> {
	const observations = await observeHosts(domain, fetchFn, opts);
	const measured = observations.flatMap(({ host, page }) => (page !== null && isMeasurable(page) ? [policiesOf(host, page)] : []));
	const unmeasured = observations.filter(({ page }) => page === null || !isMeasurable(page));
	if (measured.length === 0) {
		return buildNotAssessedResult('csp_quality', notAssessedFinding(unmeasured, 'No host returned a page whose CSP could be read.'), 'error');
	}
	const drafts = [...measured.flatMap(hostDrafts), ...unmeasured.map(unmeasuredDraft)];
	const findings = mergeDrafts(drafts);
	const kept = findings.slice(0, CSP_QUALITY_MAX_FINDINGS);
	const metadata = resultMetadata(measured, unmeasured, findings.length - kept.length);
	return buildCheckResult('csp_quality', kept, measured.some((h) => h.enforced.length > 0), undefined, metadata);
}

// ── Fetching ─────────────────────────────────────────────────────────────────

async function observeHosts(domain: string, fetchFn: FetchFunction, opts: CheckCspQualityOptions): Promise<HostObservation[]> {
	const fetchOpts = opts.timeout === undefined ? {} : { timeout: opts.timeout };
	const load = async (host: string, given: CappedPage | null | undefined): Promise<HostObservation> => ({
		host,
		page: given !== undefined ? given : await fetchPageCapped(`https://${host}/`, fetchFn, fetchOpts),
	});
	const wwwHost = `www.${domain}`;
	return Promise.all([load(domain, opts.pages?.apex), ...(domain.startsWith('www.') ? [] : [load(wwwHost, opts.pages?.www)])]);
}

/** A 2xx page that is not an interstitial: only then do its headers describe the site's own policy. */
function isMeasurable(page: CappedPage): boolean {
	return page.status >= 200 && page.status < 300 && page.status !== 202;
}

// ── Reading policies ─────────────────────────────────────────────────────────

/** Split a header value into policies. A comma separates policies; several headers arrive comma-joined. */
function splitPolicies(value: string | null): string[] {
	return (value ?? '')
		.split(',')
		.map((p) => p.trim())
		.filter((p) => p !== '');
}

function metaPolicies(page: CappedPage): string[] {
	return page.body === null ? [] : extractHtmlRefs(page.body, page.finalUrl).metaCsp.filter((p) => p.trim() !== '');
}

function policiesOf(host: string, page: CappedPage): HostPolicies {
	const header = (text: string): PolicyText => ({ text, delivery: 'header' });
	const meta = (text: string): PolicyText => ({ text, delivery: 'meta' });
	return {
		host,
		enforced: [...splitPolicies(page.headers.get('content-security-policy')).map(header), ...metaPolicies(page).map(meta)],
		reportOnly: splitPolicies(page.headers.get('content-security-policy-report-only')).map(header),
	};
}

// ── Drafting findings ────────────────────────────────────────────────────────

function hostDrafts(h: HostPolicies): Draft[] {
	return [
		...h.enforced.flatMap((policy, i) => policyDrafts(h.host, policy, true, i, h.enforced.length)),
		...h.reportOnly.flatMap((policy, i) => policyDrafts(h.host, policy, false, i, h.reportOnly.length)),
		...absenceDrafts(h),
		...intersectionDrafts(h),
	];
}

function policyDrafts(host: string, policy: PolicyText, enforced: boolean, index: number, count: number): Draft[] {
	return evaluateCsp(policy.text, { delivery: policy.delivery }).map((found) => issueDraft(host, policy, enforced, index, count, found));
}

function issueDraft(host: string, policy: PolicyText, enforced: boolean, index: number, count: number, found: CspIssue): Draft {
	const prefix = count > 1 ? `Policy ${index + 1} of ${count} (the policies intersect; a request must satisfy all of them). ` : '';
	return {
		key: JSON.stringify([found.rule, found.directive, found.token ?? null, policy.delivery, enforced, index, count]),
		// A report-only policy blocks nothing, so a weakness in it is informational.
		severity: enforced ? found.severity : 'info',
		title: enforced ? found.title : `${found.title} (report-only, not enforced)`,
		detail: `${prefix}${found.detail}`,
		metadata: {
			rule: found.rule,
			directive: found.directive,
			...(found.token === undefined ? {} : { token: found.token }),
			delivery: policy.delivery,
			enforced,
			policyIndex: index + 1,
			policyCount: count,
			ruleSeverity: found.severity,
			// A graded deficiency in a policy that exists, not an absent control.
			missingControl: false,
		},
		hosts: [host],
	};
}

function absenceDrafts(h: HostPolicies): Draft[] {
	if (h.enforced.length > 0) return [];
	const reportOnly = h.reportOnly.length > 0;
	return [
		{
			key: JSON.stringify(['no-csp', reportOnly]),
			severity: 'medium',
			title: reportOnly ? 'No enforced Content-Security-Policy' : 'No Content-Security-Policy',
			detail: reportOnly
				? 'Only a Content-Security-Policy-Report-Only policy is served. It reports violations but blocks nothing.'
				: 'The page sets no Content-Security-Policy header and no CSP <meta> tag, so the browser applies no restriction on where scripts and other resources load from.',
			metadata: { rule: 'no-csp', enforced: false, reportOnlyPresent: reportOnly, missingControl: true },
			hosts: [h.host],
		},
	];
}

function intersectionDrafts(h: HostPolicies): Draft[] {
	if (h.enforced.length < 2) return [];
	return [
		{
			key: JSON.stringify(['multiple-policies', h.enforced.length]),
			severity: 'info',
			title: 'Multiple Content-Security-Policy policies enforced',
			detail: `${h.enforced.length} enforced policies were found (headers and <meta> tags). Each is evaluated on its own below. A request must satisfy all of them, so the effective policy is their intersection and a weakness in one may be masked by another.`,
			metadata: { rule: 'multiple-policies', enforced: true, policyCount: h.enforced.length, missingControl: false },
			hosts: [h.host],
		},
	];
}

function describeUnmeasured({ page }: HostObservation): string {
	return page === null ? 'no response' : `HTTP ${page.status}`;
}

function unmeasuredDraft(o: HostObservation): Draft {
	return {
		key: JSON.stringify(['not-assessed', o.host]),
		severity: 'info',
		title: 'CSP not assessed for one host',
		detail: `${o.host} gave no readable page (${describeUnmeasured(o)}), so its Content-Security-Policy was not assessed. This is not a finding that the host has no policy.`,
		metadata: { rule: 'not-assessed', inconclusive: true, missingControl: false },
		hosts: [o.host],
	};
}

function notAssessedFinding(unmeasured: HostObservation[], reason: string): Finding {
	const hosts = unmeasured.map((o) => `${o.host} (${describeUnmeasured(o)})`).join(', ');
	return createFinding('csp_quality', 'CSP not assessed', 'info', `${reason} ${hosts}`.trim(), { inconclusive: true });
}

// ── Merging and output ───────────────────────────────────────────────────────

/** Merge drafts that share a key (the same finding on apex and `www`), then order by severity. */
function mergeDrafts(drafts: Draft[]): Finding[] {
	const merged = new Map<string, Draft>();
	for (const draft of drafts) {
		const existing = merged.get(draft.key);
		if (existing === undefined) merged.set(draft.key, { ...draft, hosts: [...draft.hosts] });
		else existing.hosts.push(...draft.hosts);
	}
	return [...merged.values()]
		.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
		.map((d) => createFinding('csp_quality', d.title, d.severity, `${d.detail} Seen on: ${d.hosts.join(', ')}.`, { ...d.metadata, hosts: d.hosts }));
}

function resultMetadata(measured: HostPolicies[], unmeasured: HostObservation[], dropped: number): Record<string, unknown> {
	return {
		hostsAssessed: measured.map((h) => h.host),
		hostsNotAssessed: unmeasured.map((o) => ({ host: o.host, reason: describeUnmeasured(o) })),
		...(dropped > 0 ? { findingsTruncated: dropped } : {}),
	};
}
