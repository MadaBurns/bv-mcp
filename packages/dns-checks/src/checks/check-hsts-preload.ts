// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { CheckResult, FetchFunction } from '../types';
import { buildCheckResult, buildNotAssessedResult } from '../check-utils';
import { readResponseTextCapped } from '../response-body';
import { SCANNER_USER_AGENT } from '../robots-gate';
import { fetchPageCapped } from './page-fetch';
import type { CappedPage } from './page-fetch';
import { analyzeHstsPreload, assessPreloadEligibility, httpRedirectsToHttps, notAssessedFinding, observeHsts, parsePreloadStatus, PRELOAD_STATUS_API, PRELOAD_STATUS_MAX_BYTES } from './hsts-preload-analysis';
import type { HstsObservation, PreloadMembership } from './hsts-preload-analysis';

/** Time budget (ms) for each request when the caller sets none. */
const DEFAULT_TIMEOUT_MS = 5_000;

/** Bytes of body kept from the plain-HTTP probe; only its redirect is read. */
const HTTP_PROBE_MAX_BYTES = 1_024;

export interface CheckHstsPreloadOptions {
	/** Time budget (ms) for each request. Default 5000. */
	timeout?: number;
	/**
	 * Pages the caller already fetched, so one GET per host serves every web check. Only `apex` is
	 * read. A key left out (`undefined`) is fetched here; `null` means the caller's fetch failed and
	 * is not retried.
	 */
	pages?: { apex?: CappedPage | null; www?: CappedPage | null };
}

/**
 * The apex's OWN HTTPS response. A supplied page that followed a redirect carries the headers of
 * the final host (often www), not the apex, and hstspreload.org reads the apex's response, so that
 * case fetches the first hop only.
 */
async function resolveApexPage(domain: string, supplied: CappedPage | null | undefined, fetchFn: FetchFunction, timeout: number): Promise<CappedPage | null> {
	if (supplied === null) return null;
	if (supplied !== undefined && supplied.redirects.length === 0) return supplied;
	return fetchPageCapped(`https://${domain}/`, fetchFn, { timeout, maxRedirects: 0, maxBytes: HTTP_PROBE_MAX_BYTES });
}

async function fetchMembership(domain: string, fetchFn: FetchFunction, timeout: number): Promise<PreloadMembership> {
	try {
		const response = await fetchFn(`${PRELOAD_STATUS_API}?domain=${encodeURIComponent(domain)}`, {
			method: 'GET',
			redirect: 'manual',
			headers: { Accept: 'application/json', 'User-Agent': SCANNER_USER_AGENT },
			signal: AbortSignal.timeout(timeout),
		});
		if (!response.ok) {
			void response.body?.cancel().catch(() => undefined);
			return { status: 'not_assessed', reason: `hstspreload.org answered HTTP ${response.status}` };
		}
		const text = await readResponseTextCapped(response, PRELOAD_STATUS_MAX_BYTES);
		return text === null ? { status: 'not_assessed', reason: 'hstspreload.org returned an oversized response' } : parsePreloadStatus(text, domain);
	} catch {
		return { status: 'not_assessed', reason: 'the hstspreload.org status request failed' };
	}
}

/** The whole-result abstention, when neither the apex header nor the list status could be read. */
function bothUnmeasured(observation: HstsObservation, membership: PreloadMembership): CheckResult | null {
	if (observation.measured || membership.status !== 'not_assessed') return null;
	const reason = `${observation.reason}, and the hstspreload.org status could not be read`;
	return buildNotAssessedResult('hsts_preload', notAssessedFinding('HSTS preload not assessed', reason, 'fetch_failed'));
}

/** Structured facts for consumers; `null` where a fact was not measured. */
function resultMetadata(observation: HstsObservation, redirectsToHttps: boolean | null, membership: PreloadMembership): Record<string, unknown> {
	const eligibility = observation.measured ? assessPreloadEligibility(observation.header, { redirectsToHttps }) : null;
	return {
		membership: membership.status,
		eligible: eligibility?.eligible ?? null,
		maxAge: eligibility?.maxAge ?? null,
		includeSubDomains: eligibility?.includeSubDomains ?? null,
		preload: eligibility?.preload ?? null,
		redirectsToHttps,
	};
}

/**
 * Non-scoring HSTS preload check: whether the apex header meets the hstspreload.org submission
 * rules, and whether hstspreload.org already lists the domain.
 *
 * Each half that cannot be measured is reported as not assessed, never as a negative. When neither
 * the apex header nor the list status can be read, the whole result is the not-assessed shape.
 */
export async function checkHstsPreload(domain: string, fetchFn: FetchFunction, options?: CheckHstsPreloadOptions): Promise<CheckResult> {
	const host = domain.toLowerCase();
	const timeout = options?.timeout ?? DEFAULT_TIMEOUT_MS;
	const [apexPage, httpPage, membership] = await Promise.all([
		resolveApexPage(host, options?.pages?.apex, fetchFn, timeout),
		fetchPageCapped(`http://${host}/`, fetchFn, { timeout, maxRedirects: 0, maxBytes: HTTP_PROBE_MAX_BYTES }),
		fetchMembership(host, fetchFn, timeout),
	]);
	const observation = observeHsts(apexPage, host);
	const abstained = bothUnmeasured(observation, membership);
	if (abstained !== null) return abstained;
	const redirectsToHttps = httpRedirectsToHttps(httpPage, host);
	const findings = analyzeHstsPreload(host, observation, redirectsToHttps, membership);
	return buildCheckResult('hsts_preload', findings, undefined, undefined, resultMetadata(observation, redirectsToHttps, membership));
}
