// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { CheckResult, FetchFunction, Finding } from '../types';
import { buildCheckResult, buildNotAssessedResult } from '../check-utils';
import { fetchPageCapped } from './page-fetch';
import type { CappedPage } from './page-fetch';
import { analyzeWebContentPage, duplicatePageFinding, notAssessedFinding, pageContext } from './web-content-analysis';
import type { PageContext } from './web-content-analysis';

export interface CheckWebContentOptions {
	/** Time budget (ms) for each host's fetch chain. */
	timeout?: number;
	/**
	 * Pages the caller already fetched, so one GET per host serves every web check. A key left
	 * out (`undefined`) is fetched here; `null` means the caller's fetch failed and is not retried.
	 */
	pages?: { apex?: CappedPage | null; www?: CappedPage | null };
}

interface HostPage {
	host: string;
	url: string;
	page: CappedPage | null;
}

async function resolveHostPage(host: string, supplied: CappedPage | null | undefined, fetchFn: FetchFunction, timeout: number | undefined): Promise<HostPage> {
	const url = `https://${host}/`;
	return { host, url, page: supplied === undefined ? await fetchPageCapped(url, fetchFn, { timeout }) : supplied };
}

/** Context for a host whose fetch produced no page. */
function unreachableContext(host: string, domain: string): PageContext {
	return { host, pageHost: host, domain, isHttps: true };
}

function hostFindings({ host, page }: HostPage, domain: string, analysedUrls: Set<string>): Finding[] {
	if (page === null) return [notAssessedFinding(unreachableContext(host, domain), `https://${host}/ could not be fetched`, 'fetch_failed')];
	if (analysedUrls.has(page.finalUrl)) {
		return [duplicatePageFinding(pageContext(page, domain), page.finalUrl)];
	}
	analysedUrls.add(page.finalUrl);
	return analyzeWebContentPage(page, domain);
}

/**
 * Non-scoring web content check: cookie flags, mixed content, Subresource Integrity and outbound
 * http links on `https://<domain>/` and `https://www.<domain>/`.
 *
 * A host that cannot be fetched, or that answers with a block/redirect-stop/no-content response,
 * is reported per host as not assessed, never as clean. When neither host yields a page the whole
 * result is the not-assessed shape.
 */
export async function checkWebContent(domain: string, fetchFn: FetchFunction, options?: CheckWebContentOptions): Promise<CheckResult> {
	const hosts = domain.startsWith('www.') ? [domain] : [domain, `www.${domain}`];
	const supplied = [options?.pages?.apex, options?.pages?.www];
	const resolved = await Promise.all(hosts.map((host, index) => resolveHostPage(host, supplied[index], fetchFn, options?.timeout)));

	if (resolved.every(({ page }) => page === null)) {
		const ctx = unreachableContext(domain, domain);
		return buildNotAssessedResult('web_content', notAssessedFinding(ctx, `no page could be fetched from ${hosts.join(' or ')}`, 'fetch_failed'));
	}
	const analysedUrls = new Set<string>();
	return buildCheckResult('web_content', resolved.flatMap((hostPage) => hostFindings(hostPage, domain, analysedUrls)));
}
