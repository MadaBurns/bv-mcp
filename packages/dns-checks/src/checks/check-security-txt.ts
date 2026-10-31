// SPDX-License-Identifier: BUSL-1.1

// Copyright (c) 2023-2026 BLACKVEIL Security

import type { CheckResult, FetchFunction } from '../types';
import { buildCheckResult, buildNotAssessedResult, createFinding } from '../check-utils';
import { fetchPageCapped } from './page-fetch';
import type { CappedPage } from './page-fetch';
import { absentFinding, analyzeSecurityTxt } from './security-txt-analysis';
import type { SecurityTxtLocation } from './security-txt-analysis';

/** security.txt is a few hundred bytes; 64 KiB is the same cap the MTA-STS policy fetch uses. */
const MAX_BYTES = 65_536;

export interface CheckSecurityTxtOptions {
	/** Time budget (ms) per request. Default 5000. */
	timeout?: number;
	/** The clock Expires is judged against. Default the current time. */
	now?: Date;
}

const notAssessed = (reason: string): CheckResult =>
	buildNotAssessedResult('security_txt', createFinding('security_txt', 'security.txt not assessed', 'info', `not assessed: ${reason}.`, { inconclusive: true }));

/**
 * Non-scoring RFC 9116 check: is there a security.txt, is it a real text file, and is it valid,
 * unexpired and (optionally) signed. Falls back to the legacy /security.txt on a 404.
 */
export async function checkSecurityTxt(domain: string, fetchFn: FetchFunction, options?: CheckSecurityTxtOptions): Promise<CheckResult> {
	const host = domain.toLowerCase();
	const get = (path: string): Promise<CappedPage | null> => fetchPageCapped(`https://${host}${path}`, fetchFn, { timeout: options?.timeout, maxBytes: MAX_BYTES });
	const wellKnown = await get('/.well-known/security.txt');
	if (wellKnown === null) return notAssessed(`https://${host}/.well-known/security.txt could not be fetched`);
	let page = wellKnown;
	let location: SecurityTxtLocation = 'well-known';
	if (wellKnown.status === 404) {
		const legacy = await get('/security.txt');
		if (legacy === null) return notAssessed(`https://${host}/security.txt could not be fetched`);
		if (legacy.status === 404) return buildCheckResult('security_txt', [absentFinding(host)]);
		page = legacy;
		location = 'legacy';
	}
	if (page.status !== 200) return notAssessed(`${page.finalUrl} answered HTTP ${page.status}`);
	const findings = analyzeSecurityTxt({ location, url: page.finalUrl, contentType: page.headers.get('content-type'), body: page.body ?? '' }, options?.now ?? new Date());
	return buildCheckResult('security_txt', findings);
}
