// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF canary — daily synthetic probe against a curated list of domains that
 * publish stable, well-formed SPF records. Run from the daily cron, this turns
 * "elevated null SPF" from a dashboard impression into a tripwire:
 *   - if more than `nullRateThreshold` of the canary set reports "No SPF record
 *     found", an alert fires with the failing domains attached, so the next
 *     responder has a concrete reproducer instead of an absence pattern.
 *
 * The list is intentionally narrow (well-known, high-stability publishers) so
 * a single null is significant, not noise. Adding/removing entries is allowed
 * — keep them domains that historically publish SPF and are unlikely to ever
 * stop.
 */

import { checkSpf } from '../tools/check-spf';

/**
 * Curated SPF-publishing domains. Each is verified to publish a `v=spf1` TXT
 * record at the apex; a null here means either our lookup path regressed or
 * the publisher genuinely dropped SPF (rare, newsworthy).
 */
export const SPF_CANARY_DOMAINS: readonly string[] = [
	'google.com',
	'microsoft.com',
	'paypal.com',
	'stripe.com',
	'anthropic.com',
	'netflix.com',
	'apple.com',
	'facebook.com',
	'salesforce.com',
	'slack.com',
	'adobe.com',
	'nytimes.com',
	'bbc.co.uk',
	'spotify.com',
	'mozilla.org',
	'cloudflare.com',
	'github.com',
	'linkedin.com',
	'amazon.com',
	'dropbox.com',
] as const;

export interface SpfCanaryResult {
	totalProbed: number;
	nullCount: number;
	errorCount: number;
	nullRate: number;
	nullDomains: string[];
	errorDomains: string[];
}

/**
 * Probe every canary domain and classify each result as null, error, or
 * found. Runs in parallel; per-probe failures are isolated via allSettled so
 * a single timeout does not poison the rest of the report.
 */
export async function runSpfCanary(domains: readonly string[] = SPF_CANARY_DOMAINS): Promise<SpfCanaryResult> {
	const settled = await Promise.allSettled(
		domains.map(async (domain) => {
			const result = await checkSpf(domain);
			const titles = result.findings.map((f) => f.title);
			const isNull = titles.some((t) => t === 'No SPF record found');
			const isError = titles.some((t) => /could not complete|timed out/i.test(t));
			return { domain, isNull, isError };
		}),
	);

	const nullDomains: string[] = [];
	const errorDomains: string[] = [];

	for (let i = 0; i < settled.length; i++) {
		const r = settled[i];
		if (r.status === 'fulfilled') {
			if (r.value.isNull) nullDomains.push(r.value.domain);
			if (r.value.isError) errorDomains.push(r.value.domain);
		} else {
			errorDomains.push(domains[i]);
		}
	}

	return {
		totalProbed: domains.length,
		nullCount: nullDomains.length,
		errorCount: errorDomains.length,
		nullRate: nullDomains.length / Math.max(1, domains.length),
		nullDomains,
		errorDomains,
	};
}

/**
 * Decide whether the canary's null rate breaches the configured threshold.
 * Kept pure for unit testing — the scheduled handler composes this with the
 * webhook dispatch.
 */
export function shouldAlertOnCanary(result: SpfCanaryResult, nullRateThreshold: number): boolean {
	return result.nullRate >= nullRateThreshold;
}
