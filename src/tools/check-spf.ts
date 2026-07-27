// SPDX-License-Identifier: BUSL-1.1

/**
 * SPF (Sender Policy Framework) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkSPF } from '@blackveil/dns-checks';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildDnsErrorResult } from '../lib/dns-error-result';
import { isCompletedCheck } from '../lib/ungraded-display';
import type { CheckResult, Finding } from '../lib/scoring';
import { analyzeTrustSurface, type TrustSurfaceContext } from './spf-trust-surface';

/**
 * Check SPF records for a domain.
 * Looks for v=spf1 TXT records and validates their configuration.
 * Recursively expands include chains to compute true DNS lookup count.
 *
 * Top-level DNS failures (timeout, DoH HTTP error, SERVFAIL) are converted to a
 * structured CheckResult instead of a thrown error — see buildDnsErrorResult.
 * The `checkStatus: 'error'` shape (not `missingControl`) is what makes
 * scan_domain's transient-zero retry fire for a one-off SPF DNS hiccup.
 */
export async function checkSpf(domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		const core = (await checkSPF(domain, makeQueryDNS(dnsOptions), {
			timeout: dnsOptions?.timeoutMs ?? 5000,
		})) as CheckResult;
		return await augmentTrustSurface(core, domain, dnsOptions);
	} catch (err) {
		return buildDnsErrorResult('spf', 'SPF', err);
	}
}

/**
 * Worker-layer trust-surface post-processor (issue #566).
 *
 * The core `checkSPF` produces trust-surface findings ("SPF delegates to shared
 * platform: …" + an "N shared platforms" summary) from its OWN parity-locked ESP
 * catalog, which misses some multi-tenant senders (e.g. Mailjet) and counts only
 * cataloged platforms. We cannot edit the vendored core, so this re-derives the trust
 * surface in the worker with a broader recognizer and REPLACES the core-produced
 * trust-surface findings.
 *
 * SCORE IS NEVER RECOMPUTED: `core.score`, `passed`, `checkStatus`, `partial`, and every
 * non-trust-surface finding are passed through unchanged — this only rewrites the
 * informational trust-surface findings. Fail-soft: any error returns `core` untouched.
 */
async function augmentTrustSurface(core: CheckResult, domain: string, dnsOptions?: QueryDnsOptions): Promise<CheckResult> {
	try {
		// A failed/transient check has unreliable findings — never post-process it.
		if (!isCompletedCheck(core)) {
			return core;
		}

		const coreTrustFindings = core.findings.filter((f) => f.metadata?.trustSurface === true);

		// Re-fetch the SPF record: the include list is not reliably exposed on the core
		// result (a clean `-all` record with only cataloged includes carries no
		// includeDomains-bearing finding), so we parse it ourselves.
		const txtRecords = await makeQueryDNS(dnsOptions)(domain, 'TXT');
		const spf = txtRecords.find((record) => /^v=spf1(\s|$)/i.test(record.trim()));
		if (!spf) {
			return core; // No SPF record to analyze — leave core as-is.
		}

		// Reconstruct the DMARC context the core used from its own trust-surface finding
		// metadata so worker severities match the core's (info vs medium/high). When the
		// core recognized nothing, default to no-corroboration (conservative info).
		const ctxSource = coreTrustFindings[0]?.metadata;
		const context: TrustSurfaceContext = ctxSource
			? {
					corroboratedByWeakDmarc: ctxSource.dmarcCorroborated === true,
					...(typeof ctxSource.dmarcPolicy === 'string' ? { dmarcPolicy: ctxSource.dmarcPolicy } : {}),
					...(typeof ctxSource.dmarcAlignmentMode === 'string' ? { dmarcAlignmentMode: ctxSource.dmarcAlignmentMode } : {}),
				}
			: {};

		const workerTrustFindings = analyzeTrustSurface(spf, context);

		// Replace core trust-surface findings with the corrected worker ones; preserve all
		// other findings in their original relative order.
		const nonTrustFindings: Finding[] = core.findings.filter((f) => f.metadata?.trustSurface !== true);

		// Mirror the core suppression rule: the "SPF record configured" info finding is only
		// valid when no non-informational trust-surface finding remains. If the broadened
		// worker analysis surfaced a real (non-info) trust finding, drop a now-stale
		// "configured" finding so output stays self-consistent (does NOT affect score).
		const hasNonInfoTrust = workerTrustFindings.some((f) => f.severity !== 'info');
		const mergedNonTrust = hasNonInfoTrust ? nonTrustFindings.filter((f) => f.title !== 'SPF record configured') : nonTrustFindings;

		return { ...core, findings: [...mergedNonTrust, ...workerTrustFindings] };
	} catch {
		// Fail-soft: never worsen the core result on any post-processing error.
		return core;
	}
}
