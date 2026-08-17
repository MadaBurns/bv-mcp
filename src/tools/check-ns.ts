// SPDX-License-Identifier: BUSL-1.1

/**
 * NS (Name Server) check tool.
 * Thin wrapper around @blackveil/dns-checks — delegates all logic to the shared package.
 */

import { checkNS } from '@blackveil/dns-checks';
import type { ZoneContext } from '@blackveil/dns-checks';
import { analyzeDelegationConsistency } from '../lib/authoritative-dns-infra/delegation-analysis';
import {
	type InfraProbeBinding,
	fetchDelegationConsistencyEvidence,
} from '../lib/authoritative-dns-infra/probe-client';
import { queryDns } from '../lib/dns';
import { makeQueryDNS } from '../lib/dns-query-adapter';
import { resolveZoneApex } from '../lib/zone-apex';
import type { QueryDnsOptions } from '../lib/dns-types';
import { buildCheckResult, type CheckResult } from '../lib/scoring';

export interface NsCheckOptions {
	/** Optional service binding that can query parent and child authoritative servers directly over TCP/53. */
	infraProbe?: InfraProbeBinding;
}

/**
 * Check nameserver configuration for a domain.
 * Validates NS records, diversity, SOA posture, and — when BV_INFRA_PROBE is
 * available — parent/child delegation, authoritative AA, and glue consistency.
 */
export async function checkNs(
	domain: string,
	dnsOptions?: QueryDnsOptions,
	zone?: ZoneContext,
	options: NsCheckOptions = {},
): Promise<CheckResult> {
	const resolvedZone = zone ?? (await resolveZoneApex(domain, dnsOptions));
	const base = await checkNS(
		domain,
		makeQueryDNS(dnsOptions),
		{
			timeout: dnsOptions?.timeoutMs ?? 5000,
			zone: resolvedZone,
			rawQueryDNS: async (d, type, dnssecFlag) => {
				const resp = await queryDns(d, type as Parameters<typeof queryDns>[1], dnssecFlag ?? false, dnsOptions);
				return { AD: resp.AD, Answer: resp.Answer };
			},
		},
	) as CheckResult;

	// An inherited subdomain is not itself delegated, and a failed core check
	// lacks enough evidence to safely enrich. Self-hosts without the optional
	// binding retain the exact worker-only behavior.
	if (!options.infraProbe || !resolvedZone.isApex || base.checkStatus === 'error') return base;

	try {
		const evidence = await fetchDelegationConsistencyEvidence(resolvedZone.zoneApex, options.infraProbe);
		const analysis = analyzeDelegationConsistency(evidence);
		if (analysis.findings.length === 0) {
			return {
				...base,
				metadata: { ...base.metadata, delegationEvidenceMode: 'inconclusive' },
			};
		}

		const hasRiskFinding = analysis.findings.some((finding) => finding.severity !== 'info');
		const baseFindings = hasRiskFinding
			? base.findings.filter((finding) => finding.title !== 'Nameservers properly configured')
			: base.findings;
		const rebuilt = buildCheckResult('ns', [...baseFindings, ...analysis.findings]);
		return {
			...base,
			...rebuilt,
			metadata: {
				...base.metadata,
				delegationEvidenceMode: 'direct_dns_tcp',
				delegationCheckedAt: evidence.checkedAt,
				delegationFailedChecks: analysis.failedChecks,
			},
		};
	} catch {
		// Optional enrichment is fail-soft. A probe outage is not evidence that the
		// domain's delegation is bad and must never alter the core NS score.
		return {
			...base,
			metadata: { ...base.metadata, delegationEvidenceMode: 'probe_unavailable' },
		};
	}
}
