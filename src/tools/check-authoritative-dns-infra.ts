// SPDX-License-Identifier: BUSL-1.1

import { type CheckResult, buildCheckResult, createFinding } from '../lib/scoring';
import {
	type InfraProbeBinding,
	fetchAuthoritativeDnsEvidence,
	normalizeInfraHostname,
} from '../lib/authoritative-dns-infra/probe-client';
import { analyzeAuthoritativeDnsInfraEvidence } from '../lib/authoritative-dns-infra/analyze';

export interface AuthoritativeDnsInfraCheckOptions {
	infraProbe?: InfraProbeBinding;
}

export async function checkAuthoritativeDnsInfra(
	domain: string,
	options: AuthoritativeDnsInfraCheckOptions = {},
): Promise<CheckResult> {
	const hostname = normalizeInfraHostname(domain);

	if (!options.infraProbe) {
		return {
			...buildCheckResult('authoritative_dns_infra', [
				createFinding(
					'authoritative_dns_infra',
					'Authoritative DNS infra probe not configured',
					'info',
					'BV_INFRA_PROBE is not provisioned, so raw UDP/TCP DNS, BGP, RPKI, and vantage checks were not run.',
					{ evidenceMode: 'worker_only' },
				),
			]),
			partial: true,
			metadata: { evidenceMode: 'worker_only', hostname },
		};
	}

	const evidence = await fetchAuthoritativeDnsEvidence(hostname, options.infraProbe);
	const checkedAt = evidence.checkedAt ?? new Date().toISOString();
	const analysis = analyzeAuthoritativeDnsInfraEvidence({ ...evidence, hostname });

	return {
		...buildCheckResult('authoritative_dns_infra', [
			createFinding(
				'authoritative_dns_infra',
				'Authoritative DNS infra probe evidence received',
				'info',
				`Infra probe returned authoritative DNS evidence for ${hostname}.`,
				{
					evidenceMode: 'infra_probe',
					checkedAt,
					reachability: evidence.reachability,
					authoritative: evidence.authoritative,
				},
			),
			...analysis.findings,
		]),
		metadata: {
			evidenceMode: 'infra_probe',
			hostname,
			checkedAt,
			capabilitySummary: analysis.capabilitySummary,
		},
	};
}
