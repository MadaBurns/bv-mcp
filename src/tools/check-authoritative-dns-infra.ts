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

	let evidence: Awaited<ReturnType<typeof fetchAuthoritativeDnsEvidence>>;
	try {
		evidence = await fetchAuthoritativeDnsEvidence(hostname, options.infraProbe);
	} catch (err) {
		// Provisioned-but-failing path (5xx / non-OK / network error). Degrade
		// gracefully to an INCONCLUSIVE result (excluded from scoring via
		// checkStatus: 'error') instead of surfacing a hard error to the client —
		// this mirrors scan_domain's safeCheck() wrapper for the standalone path.
		const message = err instanceof Error ? err.message : String(err);
		return {
			...buildCheckResult('authoritative_dns_infra', [
				createFinding(
					'authoritative_dns_infra',
					'Authoritative DNS infra probe unavailable',
					'info',
					`The authoritative DNS infra probe could not be reached, so raw UDP/TCP DNS, BGP, RPKI, and vantage checks were not run: ${message}`,
					{ evidenceMode: 'probe_unavailable' },
				),
			]),
			checkStatus: 'error',
			partial: true,
			metadata: { evidenceMode: 'probe_unavailable', hostname },
		};
	}
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
