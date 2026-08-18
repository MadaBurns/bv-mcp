// SPDX-License-Identifier: BUSL-1.1

import { type CheckResult, buildCheckResult, createFinding } from '../lib/scoring';
import { ROOT_SERVER_NAMES } from '../lib/authoritative-dns-infra/root-hints';
import {
	type InfraProbeBinding,
	fetchRootServerSetEvidence,
} from '../lib/authoritative-dns-infra/probe-client';
import { analyzeRootServerSetEvidence } from '../lib/authoritative-dns-infra/analyze-root-server-set';

export interface RootServerSetCheckOptions {
	infraProbe?: InfraProbeBinding;
}

export async function checkRootServerSet(
	options: RootServerSetCheckOptions = {},
): Promise<CheckResult> {
	if (!options.infraProbe) {
		return {
			...buildCheckResult('authoritative_dns_infra', [
				createFinding(
					'authoritative_dns_infra',
					'Official root hints embedded',
					'info',
					'The check returned the embedded official root-server names. BV_INFRA_PROBE is not provisioned, so live root glue, delegation, serial, and DNSKEY cross-checks were not run. Nothing was verified against the live root zone.',
					{ evidenceMode: 'worker_only', inconclusive: true },
				),
			]),
			// Nothing was measured — see the twin branch in check-authoritative-dns-infra.ts (#696).
			score: 0,
			passed: false,
			checkStatus: 'error',
			partial: true,
			metadata: {
				evidenceMode: 'worker_only',
				rootServers: ROOT_SERVER_NAMES,
				capabilitySummary: {
					// `official_root_hints_match` was reported as PASSED here. Nothing was queried:
					// the "match" was this module's own embedded ROOT_SERVER_NAMES constant compared
					// against itself. A capability does not pass because the checker agrees with
					// itself — it belongs in `inconclusive`, which is what it always was (#696).
					passed: [],
					failed: [],
					inconclusive: [
						'official_root_hints_match',
						'root_priming_ns_set',
						'root_glue_records',
						'root_servers_parent_child_delegation',
						'root_server_ns_soa_dnskey_cross_compare',
						'stale_root_zone_serial_detection',
					],
				},
			},
		};
	}

	let evidence: Awaited<ReturnType<typeof fetchRootServerSetEvidence>>;
	try {
		evidence = await fetchRootServerSetEvidence(options.infraProbe);
	} catch (err) {
		// Provisioned-but-failing path (5xx / non-OK / network error). Degrade
		// gracefully to an INCONCLUSIVE result (checkStatus: 'error') instead of
		// surfacing a hard error — mirrors scan_domain's safeCheck() wrapper.
		const message = err instanceof Error ? err.message : String(err);
		return {
			...buildCheckResult('authoritative_dns_infra', [
				createFinding(
					'authoritative_dns_infra',
					'Root server set probe unavailable',
					'info',
					`The root-server-set infra probe could not be reached, so live root glue, delegation, serial, and DNSKEY cross-checks were not run: ${message}`,
					{ evidenceMode: 'probe_unavailable' },
				),
			]),
			checkStatus: 'error',
			partial: true,
			metadata: {
				evidenceMode: 'probe_unavailable',
				rootServers: ROOT_SERVER_NAMES,
			},
		};
	}
	const analysis = analyzeRootServerSetEvidence(evidence);
	const checkedAt = evidence.checkedAt ?? new Date().toISOString();

	return {
		...buildCheckResult('authoritative_dns_infra', [
			createFinding(
				'authoritative_dns_infra',
				'Root server set probe evidence received',
				'info',
				'Infra probe returned root-server-set evidence.',
				{ evidenceMode: 'infra_probe', checkedAt },
			),
			...analysis.findings,
		]),
		metadata: {
			evidenceMode: 'infra_probe',
			hostname: '.',
			checkedAt,
			rootServers: ROOT_SERVER_NAMES,
			capabilitySummary: analysis.capabilitySummary,
		},
	};
}
