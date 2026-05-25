// SPDX-License-Identifier: BUSL-1.1
/**
 * Realtime threat-feed check. Wraps bv-recon's intelligence
 * /osint/scan?type=REALTIME_THREAT_FEED endpoint via the BV_RECON binding.
 * Fail-soft: when the binding is absent (BSL self-hosts), returns an info
 * result flagged unprovisioned. Distinct from DNSBL checks (check_dbl/check_rbl)
 * — returns curated intel-gateway threat-feed signal.
 */
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import { callReconScan, type ReconBinding } from '../lib/recon-binding';

const CATEGORY = 'realtime_threat_feed' as CheckCategory;

const ALLOWED_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

export interface RealtimeThreatFeedOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
}

/**
 * Check a domain against BlackVeil real-time threat intelligence.
 *
 * Queries the curated intel-gateway threat-feed via the BV_RECON service binding.
 * Returns unprovisioned info when the binding is absent (BSL self-hosts).
 *
 * @param domain - The domain to check
 * @param options - Optional binding and auth token
 * @returns CheckResult with threat-feed findings
 */
export async function checkRealtimeThreatFeed(domain: string, options: RealtimeThreatFeedOptions = {}): Promise<CheckResult> {
	const findings: ReturnType<typeof createFinding>[] = [];
	const scan = await callReconScan(options.reconBinding, options.reconAuthToken, 'REALTIME_THREAT_FEED', { domain });

	if (!scan) {
		findings.push(
			createFinding(
				CATEGORY,
				'Realtime threat feed unavailable',
				'info',
				`Realtime threat-feed intelligence is not provisioned in this deployment for ${domain}. This is an operator-deploy only feature.`,
				{ domain, unprovisioned: true },
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	if (scan.findings.length === 0) {
		findings.push(
			createFinding(CATEGORY, 'No realtime threat-feed hits', 'info', `${domain} has no matches in the BlackVeil realtime threat intelligence feed.`, {
				domain,
			}),
		);
	} else {
		for (const f of scan.findings) {
			const sev = (ALLOWED_SEVERITIES as readonly string[]).includes(f.severity) ? (f.severity as (typeof ALLOWED_SEVERITIES)[number]) : 'info';
			findings.push(
				createFinding(CATEGORY, f.title ?? 'Threat-feed hit', sev, f.detail ?? f.title ?? 'Realtime threat-feed match.', { domain }),
			);
		}
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
