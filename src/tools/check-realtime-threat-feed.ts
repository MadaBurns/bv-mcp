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
import { callReconScan, isReconHit, type ReconBinding } from '../lib/recon-binding';

// F7 (OWASP LLM01): attacker-influenceable upstream metadata/status spread into
// finding metadata below is sanitized at the `createFinding` chokepoint
// (`@blackveil/dns-checks/scoring`). The former per-tool `sanitizeUpstream*` opt-ins
// were removed as redundant.

const CATEGORY = 'realtime_threat_feed' as CheckCategory;

export interface RealtimeThreatFeedOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
}

/** Map a DNSCheckResult status to a finding severity for threat-feed hits. */
function hitSeverity(status: string | undefined): 'critical' | 'high' | 'medium' {
	const s = (status ?? '').toLowerCase();
	if (s === 'critical') return 'critical';
	if (s === 'high') return 'high';
	if (s === 'medium') return 'medium';
	// warning / fail / other hit statuses → high
	return 'high';
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

	if (isReconHit(scan.status)) {
		const sev = hitSeverity(scan.status);
		findings.push(
			createFinding(
				CATEGORY,
				'Realtime threat-feed hit',
				sev,
				scan.details ?? 'Threat intelligence flagged this domain.',
				// F7: upstream metadata + status are sanitized at the createFinding chokepoint.
				// Spread upstream FIRST so the explicit `domain`/`status` keys (trusted input)
				// win over any malicious upstream key of the same name.
				{ ...(scan.metadata ?? {}), domain, status: scan.status },
			),
		);
	} else {
		findings.push(
			createFinding(
				CATEGORY,
				'No realtime threat-feed hits',
				'info',
				scan.details ?? 'No active threat-feed matches.',
				{ domain },
			),
		);
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
