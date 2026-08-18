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
					{ evidenceMode: 'worker_only', inconclusive: true },
				),
			]),
			// Nothing was measured, so no verdict is reported. `buildCheckResult` would otherwise
			// derive score 100 / passed true from the single `info` finding — and because this
			// category is the ENTIRE scan under `profile: 'authoritative_dns_infra'`, that 100
			// became a published `Overall Score: 100 (A+)` for a probe that never ran (#696).
			// `checkStatus: 'error'` is what makes the scoring engine EXCLUDE the category, so a
			// single-category infra scan returns `overall: null` instead of a fabricated grade.
			score: 0,
			passed: false,
			checkStatus: 'error',
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

	// The probe answered — but did it MEASURE anything? A response establishing no capability
	// either way leaves `passed` and `failed` both empty, and the findings that remain are
	// `info`, which `buildCheckResult` turns into 100/passed. This is the LIVE half of #696:
	// the absent-binding branch above is unreachable on any deployment using this repo's own
	// wrangler.jsonc, but an all-inconclusive probe response is not.
	//
	// ⚠️ The trigger is "nothing measured at all", NOT `!probeEstablishedContact()`. Contact is
	// a DNS-reachability notion; `rpki_roa_validity` and the critical `route_leak_hijack_alerts`
	// are measured from routing/vantage evidence needing no DNS contact whatsoever. Keying on
	// contact would discard genuinely measured critical findings and re-grade live scans on a
	// core-tier category — a scoring change, not a correctness fix. Pinned by a spec.
	const measuredNothing =
		analysis.capabilitySummary.passed.length === 0 && analysis.capabilitySummary.failed.length === 0;

	const evidenceReceived = createFinding(
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
	);

	return {
		// "evidence received" asserts the probe returned something usable. When it established
		// nothing, that claim is unearned — drop it rather than let it stand as the sole finding
		// behind a clean verdict.
		...buildCheckResult(
			'authoritative_dns_infra',
			measuredNothing ? analysis.findings : [evidenceReceived, ...analysis.findings],
		),
		...(measuredNothing ? { score: 0, passed: false, checkStatus: 'error' as const, partial: true } : {}),
		metadata: {
			evidenceMode: 'infra_probe',
			hostname,
			checkedAt,
			capabilitySummary: analysis.capabilitySummary,
			...(measuredNothing ? { inconclusive: true } : {}),
		},
	};
}
