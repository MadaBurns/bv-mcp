// SPDX-License-Identifier: BUSL-1.1
/**
 * Package supply-chain trust check. Wraps bv-recon's package-trust /check
 * endpoint via the BV_RECON binding. Fail-soft: when the binding is absent
 * (BSL self-hosts), returns an info result flagged unprovisioned.
 */
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import { callReconPackageCheck, type ReconBinding } from '../lib/recon-binding';

const CATEGORY = 'package_trust' as CheckCategory;

export interface PackageTrustArgs {
	registry: string;
	package: string;
	version?: string;
}
export interface PackageTrustOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
}

const VERDICT_SEVERITY: Record<string, 'critical' | 'high' | 'low' | 'info'> = {
	MALICIOUS: 'critical',
	SUSPICIOUS: 'high',
	LOW_RISK: 'low',
	SAFE: 'info',
	UNKNOWN: 'info',
};

const ALLOWED_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;

export async function checkPackageTrust(args: PackageTrustArgs, options: PackageTrustOptions = {}): Promise<CheckResult> {
	const findings: ReturnType<typeof createFinding>[] = [];
	const verdict = await callReconPackageCheck(options.reconBinding, options.reconAuthToken, args);

	if (!verdict) {
		findings.push(
			createFinding(
				CATEGORY,
				'Package trust unavailable',
				'info',
				`Package trust scoring is not provisioned in this deployment for ${args.registry}:${args.package}.`,
				{
					registry: args.registry,
					package: args.package,
					version: args.version ?? null,
					unprovisioned: true,
				},
			),
		);
		return buildCheckResult(CATEGORY, findings) as CheckResult;
	}

	const verdictLabel = verdict.verdict ?? 'UNKNOWN';
	const severity = VERDICT_SEVERITY[verdictLabel] ?? 'info';
	findings.push(
		createFinding(
			CATEGORY,
			`Package verdict: ${verdictLabel}`,
			severity,
			`${args.registry}:${args.package}${args.version ? `@${args.version}` : ''} → ${verdictLabel} (confidence ${verdict.confidence ?? 'unknown'}).`,
			{
				registry: args.registry,
				package: args.package,
				version: args.version ?? null,
				verdict: verdictLabel,
				confidence: verdict.confidence ?? null,
			},
		),
	);
	for (const sig of verdict.signals) {
		const sev = (ALLOWED_SEVERITIES as readonly string[]).includes(sig.severity)
			? (sig.severity as (typeof ALLOWED_SEVERITIES)[number])
			: 'info';
		findings.push(createFinding(CATEGORY, sig.id ?? 'Package signal', sev, sig.detail, { registry: args.registry, package: args.package }));
	}

	return buildCheckResult(CATEGORY, findings) as CheckResult;
}
