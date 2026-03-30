// SPDX-License-Identifier: BUSL-1.1

/**
 * Phased DMARC enforcement rollout plan generator.
 *
 * Checks current DMARC/SPF/DKIM state, identifies prerequisites,
 * and produces time-boxed phases with exact DNS records.
 */

import type { OutputFormat } from '../handlers/tool-args';
import type { CheckResult, Finding } from '../lib/scoring-model';
import type { QueryDnsOptions } from '../lib/dns-types';
import { checkDmarc } from './check-dmarc';
import { checkSpf } from './check-spf';
import { checkDkim } from './check-dkim';

/** A single phase in the DMARC rollout plan. */
export interface RolloutPhase {
	name: string;
	record: string;
	duration: string;
	successCriteria: string;
	rollback: string;
}

/** Complete rollout plan result. */
export interface RolloutPlanResult {
	domain: string;
	currentPolicy: string;
	targetPolicy: string;
	timeline: string;
	atTarget: boolean;
	prerequisites: string[];
	phases: RolloutPhase[];
	estimatedDuration: string;
}

type Timeline = 'aggressive' | 'standard' | 'conservative';
type TargetPolicy = 'quarantine' | 'reject';

/** Duration table keyed by timeline and phase stage. */
const DURATIONS: Record<Timeline, Record<string, string>> = {
	aggressive: {
		monitor: '1 week',
		ramp10: '3 days',
		ramp100: '3 days',
		final: 'ongoing',
	},
	standard: {
		monitor: '2 weeks',
		ramp10: '1 week',
		ramp100: '1 week',
		final: 'ongoing',
	},
	conservative: {
		monitor: '3 weeks',
		ramp10: '2 weeks',
		ramp100: '1 week',
		final: 'ongoing',
	},
};

/** Extract the current DMARC policy from check results. */
function extractCurrentPolicy(dmarcResult: CheckResult): string {
	const findings = dmarcResult.findings;

	// Check if there's no DMARC record at all
	const noRecord = findings.some((f: Finding) =>
		f.title.toLowerCase().includes('no dmarc') || f.title.toLowerCase().includes('missing'),
	);
	if (noRecord) return 'none';

	// Check finding titles for explicit policy indicators
	// checkDMARC produces titles like "DMARC policy set to none/quarantine"
	const allTitles = findings.map((f: Finding) => f.title.toLowerCase()).join(' ');
	if (allTitles.includes('policy set to quarantine')) return 'quarantine';
	if (allTitles.includes('policy set to none')) return 'none';

	// Check all text for policy references (detail text uses 'policy "reject"' etc.)
	const allText = findings
		.map((f: Finding) => `${f.title.toLowerCase()} ${f.detail.toLowerCase()}`)
		.join(' ');

	if (allText.includes('p=reject') || /policy\s*"reject"/i.test(allText) || /policy\s*is\s*"reject"/i.test(allText)) return 'reject';
	if (allText.includes('p=quarantine') || /policy\s*"quarantine"/i.test(allText)) return 'quarantine';
	if (allText.includes('p=none') || /policy\s*"none"/i.test(allText)) return 'none';

	// "DMARC properly configured" without explicit none/quarantine title implies reject
	if (allTitles.includes('properly configured')) return 'reject';

	// If a DMARC record exists but we can't determine policy, assume none
	return 'none';
}

/** Identify missing prerequisites from SPF and DKIM results. */
function identifyPrerequisites(spfResult: CheckResult, dkimResult: CheckResult): string[] {
	const prerequisites: string[] = [];

	const spfMissing = spfResult.findings.some((f: Finding) =>
		f.title.toLowerCase().includes('no spf') || f.title.toLowerCase().includes('missing'),
	);
	if (spfMissing) {
		prerequisites.push('Add an SPF record (e.g., v=spf1 include:_spf.google.com -all)');
	}

	const dkimMissing = dkimResult.findings.some((f: Finding) =>
		f.title.toLowerCase().includes('no dkim') || f.title.toLowerCase().includes('not found'),
	);
	if (dkimMissing) {
		prerequisites.push('Enable DKIM signing with your email provider');
	}

	return prerequisites;
}

/** Build the base RUA tag for DMARC records. */
function ruaTag(domain: string): string {
	return `rua=mailto:dmarc-reports@${domain}`;
}

/** Build phases from current policy to target policy. */
function buildPhases(
	domain: string,
	currentPolicy: string,
	targetPolicy: TargetPolicy,
	timeline: Timeline,
): RolloutPhase[] {
	const phases: RolloutPhase[] = [];
	const durations = DURATIONS[timeline];
	const rua = ruaTag(domain);

	// Phase progression depends on where we start and where we're going.
	// Full path (no DMARC): Monitor → Quarantine 10% → Quarantine 100% → Reject
	// From p=none: Quarantine 10% → Quarantine 100% → Reject
	// From p=quarantine: Reject
	// From p=reject: already at target (handled before this function)

	const isNoDmarc = currentPolicy === 'none';

	// Check if we need the monitor phase (only when there's NO DMARC at all or no enforcement)
	// "none" could mean no record OR p=none; both need the same treatment for rollout purposes
	if (isNoDmarc) {
		phases.push({
			name: 'Monitor',
			record: `v=DMARC1; p=none; ${rua}`,
			duration: durations.monitor,
			successCriteria: 'Review DMARC aggregate reports — confirm legitimate senders are SPF/DKIM aligned',
			rollback: 'Remove _dmarc TXT record',
		});
	}

	// Quarantine ramp phases (skip if target is quarantine and current is already quarantine)
	if (currentPolicy !== 'quarantine' && currentPolicy !== 'reject') {
		phases.push({
			name: 'Quarantine 10%',
			record: `v=DMARC1; p=quarantine; pct=10; ${rua}`,
			duration: durations.ramp10,
			successCriteria: 'Verify no legitimate mail is quarantined in reports; false positive rate < 0.1%',
			rollback: `v=DMARC1; p=none; ${rua}`,
		});

		phases.push({
			name: 'Quarantine 100%',
			record: `v=DMARC1; p=quarantine; ${rua}`,
			duration: durations.ramp100,
			successCriteria: 'Confirm all legitimate senders pass DMARC; no delivery complaints',
			rollback: `v=DMARC1; p=quarantine; pct=10; ${rua}`,
		});
	}

	// Reject phase (only if target is reject)
	if (targetPolicy === 'reject') {
		if (currentPolicy === 'quarantine') {
			// Going from quarantine to reject
			phases.push({
				name: 'Reject',
				record: `v=DMARC1; p=reject; ${rua}`,
				duration: durations.final,
				successCriteria: 'Monitor reports for any remaining legitimate senders failing alignment',
				rollback: `v=DMARC1; p=quarantine; ${rua}`,
			});
		} else {
			// Full path or from none
			phases.push({
				name: 'Reject',
				record: `v=DMARC1; p=reject; ${rua}`,
				duration: durations.final,
				successCriteria: 'Monitor reports for any remaining legitimate senders failing alignment',
				rollback: `v=DMARC1; p=quarantine; ${rua}`,
			});
		}
	} else {
		// Target is quarantine — mark the last quarantine phase as final/ongoing
		if (phases.length > 0) {
			const lastPhase = phases[phases.length - 1];
			if (lastPhase.name === 'Quarantine 100%') {
				lastPhase.duration = durations.final;
			}
		}
	}

	return phases;
}

/** Calculate total estimated duration from phases. */
function calculateEstimatedDuration(phases: RolloutPhase[]): string {
	let totalDays = 0;
	for (const phase of phases) {
		const dur = phase.duration.toLowerCase();
		if (dur === 'ongoing') continue;
		const match = dur.match(/(\d+)\s*(week|day)/);
		if (match) {
			const num = parseInt(match[1], 10);
			totalDays += match[2] === 'week' ? num * 7 : num;
		}
	}
	if (totalDays === 0) return 'already at target';

	const weeks = Math.floor(totalDays / 7);
	const days = totalDays % 7;
	if (weeks > 0 && days > 0) return `~${weeks} week${weeks > 1 ? 's' : ''} ${days} day${days > 1 ? 's' : ''}`;
	if (weeks > 0) return `~${weeks} week${weeks > 1 ? 's' : ''}`;
	return `~${days} day${days > 1 ? 's' : ''}`;
}

/**
 * Generate a phased DMARC enforcement rollout plan.
 *
 * @param domain - Validated, sanitized domain
 * @param targetPolicy - Target DMARC policy (default: reject)
 * @param timeline - Rollout speed (default: standard)
 * @param dnsOptions - Optional DNS query options
 * @returns Phased rollout plan with exact DNS records
 */
export async function generateRolloutPlan(
	domain: string,
	targetPolicy: TargetPolicy = 'reject',
	timeline: Timeline = 'standard',
	dnsOptions?: QueryDnsOptions,
): Promise<RolloutPlanResult> {
	// Run checks in parallel
	const [dmarcResult, spfResult, dkimResult] = await Promise.all([
		checkDmarc(domain, dnsOptions),
		checkSpf(domain, dnsOptions),
		checkDkim(domain, undefined, dnsOptions),
	]);

	const currentPolicy = extractCurrentPolicy(dmarcResult);

	// Check if already at target
	if (
		(targetPolicy === 'reject' && currentPolicy === 'reject') ||
		(targetPolicy === 'quarantine' && (currentPolicy === 'quarantine' || currentPolicy === 'reject'))
	) {
		return {
			domain,
			currentPolicy,
			targetPolicy,
			timeline,
			atTarget: true,
			prerequisites: [],
			phases: [],
			estimatedDuration: 'already at target',
		};
	}

	const prerequisites = identifyPrerequisites(spfResult, dkimResult);
	const phases = buildPhases(domain, currentPolicy, targetPolicy, timeline);
	const estimatedDuration = calculateEstimatedDuration(phases);

	return {
		domain,
		currentPolicy,
		targetPolicy,
		timeline,
		atTarget: false,
		prerequisites,
		phases,
		estimatedDuration,
	};
}

/** Format rollout plan as human-readable text. */
export function formatRolloutPlan(result: RolloutPlanResult, format: OutputFormat = 'full'): string {
	if (result.atTarget) {
		if (format === 'compact') {
			return `DMARC Rollout: ${result.domain} — Already at ${result.currentPolicy}. No changes needed.`;
		}
		return [
			`# DMARC Rollout Plan: ${result.domain}`,
			'',
			`Current policy: ${result.currentPolicy}`,
			`Target policy: ${result.targetPolicy}`,
			'',
			'Domain is already at or beyond the target enforcement level. No rollout needed.',
		].join('\n');
	}

	if (format === 'compact') {
		const lines: string[] = [];
		lines.push(`DMARC Rollout: ${result.domain} — ${result.currentPolicy} -> ${result.targetPolicy} (${result.timeline})`);
		lines.push(`Estimated: ${result.estimatedDuration} | ${result.phases.length} phase${result.phases.length !== 1 ? 's' : ''}`);
		if (result.prerequisites.length > 0) {
			lines.push(`Prerequisites: ${result.prerequisites.join('; ')}`);
		}
		for (let i = 0; i < result.phases.length; i++) {
			const p = result.phases[i];
			lines.push(`${i + 1}. ${p.name} (${p.duration}): ${p.record}`);
		}
		return lines.join('\n');
	}

	const lines: string[] = [];
	lines.push(`# DMARC Rollout Plan: ${result.domain}`);
	lines.push('');
	lines.push(`Current policy: ${result.currentPolicy}`);
	lines.push(`Target policy: ${result.targetPolicy}`);
	lines.push(`Timeline: ${result.timeline}`);
	lines.push(`Estimated duration: ${result.estimatedDuration}`);

	if (result.prerequisites.length > 0) {
		lines.push('');
		lines.push('## Prerequisites');
		for (const prereq of result.prerequisites) {
			lines.push(`  - ${prereq}`);
		}
	}

	lines.push('');
	lines.push('## Phases');
	for (let i = 0; i < result.phases.length; i++) {
		const phase = result.phases[i];
		lines.push('');
		lines.push(`### Phase ${i + 1}: ${phase.name}`);
		lines.push(`  Duration: ${phase.duration}`);
		lines.push(`  DNS Record: \`${phase.record}\``);
		lines.push(`  Success Criteria: ${phase.successCriteria}`);
		lines.push(`  Rollback: \`${phase.rollback}\``);
	}

	return lines.join('\n');
}
