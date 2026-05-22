// SPDX-License-Identifier: BUSL-1.1

import type { BrandAuditDepth, CandidateSeedSource } from './brand-candidate-universe';
import type { DiscoverSignal } from '../tools/discover-brand-domains';

export type PlannerCandidateSource = CandidateSeedSource | 'app_links' | 'bounty_scope';

export interface PlannerCandidate {
	domain: string;
	sources: PlannerCandidateSource[];
	reasons: string[];
}

export interface BrandDiscoveryPlannerOptions {
	depth: BrandAuditDepth;
	candidates: PlannerCandidate[];
	signals: DiscoverSignal[];
	caps?: Partial<Record<DiscoverSignal, number>>;
}

export interface BrandDiscoverySignalPlan {
	candidatesBySignal: Partial<Record<DiscoverSignal, string[]>>;
	droppedBySignal: Partial<Record<DiscoverSignal, Array<{ domain: string; reason: string }>>>;
	priorityByDomain: Record<string, number>;
	guardedByDomain: Record<string, string>;
}

// Per-signal cost tiers. Caps are calibrated against production benchmarks
// (large-portfolio brands, 150-candidate deep audits):
//   - High-yield signals (ns/mx_platform/spf_include) accounted for every
//     surfaced candidate in observed runs; keep them effectively uncapped so
//     recall is not the lever we trade away.
//   - Low-yield candidate-backed signals (dkim_key_reuse / mx_overlap /
//     txt_verification / cname_alignment) contributed zero surfaced findings
//     in those benchmarks but consume a disproportionate share of probe
//     budget. Tighten those caps to claw back budget without harming recall.
// The ceiling values are kept high enough that 150-candidate deep audits stay
// non-binding on the high-yield signals while still bounding pathological
// brand portfolios with thousands of candidates. Reduction is a function of
// candidate count: at 150 candidates this yields ~44% reduction; at 50 the
// low-yield caps bite less and reduction is lower — that is expected, not a
// regression.
const DEFAULT_SIGNAL_CAPS: Partial<Record<DiscoverSignal, number>> = {
	dkim_key_reuse: 30,
	ns: 500,
	mx_platform: 500,
	mx_overlap: 40,
	txt_verification: 30,
	spf_include: 500,
	cname_alignment: 30,
};

const STANDARD_SIGNAL_CAPS: Partial<Record<DiscoverSignal, number>> = {
	dkim_key_reuse: 25,
	ns: 200,
	mx_platform: 200,
	mx_overlap: 30,
	txt_verification: 25,
	spf_include: 200,
	cname_alignment: 25,
};

const CANDIDATE_BACKED_SIGNALS = new Set<DiscoverSignal>([
	'dkim_key_reuse',
	'ns',
	'mx_platform',
	'mx_overlap',
	'txt_verification',
	'spf_include',
	'cname_alignment',
]);

export function planBrandDiscoverySignals(options: BrandDiscoveryPlannerOptions): BrandDiscoverySignalPlan {
	const priorityByDomain: Record<string, number> = {};
	const guardedByDomain: Record<string, string> = {};
	const ranked = options.candidates
		.map((candidate, index) => {
			const priority = scoreCandidate(candidate);
			priorityByDomain[candidate.domain] = priority;
			const guardReason = highTrustReason(candidate);
			if (guardReason) guardedByDomain[candidate.domain] = guardReason;
			return { ...candidate, index, priority };
		})
		.filter((candidate) => options.depth === 'deep' || isStandardEligible(candidate))
		.sort((a, b) => b.priority - a.priority || a.index - b.index);

	const candidatesBySignal: BrandDiscoverySignalPlan['candidatesBySignal'] = {};
	const droppedBySignal: BrandDiscoverySignalPlan['droppedBySignal'] = {};

	const guarded = ranked.filter((candidate) => guardedByDomain[candidate.domain]);
	const unguarded = ranked.filter((candidate) => !guardedByDomain[candidate.domain]);

	for (const signal of options.signals) {
		if (!CANDIDATE_BACKED_SIGNALS.has(signal)) continue;
		const defaultCap =
			options.depth === 'deep'
				? (DEFAULT_SIGNAL_CAPS[signal] ?? ranked.length)
				: (STANDARD_SIGNAL_CAPS[signal] ?? Math.min(40, ranked.length));
		const cap = Math.max(1, Math.trunc(options.caps?.[signal] ?? defaultCap));
		// Guarded candidates (caller_candidate / app_links / bounty_scope) always
		// pass; only the unguarded remainder competes for the residual budget.
		const residualCap = Math.max(0, cap - guarded.length);
		const selected = [...guarded, ...unguarded.slice(0, residualCap)];
		const dropped = unguarded.slice(residualCap);
		candidatesBySignal[signal] = selected.map((candidate) => candidate.domain);
		if (dropped.length > 0) {
			droppedBySignal[signal] = dropped.map((candidate) => ({ domain: candidate.domain, reason: 'signal_cap' }));
		}
	}

	return { candidatesBySignal, droppedBySignal, priorityByDomain, guardedByDomain };
}

function isStandardEligible(candidate: PlannerCandidate): boolean {
	return candidate.sources.some(
		(source) =>
			source === 'caller_candidate' ||
			source === 'app_links' ||
			source === 'bounty_scope' ||
			source === 'tld_sweep' ||
			source === 'alias_tld_sweep' ||
			source === 'active_lookalike',
	);
}

function scoreCandidate(candidate: PlannerCandidate): number {
	let score = 0;
	if (candidate.sources.includes('caller_candidate')) score += 1000;
	if (candidate.sources.includes('app_links')) score += 1000;
	if (candidate.sources.includes('bounty_scope')) score += 1000;
	if (candidate.sources.includes('tld_sweep')) score += 200;
	if (candidate.sources.includes('active_lookalike')) score += 180;
	if (candidate.sources.includes('enterprise_affix')) score += 120;
	if (candidate.sources.includes('alias_tld_sweep')) score += 110;
	if (candidate.sources.includes('markov')) score += 10;
	if (candidate.reasons.some((reason) => reason.includes('seed label across'))) score += 100;
	return score;
}

function highTrustReason(candidate: PlannerCandidate): string | null {
	if (candidate.sources.includes('app_links')) return 'app_links';
	if (candidate.sources.includes('bounty_scope')) return 'bounty_scope';
	if (candidate.sources.includes('caller_candidate')) return 'caller_candidate';
	return null;
}
