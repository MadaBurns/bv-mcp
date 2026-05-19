// SPDX-License-Identifier: BUSL-1.1

import type { BrandAuditMetricsSummary } from './brand-audit-metrics';

export type RegistrarCoverageSource = 'rdap' | 'whois' | 'redacted' | 'notfound' | 'lookup_failed' | 'unknown';

export interface CandidateUniverseDepth {
	seeded: number;
	probed: number;
	surfaced: number;
	dropped: Record<string, number>;
	sources: Record<string, number>;
}

export interface BrandAuditDepthInput {
	candidateUniverse: CandidateUniverseDepth;
	signalStatus: Record<string, { status: string; error?: string }>;
	registrarSources: RegistrarCoverageSource[];
	performance?: Pick<BrandAuditMetricsSummary, 'steps' | 'stepStatusCounts'>;
	plannerEfficiency?: {
		mode: 'off' | 'observe' | 'enforce';
		candidateSignalProbes: number;
		baselineCandidateSignalProbes: number;
		surfacedCandidates: number;
		wouldProbeBySignal?: Record<string, number>;
		wouldDropBySignal?: Record<string, number>;
	};
}

export interface BrandAuditDepthSummary {
	candidateUniverse: CandidateUniverseDepth;
	signalCoverage: {
		requested: number;
		ok: number;
		failed: number;
		partial: number;
		timeout: number;
		skipped: number;
	};
	registrarCoverage: Record<RegistrarCoverageSource, number> & {
		total: number;
		knownRatio: number;
	};
	plannerEfficiency?: BrandAuditDepthInput['plannerEfficiency'];
	warnings: string[];
}

type NormalizedSignalStatus = 'ok' | 'failed' | 'partial' | 'timeout' | 'skipped';

function round2(value: number): number {
	return Math.round(value * 100) / 100;
}

function normalizeSignalStatus(status: string): NormalizedSignalStatus {
	if (status === 'ok' || status === 'no_dmarc' || status === 'no_spf') return 'ok';
	if (status === 'partial' || status === 'budget_exceeded' || status === 'rate_limited') return 'partial';
	if (status === 'timeout') return 'timeout';
	if (status === 'failed' || status === 'error') return 'failed';
	if (status.startsWith('skipped')) return 'skipped';
	return 'failed';
}

function signalNamesByStatus(
	signalStatus: BrandAuditDepthInput['signalStatus'],
	normalizedStatus: NormalizedSignalStatus,
): string[] {
	return Object.entries(signalStatus)
		.filter(([, value]) => normalizeSignalStatus(value.status) === normalizedStatus)
		.map(([name]) => name)
		.sort();
}

export function buildBrandAuditDepthSummary(input: BrandAuditDepthInput): BrandAuditDepthSummary {
	const normalizedStatusValues = Object.values(input.signalStatus).map((s) => normalizeSignalStatus(s.status));
	const signalCoverage = {
		requested: normalizedStatusValues.length,
		ok: normalizedStatusValues.filter((status) => status === 'ok').length,
		failed: normalizedStatusValues.filter((status) => status === 'failed').length,
		partial: normalizedStatusValues.filter((status) => status === 'partial').length,
		timeout: normalizedStatusValues.filter((status) => status === 'timeout').length,
		skipped: normalizedStatusValues.filter((status) => status === 'skipped').length,
	};

	const registrarCoverage = {
		total: input.registrarSources.length,
		rdap: input.registrarSources.filter((s) => s === 'rdap').length,
		whois: input.registrarSources.filter((s) => s === 'whois').length,
		redacted: input.registrarSources.filter((s) => s === 'redacted').length,
		notfound: input.registrarSources.filter((s) => s === 'notfound').length,
		lookup_failed: input.registrarSources.filter((s) => s === 'lookup_failed').length,
		unknown: input.registrarSources.filter((s) => s === 'unknown').length,
		knownRatio:
			input.registrarSources.length === 0
				? 1
				: round2(input.registrarSources.filter((s) => s === 'rdap' || s === 'whois').length / input.registrarSources.length),
	};

	const warnings: string[] = [];
	const specificallyWarnedSignals = new Set<string>();
	if (signalCoverage.partial > 0 && input.signalStatus.san?.status === 'partial') {
		warnings.push('SAN signal returned partial results; certificate-derived sibling coverage is incomplete.');
		specificallyWarnedSignals.add('san');
	}
	if (signalCoverage.partial > 0 && input.signalStatus.san?.status === 'rate_limited') {
		warnings.push('SAN signal was rate limited; certificate-derived sibling coverage is incomplete.');
		specificallyWarnedSignals.add('san');
	}
	if (signalCoverage.partial > 0 && input.signalStatus.san_recursive?.status === 'partial') {
		warnings.push('Recursive SAN signal returned partial results; mutual certificate confirmation coverage is incomplete.');
		specificallyWarnedSignals.add('san_recursive');
	}
	if (input.signalStatus.san_recursive?.status === 'skipped_deadline') {
		warnings.push('Recursive SAN signal skipped to preserve audit deadline headroom; mutual certificate confirmation coverage is incomplete.');
		specificallyWarnedSignals.add('san_recursive');
	}
	if (signalCoverage.timeout > 0 && input.signalStatus.san?.status === 'timeout') {
		warnings.push('SAN signal timed out; certificate-derived sibling coverage is incomplete.');
		specificallyWarnedSignals.add('san');
	}

	const partialSignals = signalNamesByStatus(input.signalStatus, 'partial');
	const failedSignals = signalNamesByStatus(input.signalStatus, 'failed');
	const timeoutSignals = signalNamesByStatus(input.signalStatus, 'timeout');
	const incompleteSignals = [...partialSignals, ...failedSignals, ...timeoutSignals];
	const hasUnexplainedIncompleteSignal = incompleteSignals.some((name) => !specificallyWarnedSignals.has(name));
	if (hasUnexplainedIncompleteSignal) {
		const parts = [
			partialSignals.length > 0 ? `partial: ${partialSignals.join(', ')}` : null,
			failedSignals.length > 0 ? `failed: ${failedSignals.join(', ')}` : null,
			timeoutSignals.length > 0 ? `timeout: ${timeoutSignals.join(', ')}` : null,
		].filter((part): part is string => part !== null);
		warnings.push(`Discovery signals returned incomplete results (${parts.join('; ')}); finding coverage is incomplete.`);
	}
	if (input.performance?.steps.some((step) => step.name === 'registrar_enrichment' && step.status === 'partial')) {
		warnings.push('Registrar enrichment completed partially; ownership classification may require manual review.');
	}
	if (registrarCoverage.knownRatio < 0.8) {
		warnings.push(`Registrar coverage is ${registrarCoverage.knownRatio}; ownership classification may require manual review.`);
	}
	const capDropped = input.candidateUniverse.dropped.cap ?? 0;
	if (capDropped > 0) {
		warnings.push(`Candidate universe was truncated by cap (${capDropped} candidate(s) dropped); discovery coverage is incomplete.`);
	}
	if (input.candidateUniverse.seeded > 0 && input.candidateUniverse.surfaced === 0) {
		warnings.push('Candidate universe produced no surfaced findings; report is a shallow negative result, not proof of zero portfolio sprawl.');
	}
	if (input.plannerEfficiency?.mode === 'enforce') {
		const reduction =
			1 - input.plannerEfficiency.candidateSignalProbes / Math.max(1, input.plannerEfficiency.baselineCandidateSignalProbes);
		if (reduction > 0.5) {
			warnings.push(
				`Discovery planner reduced candidate-backed probes by ${(reduction * 100).toFixed(1)}%; review recall guard metrics before treating coverage as exhaustive.`,
			);
		}
	}

	return {
		candidateUniverse: input.candidateUniverse,
		signalCoverage,
		registrarCoverage,
		...(input.plannerEfficiency ? { plannerEfficiency: input.plannerEfficiency } : {}),
		warnings,
	};
}
