// SPDX-License-Identifier: BUSL-1.1

export type RegistrarCoverageSource = 'rdap' | 'whois' | 'redacted' | 'notfound' | 'unknown';

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
	warnings: string[];
}

function round2(value: number): number {
	return Math.round(value * 100) / 100;
}

export function buildBrandAuditDepthSummary(input: BrandAuditDepthInput): BrandAuditDepthSummary {
	const statusValues = Object.values(input.signalStatus);
	const signalCoverage = {
		requested: statusValues.length,
		ok: statusValues.filter((s) => s.status === 'ok').length,
		failed: statusValues.filter((s) => s.status === 'failed' || s.status === 'error').length,
		partial: statusValues.filter((s) => s.status === 'partial').length,
		timeout: statusValues.filter((s) => s.status === 'timeout').length,
		skipped: statusValues.filter((s) => s.status.startsWith('skipped')).length,
	};

	const registrarCoverage = {
		total: input.registrarSources.length,
		rdap: input.registrarSources.filter((s) => s === 'rdap').length,
		whois: input.registrarSources.filter((s) => s === 'whois').length,
		redacted: input.registrarSources.filter((s) => s === 'redacted').length,
		notfound: input.registrarSources.filter((s) => s === 'notfound').length,
		unknown: input.registrarSources.filter((s) => s === 'unknown').length,
		knownRatio:
			input.registrarSources.length === 0
				? 1
				: round2(input.registrarSources.filter((s) => s === 'rdap' || s === 'whois').length / input.registrarSources.length),
	};

	const warnings: string[] = [];
	if (signalCoverage.timeout > 0 && input.signalStatus.san?.status === 'timeout') {
		warnings.push('SAN signal timed out; certificate-derived sibling coverage is incomplete.');
	}
	if (registrarCoverage.knownRatio < 0.8) {
		warnings.push(`Registrar coverage is ${registrarCoverage.knownRatio}; ownership classification may require manual review.`);
	}
	if (input.candidateUniverse.seeded > 0 && input.candidateUniverse.surfaced === 0) {
		warnings.push('Candidate universe produced no surfaced findings; report is a shallow negative result, not proof of zero portfolio sprawl.');
	}

	return {
		candidateUniverse: input.candidateUniverse,
		signalCoverage,
		registrarCoverage,
		warnings,
	};
}
