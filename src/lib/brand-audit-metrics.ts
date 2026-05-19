// SPDX-License-Identifier: BUSL-1.1

export type BrandAuditStepStatus = 'completed' | 'partial' | 'failed' | 'skipped';

export interface BrandAuditStepTiming {
	name: string;
	status: BrandAuditStepStatus;
	startedAtMs: number;
	finishedAtMs: number;
}

export interface BrandAuditCounterInput {
	queries: number;
	cacheHits: number;
	errors: number;
}

export interface BrandAuditMetricsInput {
	startedAtMs: number;
	finishedAtMs: number;
	steps: BrandAuditStepTiming[];
	dns: BrandAuditCounterInput;
	rdap: BrandAuditCounterInput;
}

export interface BrandAuditStepMetrics extends BrandAuditStepTiming {
	elapsedMs: number;
}

export interface BrandAuditCounterSummary extends BrandAuditCounterInput {
	cacheHitRatio: number;
}

export interface BrandAuditMetricsSummary {
	elapsedMs: number;
	steps: BrandAuditStepMetrics[];
	stepStatusCounts: Record<BrandAuditStepStatus, number>;
	dns: BrandAuditCounterSummary;
	rdap: BrandAuditCounterSummary;
	warnings: string[];
}

function elapsedMs(startedAtMs: number, finishedAtMs: number): number {
	return Math.max(0, finishedAtMs - startedAtMs);
}

function cacheHitRatio(counter: BrandAuditCounterInput): number {
	if (counter.queries === 0) return 1;
	return Math.round((counter.cacheHits / counter.queries) * 100) / 100;
}

function summarizeCounter(counter: BrandAuditCounterInput): BrandAuditCounterSummary {
	return {
		...counter,
		cacheHitRatio: cacheHitRatio(counter),
	};
}

export function summarizeBrandAuditMetrics(input: BrandAuditMetricsInput): BrandAuditMetricsSummary {
	const stepStatusCounts: Record<BrandAuditStepStatus, number> = {
		completed: 0,
		partial: 0,
		failed: 0,
		skipped: 0,
	};
	const warnings: string[] = [];
	const steps = input.steps.map((step) => {
		stepStatusCounts[step.status] += 1;
		if (step.status === 'partial') warnings.push(`${step.name} completed partially; report coverage is incomplete.`);
		if (step.status === 'failed') warnings.push(`${step.name} failed; report coverage is incomplete.`);

		return {
			...step,
			elapsedMs: elapsedMs(step.startedAtMs, step.finishedAtMs),
		};
	});

	return {
		elapsedMs: elapsedMs(input.startedAtMs, input.finishedAtMs),
		steps,
		stepStatusCounts,
		dns: summarizeCounter(input.dns),
		rdap: summarizeCounter(input.rdap),
		warnings,
	};
}
