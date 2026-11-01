// SPDX-License-Identifier: BUSL-1.1

import type { CtCoverage } from './ct-coverage';

/** Runner observations, never inferred from a request's mere success or a DNS answer. */
export interface AssessmentObservation {
	vantage: 'worker' | 'local' | 'mobile' | 'unknown';
	positiveControl?: boolean;
	transport: 'response' | 'network_error' | 'timeout';
	httpStatus?: number;
	/** Set only for observed enforcement evidence; a bare 403 has no known cause. */
	accessEvidence?: 'challenge_header' | 'captcha_marker' | 'declared_restriction';
	timeoutPhase?: 'dns' | 'connect' | 'tls' | 'response_headers' | 'response_body' | 'unknown';
	/** Omit phases the runtime does not measure. Durations are milliseconds, not timestamps. */
	phaseTimingsMs?: Partial<Record<'dns' | 'connect' | 'tls' | 'response_headers' | 'response_body', number>>;
	capturedBytes?: number;
	byteLimit?: number;
	responseSizeCapReached?: boolean;
	truncated?: boolean;
	/** True only after the intended review/parser completed, not merely after HTTP 200. */
	reviewCompleted?: boolean;
	ct?: { returnedSamples: number; coverage: CtCoverage };
	cache?: { provenance: 'fresh' | 'stale_fallback'; ageMs?: number };
}

export type AssessmentDisposition =
	| 'completed'
	| 'partial_source_success'
	| 'stale_fallback'
	| 'response_size_cap'
	| 'access_challenge'
	| 'access_restriction'
	| 'upstream_http_error'
	| 'transport_failure'
	| 'timeout'
	| 'unassessed';

export interface AssessmentOutcome {
	schemaVersion: 1;
	vantage: AssessmentObservation['vantage'];
	positiveControl: boolean;
	disposition: AssessmentDisposition;
	/** HTTP/transport failures differ from a usable, coverage-limited sample. */
	operationalFailure: boolean;
	reviewCompleted: boolean;
	httpStatus?: number;
	accessEvidence?: AssessmentObservation['accessEvidence'];
	timeoutPhase?: AssessmentObservation['timeoutPhase'];
	phaseTimingsMs: AssessmentObservation['phaseTimingsMs'];
	capturedBytes?: number;
	byteLimit?: number;
	truncated: boolean;
	responseSizeCapReached: boolean;
	/** A capped review is deferred; this contract never directs a retry or bypass. */
	continuation: 'none' | 'deferred_within_existing_limits';
	cache?: AssessmentObservation['cache'];
	ct?: {
		basis: 'ct-sample';
		returnedSamples: number;
		degraded: boolean;
		attemptedSources: number;
		contributingSources: number;
		unavailableSources: number;
		notConsultedSources: number;
	};
}

function count(value: number): number {
	if (!Number.isSafeInteger(value) || value < 0) throw new Error('Invalid assessment count');
	return value;
}

function duration(value: number): number {
	if (!Number.isFinite(value) || value < 0 || value > Number.MAX_SAFE_INTEGER) throw new Error('Invalid assessment duration');
	return value;
}

function requireMember(value: string, allowed: readonly string[]): void {
	if (!allowed.includes(value)) throw new Error('Invalid assessment classification');
}

/**
 * Project bounded observations onto a shareable contract. No URL, host, header,
 * response body, arbitrary error text or source label is copied into the result.
 * Coverage.degraded remains unchanged: not-consulted sources still limit recall,
 * but they do not turn returned CT samples into failed requests (#1348).
 */
export function classifyAssessmentObservation(observation: AssessmentObservation): AssessmentOutcome {
	const o = observation;
	requireMember(o.vantage, ['worker', 'local', 'mobile', 'unknown']);
	requireMember(o.transport, ['response', 'network_error', 'timeout']);
	if (o.accessEvidence !== undefined) requireMember(o.accessEvidence, ['challenge_header', 'captcha_marker', 'declared_restriction']);
	if (o.timeoutPhase !== undefined) requireMember(o.timeoutPhase, ['dns', 'connect', 'tls', 'response_headers', 'response_body', 'unknown']);
	if (o.cache) requireMember(o.cache.provenance, ['fresh', 'stale_fallback']);
	if (o.httpStatus !== undefined && (!Number.isInteger(o.httpStatus) || o.httpStatus < 100 || o.httpStatus > 599)) {
		throw new Error('Invalid assessment HTTP status');
	}
	const capturedBytes = o.capturedBytes === undefined ? undefined : count(o.capturedBytes);
	const byteLimit = o.byteLimit === undefined ? undefined : count(o.byteLimit);
	if (capturedBytes !== undefined && byteLimit !== undefined && capturedBytes > byteLimit) throw new Error('Invalid assessment byte limit');
	const phaseTimingsMs: NonNullable<AssessmentObservation['phaseTimingsMs']> = {};
	for (const phase of ['dns', 'connect', 'tls', 'response_headers', 'response_body'] as const) {
		const value = o.phaseTimingsMs?.[phase];
		if (value !== undefined) phaseTimingsMs[phase] = duration(value);
	}
	const ct = o.ct
		? {
				basis: 'ct-sample' as const,
				returnedSamples: count(o.ct.returnedSamples),
				degraded: o.ct.coverage.degraded,
				attemptedSources: o.ct.coverage.perSource.length,
				contributingSources: o.ct.coverage.contributing.length,
				unavailableSources: o.ct.coverage.unavailable.length,
				notConsultedSources: o.ct.coverage.notConsulted.length,
			}
		: undefined;
	const cache = o.cache
		? { provenance: o.cache.provenance, ...(o.cache.ageMs === undefined ? {} : { ageMs: duration(o.cache.ageMs) }) }
		: undefined;
	const httpError = o.httpStatus !== undefined && o.httpStatus >= 400;
	const accessEvidence = httpError ? o.accessEvidence : undefined;
	let disposition: AssessmentDisposition;
	if (o.responseSizeCapReached) disposition = 'response_size_cap';
	else if (ct && ct.returnedSamples > 0 && cache?.provenance === 'stale_fallback') disposition = 'stale_fallback';
	else if (ct && ct.returnedSamples > 0) disposition = 'partial_source_success';
	else if (o.transport === 'timeout') disposition = 'timeout';
	else if (o.transport === 'network_error') disposition = 'transport_failure';
	else if (accessEvidence === 'challenge_header' || accessEvidence === 'captcha_marker') disposition = 'access_challenge';
	else if (accessEvidence === 'declared_restriction' || o.httpStatus === 401 || o.httpStatus === 403) disposition = 'access_restriction';
	else if (httpError) disposition = 'upstream_http_error';
	else if (cache?.provenance === 'stale_fallback') disposition = 'stale_fallback';
	else if (o.reviewCompleted && !o.truncated) disposition = 'completed';
	else disposition = 'unassessed';
	return {
		schemaVersion: 1,
		vantage: o.vantage,
		positiveControl: o.positiveControl === true,
		disposition,
		operationalFailure: ['timeout', 'transport_failure', 'upstream_http_error'].includes(disposition),
		reviewCompleted: disposition === 'completed',
		...(o.httpStatus === undefined ? {} : { httpStatus: o.httpStatus }),
		...(accessEvidence ? { accessEvidence } : {}),
		...(o.transport === 'timeout' ? { timeoutPhase: o.timeoutPhase ?? 'unknown' } : {}),
		phaseTimingsMs,
		...(capturedBytes === undefined ? {} : { capturedBytes }),
		...(byteLimit === undefined ? {} : { byteLimit }),
		truncated: o.truncated === true || o.responseSizeCapReached === true,
		responseSizeCapReached: o.responseSizeCapReached === true,
		continuation: o.responseSizeCapReached ? 'deferred_within_existing_limits' : 'none',
		...(cache ? { cache } : {}),
		...(ct ? { ct } : {}),
	};
}

/** One input is one attempt; totals never deduplicate retries or mix vantage/control groups. */
export function summarizeAssessmentOutcomes(outcomes: readonly AssessmentOutcome[]) {
	const groups = new Map<string, {
		vantage: AssessmentOutcome['vantage'];
		positiveControl: boolean;
		attempts: number;
		completedReviews: number;
		operationalFailures: number;
		capturedBytes: number;
		attemptsWithByteMeasurements: number;
		truncated: number;
		staleFallbacks: number;
		attemptedCtSources: number;
		unavailableCtSources: number;
		notConsultedCtSources: number;
		returnedCtSamples: number;
		byDisposition: Partial<Record<AssessmentDisposition, number>>;
	}>();
	for (const outcome of outcomes) {
		const key = `${outcome.vantage}:${outcome.positiveControl}`;
		const group = groups.get(key) ?? {
			vantage: outcome.vantage,
			positiveControl: outcome.positiveControl,
			attempts: 0,
			completedReviews: 0,
			operationalFailures: 0,
			capturedBytes: 0,
			attemptsWithByteMeasurements: 0,
			truncated: 0,
			staleFallbacks: 0,
			attemptedCtSources: 0,
			unavailableCtSources: 0,
			notConsultedCtSources: 0,
			returnedCtSamples: 0,
			byDisposition: {},
		};
		group.attempts++;
		group.completedReviews += Number(outcome.reviewCompleted);
		group.operationalFailures += Number(outcome.operationalFailure);
		if (outcome.capturedBytes !== undefined) {
			group.capturedBytes = count(group.capturedBytes + outcome.capturedBytes);
			group.attemptsWithByteMeasurements++;
		}
		group.truncated += Number(outcome.truncated);
		group.staleFallbacks += Number(outcome.cache?.provenance === 'stale_fallback');
		group.attemptedCtSources += outcome.ct?.attemptedSources ?? 0;
		group.unavailableCtSources += outcome.ct?.unavailableSources ?? 0;
		group.notConsultedCtSources += outcome.ct?.notConsultedSources ?? 0;
		group.returnedCtSamples = count(group.returnedCtSamples + (outcome.ct?.returnedSamples ?? 0));
		group.byDisposition[outcome.disposition] = (group.byDisposition[outcome.disposition] ?? 0) + 1;
		groups.set(key, group);
	}
	return { attempts: outcomes.length, groups: [...groups.values()] };
}
