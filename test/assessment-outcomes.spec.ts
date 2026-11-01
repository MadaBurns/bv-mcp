// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { classifyAssessmentObservation, summarizeAssessmentOutcomes } from '../src/lib/assessment-outcomes';
import type { AssessmentObservation } from '../src/lib/assessment-outcomes';
import type { CtCoverage } from '../src/lib/ct-coverage';

const coverage: CtCoverage = {
	basis: 'ct-sample',
	perSource: [{ source: 'crtsh', outcome: 'ok', contributed: true, historyWindow: 'unexpired-only' }],
	contributing: ['crtsh'], unavailable: [], notConsulted: ['certspotter'], degraded: true, caveat: 'CT sample only',
};
const response: AssessmentObservation = { vantage: 'worker', transport: 'response', httpStatus: 200 };

describe('assessment outcome contract', () => {
	it('reports usable CT samples separately from operational failures without weakening coverage', () => {
		const result = classifyAssessmentObservation({ ...response, ct: { returnedSamples: 12, coverage } });
		expect(result.disposition).toBe('partial_source_success');
		expect(result.operationalFailure).toBe(false);
		expect(result.reviewCompleted).toBe(false);
		expect(result.ct).toMatchObject({ basis: 'ct-sample', degraded: true, notConsultedSources: 1, returnedSamples: 12 });
		expect(coverage.degraded).toBe(true);
	});

	it('retains stale fallback age and truncation alongside returned samples', () => {
		const result = classifyAssessmentObservation({ ...response, ct: { returnedSamples: 3, coverage }, truncated: true,
			cache: { provenance: 'stale_fallback', ageMs: 143 * 60_000 } });
		expect(result.disposition).toBe('stale_fallback');
		expect(result.cache?.ageMs).toBe(8_580_000);
		expect(result.truncated).toBe(true);
		expect(result.operationalFailure).toBe(false);
	});

	it('requires challenge evidence rather than inferring a WAF from HTTP 403', () => {
		const denied = classifyAssessmentObservation({ ...response, httpStatus: 403 });
		const challenged = classifyAssessmentObservation({ ...response, httpStatus: 403, accessEvidence: 'challenge_header' });
		expect(denied.disposition).toBe('access_restriction');
		expect(denied.accessEvidence).toBeUndefined();
		expect(challenged.disposition).toBe('access_challenge');
		expect(denied.reviewCompleted).toBe(false);
		expect(challenged.reviewCompleted).toBe(false);
	});

	it('distinguishes HTTP errors, transport failures and measured timeout phases', () => {
		expect(classifyAssessmentObservation({ ...response, httpStatus: 504 }).disposition).toBe('upstream_http_error');
		expect(classifyAssessmentObservation({ vantage: 'local', transport: 'network_error' }).disposition).toBe('transport_failure');
		const result = classifyAssessmentObservation({ vantage: 'local', transport: 'timeout', timeoutPhase: 'response_headers',
			phaseTimingsMs: { connect: 42, response_headers: 12_000 }, capturedBytes: 0 });
		expect(result.timeoutPhase).toBe('response_headers');
		expect(result.phaseTimingsMs).toEqual({ connect: 42, response_headers: 12_000 });
		expect(classifyAssessmentObservation({ vantage: 'worker', transport: 'timeout' }).timeoutPhase).toBe('unknown');
	});

	it('defers a capped sitemap review despite HTTP 200 and keeps limits intact', () => {
		const result = classifyAssessmentObservation({ ...response, capturedBytes: 2_097_152, byteLimit: 2_097_152,
			responseSizeCapReached: true, reviewCompleted: true });
		expect(result.disposition).toBe('response_size_cap');
		expect(result.continuation).toBe('deferred_within_existing_limits');
		expect(result.reviewCompleted).toBe(false);
		expect(result.truncated).toBe(true);
		expect(classifyAssessmentObservation(response).disposition).toBe('unassessed');
		expect(classifyAssessmentObservation({ ...response, reviewCompleted: true }).disposition).toBe('completed');
	});

	it('rejects impossible byte counts and timings rather than reporting a false zero', () => {
		expect(() => classifyAssessmentObservation({ ...response, capturedBytes: 11, byteLimit: 10 })).toThrow();
		expect(() => classifyAssessmentObservation({ ...response, capturedBytes: -1 })).toThrow();
		expect(() => classifyAssessmentObservation({ ...response, phaseTimingsMs: { connect: NaN } })).toThrow();
	});

	it('projects only allowlisted measurements, omitting raw response data', () => {
		const input = { ...response, url: 'https://example.test/private', body: 'untrusted response', error: 'raw error' };
		const result = JSON.stringify(classifyAssessmentObservation(input));
		expect(result).not.toContain('example.test');
		expect(result).not.toContain('untrusted');
		expect(result).not.toContain('raw error');
	});

	it('reconciles attempts by vantage and controls; samples are counts across attempts, never inventory', () => {
		const outcomes = [
			classifyAssessmentObservation({ ...response, ct: { returnedSamples: 12, coverage } }),
			classifyAssessmentObservation({ ...response, transport: 'timeout', httpStatus: undefined }),
			classifyAssessmentObservation({ ...response, reviewCompleted: true, positiveControl: true, capturedBytes: 10 }),
			classifyAssessmentObservation({ ...response, vantage: 'mobile', reviewCompleted: true }),
		];
		const summary = summarizeAssessmentOutcomes(outcomes);
		expect(summary.attempts).toBe(4);
		expect(summary.groups).toHaveLength(3);
		const assessed = summary.groups[0];
		expect(assessed.attempts).toBe(2);
		expect(assessed.operationalFailures).toBe(1);
		expect(assessed.returnedCtSamples).toBe(12);
		expect(assessed.notConsultedCtSources).toBe(1);
		expect(assessed.attemptsWithByteMeasurements).toBe(0);
		expect(Object.values(assessed.byDisposition).reduce((sum, value) => sum + value, 0)).toBe(assessed.attempts);
		expect(summary.groups[1].completedReviews).toBe(1);
	});
});
