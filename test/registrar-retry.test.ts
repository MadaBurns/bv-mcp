// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2a of registrar-coverage-tdd-plan.md — pure helper for detecting
 * transient registrar-lookup failures in a completed brand-audit CheckResult.
 *
 * Tested independently of the pipeline / queue / consumer so Phase 2b can
 * consume this predicate without spinning the whole orchestrator.
 */

import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import { findRetryableCandidates, shouldRetryAudit } from '../src/lib/registrar-retry';

function summary(targetSource: string, opts: { failureReason?: string } = {}): CheckResult['findings'][number] {
	return {
		category: 'brand_audit',
		title: 'Brand audit: classified',
		severity: 'info',
		detail: '',
		metadata: {
			summary: true,
			target: 'example.com',
			targetRegistrarSource: targetSource,
			...(opts.failureReason ? { targetRegistrarFailureReason: opts.failureReason } : {}),
		},
	};
}

function candidate(domain: string, source: string, opts: { failureReason?: string } = {}): CheckResult['findings'][number] {
	return {
		category: 'brand_audit',
		title: `Brand candidate: ${domain}`,
		severity: 'low',
		detail: '',
		metadata: {
			candidate: domain,
			registrarSource: source,
			...(opts.failureReason ? { registrarFailureReason: opts.failureReason } : {}),
		},
	};
}

function makeResult(findings: CheckResult['findings']): CheckResult {
	return { category: 'brand_audit', score: 100, findings };
}

describe('findRetryableCandidates', () => {
	it('returns target as retryable when target lookup_failed', () => {
		const result = makeResult([
			summary('lookup_failed', { failureReason: 'exception' }),
			candidate('a.com', 'rdap'),
			candidate('b.com', 'rdap'),
		]);
		const retryable = findRetryableCandidates(result);
		expect(retryable.target).toEqual({ failureReason: 'exception' });
		expect(retryable.candidates).toEqual([]);
	});

	it('returns lookup_failed candidates with their reasons', () => {
		const result = makeResult([
			summary('rdap'),
			candidate('a.com', 'rdap'),
			candidate('b.com', 'lookup_failed', { failureReason: 'rdap_http_503' }),
			candidate('c.com', 'lookup_failed', { failureReason: 'whois_error' }),
		]);
		const retryable = findRetryableCandidates(result);
		expect(retryable.target).toBeNull();
		expect(retryable.candidates).toEqual([
			{ domain: 'b.com', failureReason: 'rdap_http_503' },
			{ domain: 'c.com', failureReason: 'whois_error' },
		]);
	});

	it('does NOT flag unknown / notfound / redacted as retryable (deterministic states)', () => {
		const result = makeResult([
			summary('rdap'),
			candidate('a.com', 'unknown'),
			candidate('b.com', 'notfound'),
			candidate('c.com', 'redacted'),
		]);
		const retryable = findRetryableCandidates(result);
		expect(retryable.target).toBeNull();
		expect(retryable.candidates).toEqual([]);
	});

	it('flags skipped_deadline candidates as retryable with a synthetic deadline_skipped reason', () => {
		const result = makeResult([
			summary('rdap'),
			// skipped_deadline sets registrarSource='unknown' + registrarEnrichmentStatus='skipped_deadline'.
			{
				category: 'brand_audit',
				title: 'Brand candidate: late.com',
				severity: 'info',
				detail: '',
				metadata: {
					candidate: 'late.com',
					registrarSource: 'unknown',
					registrarEnrichmentStatus: 'skipped_deadline',
				},
			},
		]);
		const retryable = findRetryableCandidates(result);
		expect(retryable.candidates).toEqual([{ domain: 'late.com', failureReason: 'deadline_skipped' }]);
	});

	it('handles findings with missing/malformed metadata gracefully', () => {
		const result = makeResult([
			{ category: 'brand_audit', title: 'no metadata', severity: 'info', detail: '' },
			{ category: 'brand_audit', title: 'wrong shape', severity: 'info', detail: '', metadata: { foo: 'bar' } },
		]);
		const retryable = findRetryableCandidates(result);
		expect(retryable.target).toBeNull();
		expect(retryable.candidates).toEqual([]);
	});
});

describe('shouldRetryAudit', () => {
	it('true when target lookup_failed', () => {
		const result = makeResult([summary('lookup_failed', { failureReason: 'exception' })]);
		expect(shouldRetryAudit(result)).toBe(true);
	});

	it('true when any candidate lookup_failed', () => {
		const result = makeResult([
			summary('rdap'),
			candidate('a.com', 'lookup_failed', { failureReason: 'rdap_http_503' }),
		]);
		expect(shouldRetryAudit(result)).toBe(true);
	});

	it('false when all candidates resolved cleanly', () => {
		const result = makeResult([
			summary('rdap'),
			candidate('a.com', 'rdap'),
			candidate('b.com', 'whois'),
			candidate('c.com', 'redacted'),
		]);
		expect(shouldRetryAudit(result)).toBe(false);
	});
});
