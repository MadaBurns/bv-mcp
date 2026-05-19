// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 2b of registrar-coverage-tdd-plan.md — pure helper deciding whether
 * the consumer should enqueue a retry pass. Kept pure so the chaos / duplicate-
 * delivery cases can be pinned without spinning the whole consumer / queue.
 */

import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import { decideRetryEnqueue } from '../src/lib/registrar-retry';
import type { BrandAuditQueueMessage } from '../src/queue/brand-audit-consumer';

function summary(targetSource: string, failureReason?: string): CheckResult['findings'][number] {
	return {
		category: 'brand_audit',
		title: 'summary',
		severity: 'info',
		detail: '',
		metadata: {
			summary: true,
			targetRegistrarSource: targetSource,
			...(failureReason ? { targetRegistrarFailureReason: failureReason } : {}),
		},
	};
}

function candidate(domain: string, source: string, failureReason?: string): CheckResult['findings'][number] {
	return {
		category: 'brand_audit',
		title: domain,
		severity: 'low',
		detail: '',
		metadata: {
			candidate: domain,
			registrarSource: source,
			...(failureReason ? { registrarFailureReason: failureReason } : {}),
		},
	};
}

function makeResult(findings: CheckResult['findings']): CheckResult {
	return { category: 'brand_audit', score: 100, findings };
}

const baseMsg: BrandAuditQueueMessage = {
	auditId: 'aud-1',
	target: 'example.com',
	format: 'json',
};

describe('decideRetryEnqueue', () => {
	it('returns a retry message when retry_attempt=0 and candidates have lookup_failed', () => {
		const result = makeResult([
			summary('rdap'),
			candidate('a.com', 'lookup_failed', 'rdap_http_503'),
		]);
		const decision = decideRetryEnqueue(result, baseMsg);
		expect(decision).not.toBeNull();
		expect(decision!.auditId).toBe('aud-1');
		expect(decision!.target).toBe('example.com');
		expect(decision!.retry_attempt).toBe(1);
	});

	it('returns a retry message when retry_attempt=0 and target lookup_failed', () => {
		const result = makeResult([summary('lookup_failed', 'exception')]);
		expect(decideRetryEnqueue(result, baseMsg)?.retry_attempt).toBe(1);
	});

	it('returns null when retry_attempt=1 (already retried — bound to a single pass)', () => {
		const result = makeResult([
			summary('rdap'),
			candidate('a.com', 'lookup_failed', 'rdap_http_503'),
		]);
		const decision = decideRetryEnqueue(result, { ...baseMsg, retry_attempt: 1 });
		expect(decision).toBeNull();
	});

	it('returns null when nothing is retryable', () => {
		const result = makeResult([
			summary('rdap'),
			candidate('a.com', 'rdap'),
			candidate('b.com', 'redacted'),
		]);
		expect(decideRetryEnqueue(result, baseMsg)).toBeNull();
	});

	it('returns a retry message when a candidate hit skipped_deadline (Phase 7 surface)', () => {
		const result = makeResult([
			summary('rdap'),
			{
				category: 'brand_audit',
				title: 'late.com',
				severity: 'info',
				detail: '',
				metadata: {
					candidate: 'late.com',
					registrarSource: 'unknown',
					registrarEnrichmentStatus: 'skipped_deadline',
				},
			},
		]);
		expect(decideRetryEnqueue(result, baseMsg)?.retry_attempt).toBe(1);
	});

	it('preserves message context fields (format, min_confidence, watchId) on the retry payload', () => {
		const result = makeResult([candidate('a.com', 'lookup_failed', 'rdap_http_503')]);
		const decision = decideRetryEnqueue(result, {
			...baseMsg,
			format: 'markdown',
			min_confidence: 0.7,
			watchId: 'watch-42',
			ownerId: 'owner-7',
		});
		expect(decision).toMatchObject({
			format: 'markdown',
			min_confidence: 0.7,
			watchId: 'watch-42',
			ownerId: 'owner-7',
			retry_attempt: 1,
		});
	});
});
