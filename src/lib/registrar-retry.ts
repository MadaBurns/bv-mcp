// SPDX-License-Identifier: BUSL-1.1

/**
 * Pure helpers for detecting transient registrar-lookup failures in a brand-audit
 * CheckResult. Drives Phase 2b's consumer auto-retry and any future re-enqueue
 * surface.
 *
 * "Transient" = `registrarSource: 'lookup_failed'` carried by the target summary
 * finding or any candidate finding. Deterministic states (rdap, whois, redacted,
 * notfound, unknown) and the deadline-skip enrichment status are explicitly
 * NOT retryable — those are surfaced by different mechanisms (classification,
 * Phase 7 deadline retry).
 */

import type { CheckResult } from './scoring';

export interface RetryableCandidate {
	domain: string;
	/** Stable reason token from the underlying lookup. Non-null for retryable rows. */
	failureReason: string;
}

export interface RetryablePayload {
	/** Set when the *target* (seed) registrar lookup failed transiently. */
	target: { failureReason: string } | null;
	/** Candidates whose individual RDAP/WHOIS calls failed transiently. */
	candidates: RetryableCandidate[];
}

function readMetaString(metadata: unknown, key: string): string | null {
	if (typeof metadata !== 'object' || metadata === null) return null;
	const value = (metadata as Record<string, unknown>)[key];
	return typeof value === 'string' ? value : null;
}

function readMetaBool(metadata: unknown, key: string): boolean {
	if (typeof metadata !== 'object' || metadata === null) return false;
	return (metadata as Record<string, unknown>)[key] === true;
}

export function findRetryableCandidates(result: CheckResult): RetryablePayload {
	let target: RetryablePayload['target'] = null;
	const candidates: RetryableCandidate[] = [];

	for (const finding of result.findings) {
		const md = finding.metadata;
		if (!md) continue;

		// Target summary lives on the `summary: true` finding and reports
		// `targetRegistrarSource` / `targetRegistrarFailureReason`.
		if (readMetaBool(md, 'summary')) {
			if (readMetaString(md, 'targetRegistrarSource') === 'lookup_failed') {
				const reason = readMetaString(md, 'targetRegistrarFailureReason');
				if (reason) target = { failureReason: reason };
			}
			continue;
		}

		// Candidate rows: keyed by `candidate: <domain>` and carry per-row
		// `registrarSource` / `registrarFailureReason`.
		const domain = readMetaString(md, 'candidate');
		if (!domain) continue;
		// Phase 7: deadline-skipped candidates are retryable too — same enqueue
		// surface as lookup_failed. Reported with a synthetic 'deadline_skipped'
		// reason so the retry policy can distinguish them from transient failures.
		if (readMetaString(md, 'registrarEnrichmentStatus') === 'skipped_deadline') {
			candidates.push({ domain, failureReason: 'deadline_skipped' });
			continue;
		}
		if (readMetaString(md, 'registrarSource') !== 'lookup_failed') continue;
		const reason = readMetaString(md, 'registrarFailureReason');
		if (!reason) continue;
		candidates.push({ domain, failureReason: reason });
	}

	return { target, candidates };
}

export function shouldRetryAudit(result: CheckResult): boolean {
	const retryable = findRetryableCandidates(result);
	return retryable.target !== null || retryable.candidates.length > 0;
}

/**
 * Shape of a brand-audit queue message, narrowed to the fields the retry helper
 * cares about. Decoupled from the consumer module so this file stays a pure
 * dependency-free helper.
 */
export interface RetryDecisionMessage {
	auditId: string;
	target: string;
	format: string;
	min_confidence?: number;
	depth?: string;
	brand_aliases?: string[];
	candidate_domains?: string[];
	watchId?: string;
	ownerId?: string;
	retry_attempt?: number;
}

/**
 * Decide whether a completed audit should be retried, given the current message
 * (carrying its `retry_attempt`) and the CheckResult.
 *
 * Returns the new queue message to enqueue, or `null` when no retry should fire:
 *   - already at retry_attempt=1 (single-pass policy)
 *   - no retryable candidates / target
 *
 * Pure — no I/O, no enqueue side effect. The caller (`processBrandAuditMessage`)
 * gates on the existing `retry_scheduled` step row for idempotency, and is the
 * only site that actually calls `brandAuditQueue.send`.
 */
export function decideRetryEnqueue<M extends RetryDecisionMessage>(result: CheckResult, message: M): M | null {
	const attempt = typeof message.retry_attempt === 'number' ? message.retry_attempt : 0;
	if (attempt >= 1) return null;
	if (!shouldRetryAudit(result)) return null;
	return { ...message, retry_attempt: 1 };
}
