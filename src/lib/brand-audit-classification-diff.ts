// SPDX-License-Identifier: BUSL-1.1

/**
 * Classification hash + diff helpers for the brand-audit watch webhook path.
 *
 * `computeClassificationHash` produces a SHA-256 hex digest of the sorted
 * (domain, bucket) tuples in a brand-audit CheckResult. Order-independent,
 * summary-row-independent, deterministic. Storage layer (`brand_audit_watches.
 * last_classification_hash`) only needs to compare hashes to detect drift.
 *
 * `computeDiff` returns the actual added/removed/modified candidate sets when
 * drift is detected — fills the `changes` field on `BrandAuditWatchWebhookPayload`.
 *
 * Both functions are pure: no I/O, no clock, no random. Trivially testable.
 */

import type { CheckResult, Finding } from './scoring';
import type { BrandAuditBucket, BrandAuditWatchDiffEntry } from '../schemas/brand-audit-watch-webhook';

interface CandidateTuple {
	domain: string;
	bucket: BrandAuditBucket;
}

function extractCandidates(result: CheckResult): CandidateTuple[] {
	const out: CandidateTuple[] = [];
	for (const f of result.findings as Finding[]) {
		const m = f.metadata;
		if (!m || typeof m.candidate !== 'string' || typeof m.bucket !== 'string') continue;
		out.push({ domain: m.candidate as string, bucket: m.bucket as BrandAuditBucket });
	}
	return out;
}

function sortedKey(c: CandidateTuple[]): string {
	return c
		.slice()
		.sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0))
		.map((t) => `${t.domain}:${t.bucket}`)
		.join('|');
}

/** SHA-256 hex digest of the sorted (domain, bucket) tuples. */
export async function computeClassificationHash(result: CheckResult): Promise<string> {
	const key = sortedKey(extractCandidates(result));
	const bytes = new TextEncoder().encode(key);
	const digest = await crypto.subtle.digest('SHA-256', bytes);
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

export interface ClassificationDiff {
	added: BrandAuditWatchDiffEntry[];
	removed: BrandAuditWatchDiffEntry[];
	modified: BrandAuditWatchDiffEntry[];
}

/** Compute `{ added, removed, modified }` between two CheckResults. */
export function computeDiff(previous: CheckResult, current: CheckResult): ClassificationDiff {
	const prev = new Map<string, BrandAuditBucket>();
	for (const c of extractCandidates(previous)) prev.set(c.domain, c.bucket);
	const curr = new Map<string, BrandAuditBucket>();
	for (const c of extractCandidates(current)) curr.set(c.domain, c.bucket);

	const added: BrandAuditWatchDiffEntry[] = [];
	const removed: BrandAuditWatchDiffEntry[] = [];
	const modified: BrandAuditWatchDiffEntry[] = [];

	for (const [domain, bucket] of curr.entries()) {
		const prevBucket = prev.get(domain);
		if (prevBucket === undefined) {
			added.push({ domain, bucket });
		} else if (prevBucket !== bucket) {
			modified.push({ domain, bucket, previousBucket: prevBucket });
		}
	}
	for (const [domain, bucket] of prev.entries()) {
		if (!curr.has(domain)) removed.push({ domain, bucket });
	}

	const byDomain = (a: BrandAuditWatchDiffEntry, b: BrandAuditWatchDiffEntry) => (a.domain < b.domain ? -1 : 1);
	added.sort(byDomain);
	removed.sort(byDomain);
	modified.sort(byDomain);
	return { added, removed, modified };
}
