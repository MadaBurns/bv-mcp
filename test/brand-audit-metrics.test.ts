// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import { summarizeBrandAuditMetrics } from '../src/lib/brand-audit-metrics';

describe('summarizeBrandAuditMetrics', () => {
	it('summarizes step timings and cache effectiveness', () => {
		const summary = summarizeBrandAuditMetrics({
			startedAtMs: 1000,
			finishedAtMs: 1900,
			steps: [
				{ name: 'candidate_generation', status: 'completed', startedAtMs: 1000, finishedAtMs: 1100 },
				{ name: 'dns_signals', status: 'partial', startedAtMs: 1100, finishedAtMs: 1700 },
			],
			dns: { queries: 80, cacheHits: 30, errors: 2 },
			rdap: { queries: 20, cacheHits: 5, errors: 1 },
		});

		expect(summary.elapsedMs).toBe(900);
		expect(summary.stepStatusCounts).toEqual({ completed: 1, partial: 1, failed: 0, skipped: 0 });
		expect(summary.dns.cacheHitRatio).toBe(0.38);
		expect(summary.rdap.cacheHitRatio).toBe(0.25);
		expect(summary.warnings).toContain('dns_signals completed partially; report coverage is incomplete.');
	});
});
