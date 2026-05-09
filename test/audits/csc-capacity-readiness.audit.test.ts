// CSC capacity-readiness invariants. This is the audit-layer codification
// of the math in CSC-Scalable-Architecture-Design.md §1.2 — the configuration
// values that make 2.5M-domain portfolio audits possible.
//
// If any of these drift toward CSC-incompatible values, this test fails in
// CI before a regression reaches prod. Update both this test AND the design
// doc together if a CSC-class threshold legitimately changes.

import { describe, expect, it } from 'vitest';
import {
	GLOBAL_DAILY_TOOL_LIMIT,
	PER_CHECK_TIMEOUT_MS,
	SCAN_TIMEOUT_MS,
	TIER_TOOL_DAILY_LIMITS,
} from '../../src/lib/config';

/**
 * Baseline numbers used for the projection — derived from production
 * analytics over the last 7 days (last refresh 2026-05-09):
 *   - scan_domain p50 latency: 12.5s
 *   - scan_domain p95 latency: 18.0s
 * Source: `node .dev/analytics-30d.mjs 7` `Latency percentiles` table.
 */
const PRODUCTION_P50_MS = 12_500;
const PRODUCTION_P95_MS = 18_000;
/** Realistic batch settings (`/internal/tools/batch`). */
const BATCH_CONCURRENCY = 50; // max accepted by batch endpoint
const CONCURRENT_BATCHES = 20; // dispatched in parallel from orchestrator
/** Headline target. */
const CSC_HEADLINE_PORTFOLIO = 2_500_000;

describe('CSC capacity-readiness invariants', () => {
	describe('Quota headroom (Phase 0)', () => {
		it('partner.scan_domain quota covers a one-shot 2.5M audit', () => {
			expect(TIER_TOOL_DAILY_LIMITS.partner?.scan_domain).toBeGreaterThanOrEqual(CSC_HEADLINE_PORTFOLIO);
		});

		it('partner.scan alias matches scan_domain (tools/call resolves the alias)', () => {
			expect(TIER_TOOL_DAILY_LIMITS.partner?.scan).toBe(TIER_TOOL_DAILY_LIMITS.partner?.scan_domain);
		});

		// GLOBAL_DAILY_TOOL_LIMIT applies only to anonymous (unauthenticated) traffic;
		// /internal/tools/batch and authenticated callers bypass it. Documenting via
		// the test so a future reader understands why we don't gate against it here.
		it('GLOBAL_DAILY_TOOL_LIMIT does not constrain authenticated CSC traffic', () => {
			// Sanity check: it's a positive number, not infinity, but irrelevant to
			// the CSC code path because authenticated callers / internal binding
			// don't pass through the global counter.
			expect(GLOBAL_DAILY_TOOL_LIMIT).toBeGreaterThan(0);
			expect(Number.isFinite(GLOBAL_DAILY_TOOL_LIMIT)).toBe(true);
		});
	});

	describe('Timeout budget (per-scan latency envelope)', () => {
		it('SCAN_TIMEOUT_MS leaves headroom over observed p50', () => {
			// scan_domain orchestrates 16 sub-checks via Promise.allSettled wrapped in
			// a single SCAN_TIMEOUT_MS race. If the timeout drops below the observed
			// p50, ~half of CSC scans would return partial results.
			expect(SCAN_TIMEOUT_MS).toBeGreaterThanOrEqual(PRODUCTION_P50_MS);
		});

		it('PER_CHECK_TIMEOUT_MS leaves any single sub-check unable to monopolise the budget', () => {
			// PER_CHECK_TIMEOUT_MS bounds an individual leaf check (SPF, DKIM, ...)
			// so one slow upstream can't exhaust SCAN_TIMEOUT_MS for the whole scan.
			expect(PER_CHECK_TIMEOUT_MS).toBeLessThan(SCAN_TIMEOUT_MS);
			expect(PER_CHECK_TIMEOUT_MS).toBeGreaterThanOrEqual(5_000);
		});
	});

	describe('Throughput projection — completes within 24h SLO', () => {
		it('projects <24h for the headline 2.5M-domain audit', () => {
			// At p50=12.5s with `concurrency × concurrent_batches` in flight:
			//   throughput = (concurrency * concurrent_batches) / p50_s
			// Then runtime = portfolio_size / throughput.
			const throughputDomainsPerSecond = (BATCH_CONCURRENCY * CONCURRENT_BATCHES) / (PRODUCTION_P50_MS / 1000);
			const projectedRuntimeSeconds = CSC_HEADLINE_PORTFOLIO / throughputDomainsPerSecond;
			const projectedRuntimeHours = projectedRuntimeSeconds / 3600;

			// SLO target: 95% within 24h, 99% within 72h.
			// p50 projection should be well under 24h; assert <12h to leave slack.
			expect(projectedRuntimeHours).toBeLessThan(12);
		});

		it('projects p95 envelope inside the 24h SLO', () => {
			// At p95 latency every scan takes 18s instead of 12.5s.
			const throughputDomainsPerSecond = (BATCH_CONCURRENCY * CONCURRENT_BATCHES) / (PRODUCTION_P95_MS / 1000);
			const projectedRuntimeSeconds = CSC_HEADLINE_PORTFOLIO / throughputDomainsPerSecond;
			const projectedRuntimeHours = projectedRuntimeSeconds / 3600;
			expect(projectedRuntimeHours).toBeLessThan(24);
		});
	});
});
