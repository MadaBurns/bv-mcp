// SPDX-License-Identifier: BUSL-1.1

/**
 * Hot-path latency budget constants for the three highest-frequency MCP tools.
 *
 * ## Measurement methodology (C-perf, 2026-06-23)
 *
 * All numbers were measured inside the @cloudflare/vitest-pool-workers runtime
 * using a deterministic fetch mock that introduces a FIXED 80ms delay per DNS
 * round-trip (Cloudflare DoH p50 observed in prod). 20 samples, sorted, p50/p95
 * extracted. The mock removes network jitter so the numbers reflect pure
 * EXECUTION latency at a stable DNS RTT, not a noisy wall-clock snapshot.
 *
 * ## Measured baseline (80ms simulated DNS RTT, 20 samples each)
 *
 * | tool         | p50    | p95    | notes                                     |
 * |-------------|--------|--------|-------------------------------------------|
 * | scan_domain | 1062ms | 1075ms | 19-check concurrent fan-out; ~13 serial    |
 * |             |        |        | query hops within the deepest check chain  |
 * | check_dmarc |   82ms |   82ms | 1 TXT query + tree-walk (1 hop on NOERROR) |
 * | check_spf   |  244ms |  245ms | 3 sequential hops (TXT + 2 include expands) |
 *
 * ## Sequential baseline (for reference — proves concurrent value)
 *
 * With dnsConcurrency=1 (all 19 checks run serially), scan_domain takes ~7000ms
 * at 80ms DNS RTT. The default concurrency=12 achieves ~1062ms — a **6.6×
 * reduction** from the existing concurrent fan-out.
 *
 * ## Budget targets (for I2 to cite as "provable latency")
 *
 * Targets are set at 2× the measured p95 to absorb:
 * - Real DNS jitter (production DoH p95 is ~150–200ms vs. 80ms mock)
 * - Worker cold-start overhead on first request in a new isolate
 * - Retry budget (scan_domain retries transient errors within its budget)
 *
 * At real DoH p95 (~150ms), scale these targets proportionally:
 *   scan_domain real-world p95 ≈ 1075 × (150/80) ≈ 2000ms
 *   check_dmarc real-world p95 ≈  82  × (150/80) ≈  154ms
 *   check_spf   real-world p95 ≈ 245  × (150/80) ≈  459ms
 *
 * The targets below are the ENGINEERING FLOOR (achievable with the current
 * concurrent architecture + fast DNS). If you're seeing these exceeded in
 * production, investigate: (a) DNS resolver latency spike, (b) a regression
 * that reintroduced sequential awaits, (c) Workers CPU quota contention.
 *
 * @see test/hot-path-concurrency.perf.spec.ts — stable regression guard
 * @see docs/superpowers/specs/ — I2 (CSC demo) cites these constants
 */

export interface ToolLatencyBudget {
	/** Median latency at 80ms DNS RTT (engineering baseline). */
	p50Ms: number;
	/** 95th-percentile latency at 80ms DNS RTT (engineering baseline). */
	p95Ms: number;
	/** p95 target budget. Tools must not ARCHITECTURALLY exceed this (sequential regressions). */
	targetP95Ms: number;
	/** Human-readable note on what dominates latency for this tool. */
	notes: string;
}

/**
 * Latency budget per hot-path tool.
 *
 * Measured 2026-06-23 on @cloudflare/vitest-pool-workers with 80ms simulated
 * DNS RTT (20 samples each). Production numbers will be proportionally higher
 * due to real DoH latency, but the RATIOS (concurrency speedup, check count)
 * are stable and testable.
 */
export const LATENCY_BUDGET: Record<'scan_domain' | 'check_dmarc' | 'check_spf', ToolLatencyBudget> = {
	scan_domain: {
		p50Ms: 1062,
		p95Ms: 1075,
		// 2× p95 headroom; dominated by the deepest serial DNS chain across all 19 checks
		targetP95Ms: 2200,
		notes:
			'19-check concurrent fan-out (Promise.allSettled). ' +
			'Dominated by deepest serial query chain (~13 hops). ' +
			'Sequential baseline ~7000ms → 6.6× speedup from concurrency.',
	},
	check_dmarc: {
		p50Ms: 82,
		p95Ms: 82,
		// 2× p95 headroom; simple single TXT + optional org-domain tree walk
		targetP95Ms: 200,
		notes:
			'1 TXT query + RFC 9989 tree walk (1 hop for a standard domain). ' +
			'Bounded by a single DNS round-trip.',
	},
	check_spf: {
		p50Ms: 244,
		p95Ms: 245,
		// 2× p95 headroom; 3 serial hops: apex TXT + include chain expansion
		targetP95Ms: 510,
		notes:
			'3 sequential DNS hops: apex TXT + 2 include-chain expansions. ' +
			'RFC 7208 allows up to 10 include lookups (worst-case ~10×80ms = 800ms at 80ms RTT). ' +
			'The test fixture uses v=spf1 include:_spf.google.com -all which expands once.',
	},
} as const;

/**
 * The measured baseline DoH RTT used for the p50/p95 measurements above.
 * Scale the p50/p95 values proportionally for other DNS RTT conditions.
 */
export const LATENCY_BUDGET_DNS_RTT_MS = 80;

/**
 * The number of checks in the scan_domain fan-out at measurement time.
 * If this grows, targetP95Ms should be re-evaluated (though the concurrent
 * architecture means adding a check adds ~0ms to p95 if a parallel slot is free).
 */
export const LATENCY_BUDGET_SCAN_CHECK_COUNT = 19;

/**
 * The measured concurrency speedup ratio for scan_domain.
 * sequential_ms / concurrent_ms ≈ 7000 / 1062 ≈ 6.6×
 * Maintained here for I2 to cite in the CSC demo.
 */
export const LATENCY_BUDGET_CONCURRENCY_SPEEDUP = 6.6;
