// SPDX-License-Identifier: BUSL-1.1
//
// Unit test for the tier-classification predicate. Pure logic — no I/O.
// See docs/superpowers/plans/2026-05-20-brand-discovery-first-principles-tdd.md
// Task 1, Step 1.

import { describe, it, expect } from 'vitest';
import { tierFor, MUTUAL_EXCLUSIVE_PAIRS } from '../src/lib/brand-discovery-tiers';

describe('tierFor', () => {
	it('returns 0 for tenant-declared sources', () => {
		expect(tierFor({ source: 'tenant_domains', confidence: 1.0 })).toBe(0);
	});
	it('returns 1 for signal-graph candidates', () => {
		expect(tierFor({ source: 'infra_graph_signal', confidence: 0.7, specificityScore: 0.8 })).toBe(1);
	});
	it('returns 2 for declared/witnessed evidence from intel gateway', () => {
		expect(tierFor({ source: 'rdap_registrant_match', confidence: 0.95 })).toBe(2);
		expect(tierFor({ source: 'dmarc_rua', confidence: 0.9 })).toBe(2);
		expect(tierFor({ source: 'ct_walk', confidence: 0.85 })).toBe(2);
	});
	it('returns 3 for live-fallback DNS signals', () => {
		expect(tierFor({ source: 'ns', confidence: 0.6 })).toBe(3);
		expect(tierFor({ source: 'dkim_key_reuse', confidence: 0.7 })).toBe(3);
	});
	it('returns 4 for impersonation-only signals', () => {
		expect(tierFor({ source: 'active_lookalike', confidence: 0.3 })).toBe(4);
		expect(tierFor({ source: 'score_alert_critical_drop', confidence: 0.5 })).toBe(4);
	});
});

describe('MUTUAL_EXCLUSIVE_PAIRS', () => {
	it('declares Tier 0/1/2/3 ↔ Tier 4 as mutually exclusive', () => {
		expect(MUTUAL_EXCLUSIVE_PAIRS).toContainEqual([0, 4]);
		expect(MUTUAL_EXCLUSIVE_PAIRS).toContainEqual([1, 4]);
		expect(MUTUAL_EXCLUSIVE_PAIRS).toContainEqual([2, 4]);
		expect(MUTUAL_EXCLUSIVE_PAIRS).toContainEqual([3, 4]);
	});
});
