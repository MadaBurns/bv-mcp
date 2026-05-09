// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for src/tenants/alerts/diff.ts.
 *
 * Pure-function diff engine — every test runs synchronously, no fixtures, no
 * env. The 6-layer pyramid lives at the bottom here; webhook delivery is
 * tested separately in test/tenants/alerts/webhook.test.ts.
 */

import { describe, it, expect } from 'vitest';
import { computeCycleDiff, _MAX_HIGHLIGHTS, type FindingRow } from '../../../src/tenants/alerts/diff';
import type { ComputeCycleDiffOptions } from '../../../src/tenants/alerts/diff';

const baseOpts: ComputeCycleDiffOptions = {
	currentCycleId: 'cyc-current',
	baselineCycleId: 'cyc-prior',
	superTenantId: 'super-acme',
	subTenantId: 'sub-prod',
	domainsScanned: 5,
	scanAt: 1_715_000_000_000,
	emittedAt: 1_715_000_001_000,
	webhookUrl: 'https://hooks.slack.com/services/T0/B0/secret',
};

function row(domain: string, category: string, severity: FindingRow['severity'], title = 'finding'): FindingRow {
	return { domain, category, severity, title };
}

describe('computeCycleDiff', () => {
	it('empty current + empty baseline → 0 deltas', () => {
		const out = computeCycleDiff([], [], baseOpts);
		expect(out.totals.deltas).toBe(0);
		expect(out.highlights).toEqual([]);
		expect(out.totals.by_severity).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
	});

	it('all-new findings → all gained', () => {
		const current = [row('a.com', 'dmarc', 'high'), row('b.com', 'spf', 'medium')];
		const out = computeCycleDiff(current, [], baseOpts);
		expect(out.totals.deltas).toBe(2);
		expect(out.highlights.every((h) => h.delta === 'gained')).toBe(true);
	});

	it('all-removed findings → all lost', () => {
		const baseline = [row('a.com', 'dmarc', 'high'), row('b.com', 'spf', 'medium')];
		const out = computeCycleDiff([], baseline, baseOpts);
		expect(out.totals.deltas).toBe(2);
		expect(out.highlights.every((h) => h.delta === 'lost')).toBe(true);
	});

	it('severity escalation populates previous_severity', () => {
		const baseline = [row('a.com', 'dmarc', 'medium')];
		const current = [row('a.com', 'dmarc', 'high')];
		const out = computeCycleDiff(current, baseline, baseOpts);
		expect(out.totals.deltas).toBe(1);
		expect(out.highlights[0].delta).toBe('severity_changed');
		expect(out.highlights[0].severity).toBe('high');
		expect(out.highlights[0].previous_severity).toBe('medium');
	});

	it('mixed gain/lose/change scenario', () => {
		const baseline = [row('a.com', 'dmarc', 'medium'), row('b.com', 'spf', 'low')];
		const current = [
			row('a.com', 'dmarc', 'high'), // changed
			row('c.com', 'dnssec', 'critical'), // gained
		];
		const out = computeCycleDiff(current, baseline, baseOpts);
		expect(out.totals.deltas).toBe(3);
		const byDelta = out.highlights.reduce(
			(acc, h) => {
				acc[h.delta] = (acc[h.delta] ?? 0) + 1;
				return acc;
			},
			{} as Record<string, number>,
		);
		expect(byDelta).toEqual({ gained: 1, lost: 1, severity_changed: 1 });
	});

	it('highlights are ordered critical first, info last', () => {
		const current = [
			row('a.com', 'dmarc', 'info'),
			row('b.com', 'spf', 'critical'),
			row('c.com', 'dnssec', 'medium'),
			row('d.com', 'dkim', 'low'),
			row('e.com', 'mta-sts', 'high'),
		];
		const out = computeCycleDiff(current, [], baseOpts);
		expect(out.highlights.map((h) => h.severity)).toEqual(['critical', 'high', 'medium', 'low', 'info']);
	});

	it('caps highlights at 20 even when more deltas exist', () => {
		const current = Array.from({ length: 30 }, (_, i) => row(`d${i}.com`, 'dmarc', 'high'));
		const out = computeCycleDiff(current, [], baseOpts);
		expect(out.highlights.length).toBe(_MAX_HIGHLIGHTS);
		// totals.deltas reflects the full count, not just highlights
		expect(out.totals.deltas).toBe(30);
	});

	it('by_severity counts every delta, not just highlights', () => {
		const current = [
			row('a.com', 'dmarc', 'critical'),
			row('b.com', 'spf', 'high'),
			row('c.com', 'spf', 'high'),
			row('d.com', 'dkim', 'medium'),
		];
		const out = computeCycleDiff(current, [], baseOpts);
		expect(out.totals.by_severity).toEqual({ critical: 1, high: 2, medium: 1, low: 0, info: 0 });
	});

	it('same finding at same severity is NOT a delta', () => {
		const baseline = [row('a.com', 'dmarc', 'high')];
		const current = [row('a.com', 'dmarc', 'high')];
		const out = computeCycleDiff(current, baseline, baseOpts);
		expect(out.totals.deltas).toBe(0);
	});

	it('null baseline_cycle_id passes through (first-ever cycle)', () => {
		const out = computeCycleDiff([], [], { ...baseOpts, baselineCycleId: null });
		expect(out.baseline_cycle_id).toBeNull();
	});

	it('webhook_url_hash is 16 lowercase hex chars', () => {
		const out = computeCycleDiff([], [], baseOpts);
		expect(out.webhook_url_hash).toMatch(/^[a-f0-9]{16}$/);
	});
});
