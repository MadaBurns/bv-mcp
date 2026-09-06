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

	it('unchanged findings in one category do not produce drift in either input order', () => {
		const findings = [row('example.com', 'spf', 'high', 'Permissive policy'), row('example.com', 'spf', 'low', 'Redundant include')];
		for (const current of [findings, [...findings].reverse()]) {
			for (const baseline of [findings, [...findings].reverse()]) {
				expect(computeCycleDiff(current, baseline, baseOpts).totals.deltas).toBe(0);
			}
		}
	});

	it('detects a gain and loss within a category that still has another finding', () => {
		const unchanged = row('example.com', 'spf', 'high', 'Permissive policy');
		const out = computeCycleDiff(
			[unchanged, row('example.com', 'spf', 'low', 'New include issue')],
			[unchanged, row('example.com', 'spf', 'low', 'Old include issue')],
			baseOpts,
		);
		expect(out.totals.deltas).toBe(2);
		expect(out.highlights).toEqual([
			expect.objectContaining({ delta: 'gained', title: 'New include issue', severity: 'low' }),
			expect.objectContaining({ delta: 'lost', title: 'Old include issue', severity: 'low' }),
		]);
	});

	it('attributes a severity transition to its finding within a shared category', () => {
		const unchanged = row('example.com', 'spf', 'high', 'Permissive policy');
		const out = computeCycleDiff(
			[row('example.com', 'spf', 'medium', 'Include issue'), unchanged],
			[unchanged, row('example.com', 'spf', 'low', 'Include issue')],
			baseOpts,
		);
		expect(out.totals.deltas).toBe(1);
		expect(out.highlights[0]).toMatchObject({
			delta: 'severity_changed',
			title: 'Include issue',
			severity: 'medium',
			previous_severity: 'low',
		});
	});

	it('matches duplicate occurrences at equal severity before pairing severity transitions', () => {
		const high = row('example.com', 'spf', 'high', 'Include issue');
		const low = row('example.com', 'spf', 'low', 'Include issue');
		const medium = row('example.com', 'spf', 'medium', 'Include issue');
		const baseline = [high, low, low];
		expect(computeCycleDiff([low, high, low], baseline, baseOpts).totals.deltas).toBe(0);

		const out = computeCycleDiff([medium, low, high], baseline, baseOpts);
		expect(out.totals.deltas).toBe(1);
		expect(out.highlights[0]).toMatchObject({ delta: 'severity_changed', severity: 'medium', previous_severity: 'low' });
		expect(computeCycleDiff([high, low, medium], [...baseline].reverse(), baseOpts)).toEqual(out);
	});

	it('counts gained and lost duplicate occurrences individually', () => {
		const finding = row('example.com', 'spf', 'low', 'Include issue');
		const gained = computeCycleDiff([finding, finding, finding], [finding], baseOpts);
		const lost = computeCycleDiff([finding], [finding, finding, finding], baseOpts);
		expect(gained.totals.deltas).toBe(2);
		expect(gained.highlights.every((entry) => entry.delta === 'gained')).toBe(true);
		expect(lost.totals.deltas).toBe(2);
		expect(lost.highlights.every((entry) => entry.delta === 'lost')).toBe(true);
	});

	it('orders highlights deterministically when findings share domain, category, severity and delta', () => {
		const findings = [row('example.com', 'spf', 'high', 'Zulu issue'), row('example.com', 'spf', 'high', 'Alpha issue')];
		const out = computeCycleDiff(findings, [], baseOpts);
		expect(out.highlights.map((entry) => entry.title)).toEqual(['Alpha issue', 'Zulu issue']);
		expect(computeCycleDiff([...findings].reverse(), [], baseOpts)).toEqual(out);
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
