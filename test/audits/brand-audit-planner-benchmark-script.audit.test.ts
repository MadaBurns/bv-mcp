// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import source from '../../scripts/brand-audit-planner-benchmark.mjs?raw';
import summarySource from '../../scripts/brand-audit-planner-benchmark-summary.mjs?raw';

describe('brand-audit planner benchmark script safety', () => {
	it('writes benchmark output only under .reports and takes domains from argv', () => {
		expect(source).toContain('.reports/brand-audit-planner-benchmark');
		expect(source).toContain('process.argv.slice(2)');
		expect(source).toContain('copyFileSync');
		expect(source).toContain('depth.plannerEfficiency');
		expect(source).toContain('candidateSignalProbes');
		expect(source).toContain('writeSnapshot');
		expect(source).not.toMatch(/walmart\.com|bankofamerica\.com|marriott\.com/i);
	});

	it('imports and prints an acceptance summary and serializes per-signal probe counts', () => {
		expect(source).toContain("from './brand-audit-planner-benchmark-summary.mjs'");
		expect(source).toContain('formatAcceptanceSummary');
		expect(source).toContain('summarizeBenchmark');
		expect(source).toContain('wouldProbeBySignal');
		expect(source).toContain('wouldDropBySignal');
		expect(source).toContain('acceptance');
	});

	it('summary helper does not hardcode brand domains and exports the documented surface', () => {
		expect(summarySource).toContain('export function summarizeBenchmark');
		expect(summarySource).toContain('export function formatAcceptanceSummary');
		expect(summarySource).not.toMatch(/walmart\.com|bankofamerica\.com|marriott\.com/i);
	});
});
