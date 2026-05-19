// SPDX-License-Identifier: BUSL-1.1

/**
 * Phase 1 of registrar-coverage-tdd-plan.md — `safeRegistrarLookup` (private
 * helper inside brand-audit-pipeline.ts) must distinguish transient failures
 * from deterministic 'unknown'. We test the observable surface: the summary
 * finding's `targetRegistrarSource` / `targetRegistrarFailureReason` when the
 * injected `checkRdapLookup` throws.
 */

import { describe, expect, it, vi } from 'vitest';
import type { CheckResult, Finding } from '../src/lib/scoring';
import { runBrandAuditPipeline } from '../src/lib/brand-audit-pipeline';

function summaryFinding(seedDomain: string, surfaced: number): Finding {
	return {
		category: 'brand_discovery',
		title: `Brand-domain discovery: ${surfaced} candidate(s) at confidence ≥ 0.5`,
		severity: 'info',
		detail: `Seed=${seedDomain}`,
		metadata: { summary: true, signals: ['ns'], signalStatus: {}, minConfidence: 0.5, totalAggregated: surfaced, surfaced },
	};
}

function candidateFinding(domain: string): Finding {
	return {
		category: 'brand_discovery',
		title: `Discovered candidate: ${domain}`,
		severity: 'low',
		detail: 'Found via ns; combined confidence 0.95.',
		metadata: { candidate: domain, signals: ['ns'], combinedConfidence: 0.95, sources: {} },
	};
}

function discoveryResult(seedDomain: string, candidates: string[]): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [summaryFinding(seedDomain, candidates.length), ...candidates.map(candidateFinding)],
	};
}

describe('runBrandAuditPipeline — safeRegistrarLookup transient-failure handling', () => {
	it('tags target as lookup_failed when injected checkRdapLookup throws', async () => {
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', []));
		const checkRdapLookup = vi.fn(async () => {
			throw new TypeError('upstream RDAP down');
		});

		const result = await runBrandAuditPipeline(
			'example.com',
			{},
			{ discoverBrandDomains, checkRdapLookup },
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.targetRegistrarSource).toBe('lookup_failed');
		expect(typeof summary?.metadata?.targetRegistrarFailureReason).toBe('string');
		expect(summary!.metadata!.targetRegistrarFailureReason).toBe('exception');
	});

	it('emits registrarEnrichmentStatus=needs_retry on candidates whose lookup throws transiently', async () => {
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', ['flaky.net']));
		const checkRdapLookup = vi.fn(async (domain: string) => {
			if (domain === 'flaky.net') throw new Error('upstream flap');
			return { category: 'rdap', score: 100, findings: [] } as CheckResult;
		});

		const result = await runBrandAuditPipeline(
			'example.com',
			{},
			{ discoverBrandDomains, checkRdapLookup },
		);
		const candidate = result.findings.find((f) => f.metadata?.candidate === 'flaky.net');
		expect(candidate?.metadata?.registrarSource).toBe('lookup_failed');
		expect(candidate?.metadata?.registrarEnrichmentStatus).toBe('needs_retry');
		expect(candidate?.metadata?.registrarFailureReason).toBe('exception');
	});

	it('preserves unknown (not lookup_failed) when rdap returns 0 findings cleanly', async () => {
		const discoverBrandDomains = vi.fn().mockResolvedValue(discoveryResult('example.com', []));
		const checkRdapLookup = vi.fn(async () => ({
			category: 'rdap',
			score: 100,
			findings: [],
		}) as CheckResult);

		const result = await runBrandAuditPipeline(
			'example.com',
			{},
			{ discoverBrandDomains, checkRdapLookup },
		);
		const summary = result.findings.find((f) => f.metadata?.summary === true);
		expect(summary?.metadata?.targetRegistrarSource).toBe('unknown');
		expect(summary?.metadata?.targetRegistrarFailureReason).toBeUndefined();
	});
});
