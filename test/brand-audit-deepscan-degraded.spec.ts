// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-290 item 4 — registrar deep-scan degradation.
 *
 *   (a) when EVERY internal call fails, the deep scan must not publish a
 *       confident `stage: 'ready'` / `danglingDnsTotal: 0` payload that
 *       `brand_audit_get_report` would then prefer over the fast payload;
 *   (b) takeover results (and the subdomain inventory) of an apex whose
 *       `scan_domain` failed are carried independently, not dropped;
 *   (c) `medianGrade` ranks grade letters, it does not sort them as strings
 *       (`['A+', 'A', 'B']` sorts lexically to `A, A+, B`, so the "median" was A+).
 *
 * Envelopes carry their payload in `structuredContent`, the only
 * machine-readable channel `handleToolsCall` emits (see
 * brand-audit-registrar-deepscan.spec.ts for the production-builder pinning).
 */

import { describe, it, expect } from 'vitest';
import type { BrandAuditStepStore } from '../src/lib/brand-audit-step-store';

type Call = (tool: string, args: { domain: string }) => Promise<unknown>;

const scanEnvelope = (domain: string, grade: string, score = 80) => ({
	content: [],
	structuredContent: { domain, score, grade, measured: true, categoryScores: {} },
});

const discoverEnvelope = (domain: string) => ({
	content: [],
	structuredContent: { domain, totalSubdomains: 1, subdomains: [{ subdomain: `www.${domain}` }] },
});

const danglingEnvelope = (domain: string) => ({
	content: [],
	structuredContent: {
		category: 'subdomain_takeover',
		findings: [
			{
				category: 'subdomain_takeover',
				title: `Dangling CNAME: www.${domain} → gone.herokuapp.com`,
				severity: 'high',
				detail: `Subdomain www.${domain} points to gone.herokuapp.com, which does not resolve.`,
			},
		],
	},
});

describe('runDeepScan — item 4(a): total failure is not published as a confident ready payload', () => {
	const allFail: Call = async () => {
		throw new Error('internal call failed');
	};
	const allIsError: Call = async () => ({ content: [{ type: 'text', text: 'Error: boom' }], isError: true });

	it('rejects when every internal call for every apex fails (thrown)', async () => {
		const { runDeepScan } = await import('../src/lib/brand-audit-registrar-deepscan');
		await expect(runDeepScan({ anchorApex: 'a.com', apexes: ['a.com', 'b.com'], internalCall: allFail })).rejects.toThrow(
			/every internal call failed/i,
		);
	});

	it('rejects when every internal call returns isError', async () => {
		const { runDeepScan } = await import('../src/lib/brand-audit-registrar-deepscan');
		await expect(runDeepScan({ anchorApex: 'a.com', apexes: ['a.com'], internalCall: allIsError })).rejects.toThrow(
			/every internal call failed/i,
		);
	});

	it('does not reject when at least one call produced data (partial stays partial)', async () => {
		const { runDeepScan } = await import('../src/lib/brand-audit-registrar-deepscan');
		const onlyDiscover: Call = async (tool, { domain }) => {
			if (tool === 'discover_subdomains') return discoverEnvelope(domain);
			throw new Error('down');
		};
		const result = await runDeepScan({ anchorApex: 'a.com', apexes: ['a.com'], internalCall: onlyDiscover });
		expect(result.postureSnapshot.apexesScanned).toBe(0);
		expect(result.deepScan.subdomainInventoryByApex['a.com']).toBeDefined();
	});

	it('the job wrapper writes no registrar_complement_full step on total failure, so get_report keeps the fast payload', async () => {
		const { runDeepScanFromStepStore } = await import('../src/lib/brand-audit-registrar-deepscan-job');
		const puts: unknown[] = [];
		const fast = {
			viewVersion: 2,
			anchor: { apex: 'a.com', primaryRegistrar: null, managedByRegistrar: true },
			registrarPortfolio: { totalApexes: 1, byFamily: [], offPortfolioCount: 0, offPortfolioApexes: [] },
			shadowItHighlights: [],
			defensiveRegistrations: { count: 0, examples: [], enrichmentStatus: 'ready' },
			postureSnapshot: { stage: 'pending', apexesScanned: 0, apexesTotal: 0, apexes: [], medianGrade: null, distribution: {} },
			deepScan: { stage: 'pending', apexesScanned: 0, apexesTotal: 0, danglingDns: [], danglingDnsTotal: 0, subdomainInventoryByApex: {} },
			generatedAt: '2026-05-22T00:00:00Z',
			reportId: 'reg_rpt_test',
		};
		const stepStore = {
			get: async (_a: string, _t: string, step: string) =>
				step === 'registrar_complement_fast' ? { status: 'completed', payload: fast } : null,
			put: async (row: unknown) => {
				puts.push(row);
			},
		} as unknown as BrandAuditStepStore;

		await expect(runDeepScanFromStepStore({ auditId: 'aud-1', target: 'a.com', stepStore, internalCall: allFail })).rejects.toThrow();
		expect(puts).toEqual([]);
	});
});

describe('runDeepScan — item 4(b): takeover results survive a failed scan_domain', () => {
	it('carries dangling DNS and the subdomain inventory for an apex whose scan_domain failed', async () => {
		const { runDeepScan } = await import('../src/lib/brand-audit-registrar-deepscan');
		const internalCall: Call = async (tool, { domain }) => {
			if (tool === 'scan_domain') {
				if (domain === 'broken.com') throw new Error('scan_domain failed');
				return scanEnvelope(domain, 'B');
			}
			if (tool === 'discover_subdomains') return discoverEnvelope(domain);
			return danglingEnvelope(domain);
		};
		const result = await runDeepScan({ anchorApex: 'ok.com', apexes: ['ok.com', 'broken.com'], internalCall });

		// Posture stays partial: the failed apex has no posture row.
		expect(result.postureSnapshot.apexesScanned).toBe(1);
		expect(result.postureSnapshot.apexes.map((a) => a.apex)).toEqual(['ok.com']);
		// ...but its takeover finding and inventory are NOT dropped.
		expect(result.deepScan.danglingDns.map((d) => d.apex).sort()).toEqual(['broken.com', 'ok.com']);
		expect(result.deepScan.danglingDnsTotal).toBe(2);
		expect(result.deepScan.subdomainInventoryByApex['broken.com']).toBeDefined();
	});
});

describe('runDeepScan — item 4(c): medianGrade ranks grades', () => {
	async function medianFor(grades: string[]) {
		const { runDeepScan } = await import('../src/lib/brand-audit-registrar-deepscan');
		const apexes = grades.map((_, i) => `apex${i}.com`);
		const internalCall: Call = async (tool, { domain }) => {
			if (tool === 'scan_domain') return scanEnvelope(domain, grades[apexes.indexOf(domain)]);
			if (tool === 'discover_subdomains') return discoverEnvelope(domain);
			return { content: [], structuredContent: { category: 'subdomain_takeover', findings: [] } };
		};
		const result = await runDeepScan({ anchorApex: apexes[0], apexes, internalCall });
		return result.postureSnapshot.medianGrade;
	}

	it("['A+', 'A', 'B'] → 'A' (lexical sort yields 'A+')", async () => {
		expect(await medianFor(['A+', 'A', 'B'])).toBe('A');
	});

	it('is independent of apex order', async () => {
		expect(await medianFor(['B', 'A+', 'A'])).toBe('A');
	});

	it("['C+', 'C', 'D'] → 'C' (lexical sort yields 'C+')", async () => {
		expect(await medianFor(['C+', 'C', 'D'])).toBe('C');
	});

	it('single grade is its own median', async () => {
		expect(await medianFor(['B'])).toBe('B');
	});
});
