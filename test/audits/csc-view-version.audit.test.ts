import { describe, it, expect } from 'vitest';
import { CSC_VIEW_VERSION, BrandAuditCscSchema } from '../../src/schemas/brand-audit-csc';

describe('AUDIT: BrandAuditCscSchema viewVersion', () => {
	it('exports CSC_VIEW_VERSION as a numeric literal', () => {
		expect(typeof CSC_VIEW_VERSION).toBe('number');
		expect(Number.isInteger(CSC_VIEW_VERSION)).toBe(true);
		expect(CSC_VIEW_VERSION).toBeGreaterThan(0);
	});

	it('viewVersion in schema is a literal that matches CSC_VIEW_VERSION', () => {
		const minimalFixture = {
			viewVersion: CSC_VIEW_VERSION,
			anchor: { apex: 'a.com', primaryRegistrar: { family: null, name: null, ianaId: null }, managedByCsc: false },
			registrarPortfolio: { totalApexes: 1, byFamily: [], offPortfolioCount: 0, offPortfolioApexes: [] },
			shadowItHighlights: [],
			defensiveRegistrations: { count: 0, examples: [], enrichmentStatus: 'sparse' as const },
			postureSnapshot: { stage: 'pending' as const, apexesScanned: 0, apexesTotal: 0, apexes: [], medianGrade: null, distribution: {} },
			deepScan: { stage: 'pending' as const, apexesScanned: 0, apexesTotal: 0, danglingDns: [], danglingDnsTotal: 0, subdomainInventoryByApex: {} },
			generatedAt: '2026-01-01T00:00:00Z',
			reportId: 'csc_rpt_x',
		};
		expect(() => BrandAuditCscSchema.parse(minimalFixture)).not.toThrow();
		expect(() => BrandAuditCscSchema.parse({ ...minimalFixture, viewVersion: CSC_VIEW_VERSION + 1 })).toThrow();
	});
});
