import { describe, it, expect } from 'vitest';
import { REGISTRAR_VIEW_VERSION, BrandAuditRegistrarSchema } from '../../src/schemas/brand-audit-registrar';

describe('AUDIT: BrandAuditRegistrarSchema viewVersion', () => {
	it('exports REGISTRAR_VIEW_VERSION as a numeric literal', () => {
		expect(typeof REGISTRAR_VIEW_VERSION).toBe('number');
		expect(Number.isInteger(REGISTRAR_VIEW_VERSION)).toBe(true);
		expect(REGISTRAR_VIEW_VERSION).toBeGreaterThan(0);
	});

	it('viewVersion in schema is a literal that matches REGISTRAR_VIEW_VERSION', () => {
		const minimalFixture = {
			viewVersion: REGISTRAR_VIEW_VERSION,
			anchor: { apex: 'a.com', primaryRegistrar: { family: null, name: null, ianaId: null }, managedByRegistrar: false },
			registrarPortfolio: { totalApexes: 1, byFamily: [], offPortfolioCount: 0, offPortfolioApexes: [] },
			shadowItHighlights: [],
			defensiveRegistrations: { count: 0, examples: [], enrichmentStatus: 'sparse' as const },
			postureSnapshot: { stage: 'pending' as const, apexesScanned: 0, apexesTotal: 0, apexes: [], medianGrade: null, distribution: {} },
			deepScan: { stage: 'pending' as const, apexesScanned: 0, apexesTotal: 0, danglingDns: [], danglingDnsTotal: 0, subdomainInventoryByApex: {} },
			generatedAt: '2026-01-01T00:00:00Z',
			reportId: 'reg_rpt_x',
		};
		expect(() => BrandAuditRegistrarSchema.parse(minimalFixture)).not.toThrow();
		expect(() => BrandAuditRegistrarSchema.parse({ ...minimalFixture, viewVersion: REGISTRAR_VIEW_VERSION + 1 })).toThrow();
	});
});
