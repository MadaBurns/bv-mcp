// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { BrandAuditRegistrarSchema, REGISTRAR_VIEW_VERSION } from '../src/schemas/brand-audit-registrar';
import { buildRegistrarComplement } from '../src/lib/brand-audit-registrar-builder';

function validFixture() {
	return {
		viewVersion: 2,
		anchor: {
			apex: 'brand-beta.com',
			primaryRegistrar: { family: 'corporate domains registrar', name: 'Brand Registrar, Inc.', ianaId: '299' },
			managedByRegistrar: true,
		},
		registrarPortfolio: {
			totalApexes: 4,
			byFamily: [
				{ family: 'corporate domains registrar', count: 3, percent: 75, exampleApexes: ['brand-beta.com', 'brand-beta.com.au'] },
				{ family: 'godaddy', count: 1, percent: 25, exampleApexes: ['fordcorp.com'] },
			],
			offPortfolioCount: 1,
			offPortfolioApexes: ['fordcorp.com'],
		},
		shadowItHighlights: [],
		defensiveRegistrations: { count: 0, examples: [], enrichmentStatus: 'sparse' as const },
		postureSnapshot: {
			stage: 'pending' as const,
			apexesScanned: 0,
			apexesTotal: 0,
			apexes: [],
			medianGrade: null,
			distribution: {},
		},
		deepScan: {
			stage: 'pending' as const,
			apexesScanned: 0,
			apexesTotal: 0,
			danglingDns: [],
			danglingDnsTotal: 0,
			subdomainInventoryByApex: {},
		},
		generatedAt: '2026-05-22T14:32:00Z',
		reportId: 'reg_rpt_abc123',
	};
}

describe('BrandAuditRegistrarSchema', () => {
	it('builds report identifiers with cryptographic randomness', async () => {
		const insecureRandom = vi.spyOn(Math, 'random').mockImplementation(() => {
			throw new Error('Math.random must not mint report identifiers');
		});
		try {
			const report = await buildRegistrarComplement({
				seedDomain: 'example.com',
				primaryRegistrar: '',
				primaryRegistrarSource: 'unknown',
				primaryRegistrarIanaId: null,
				classifiedFindings: [],
				now: () => 1_700_000_000_000,
			});

			expect(report.reportId).toMatch(/^reg_rpt_[a-z0-9]+$/);
			expect(report.reportId.length).toBeGreaterThanOrEqual(32);
		} finally {
			insecureRandom.mockRestore();
		}
	});

	it('exports REGISTRAR_VIEW_VERSION === 2', () => {
		expect(REGISTRAR_VIEW_VERSION).toBe(2);
	});

	it('accepts a valid v2 fixture', () => {
		const parsed = BrandAuditRegistrarSchema.parse(validFixture());
		expect(parsed.viewVersion).toBe(2);
		expect(parsed.anchor.managedByRegistrar).toBe(true);
	});

	it('rejects a fixture with viewVersion !== 2', () => {
		const bad = { ...validFixture(), viewVersion: 1 };
		expect(() => BrandAuditRegistrarSchema.parse(bad)).toThrow();
	});

	it('accepts report identifiers minted under a legacy prefix (prefix-agnostic regex)', () => {
		const legacy = { ...validFixture(), reportId: 'legacy_rpt_abc123' };
		expect(BrandAuditRegistrarSchema.parse(legacy).reportId).toBe('legacy_rpt_abc123');
		const malformed = { ...validFixture(), reportId: 'rpt_abc123' };
		expect(() => BrandAuditRegistrarSchema.parse(malformed)).toThrow();
	});

	it('rejects a fixture missing anchor', () => {
		const fixture = validFixture() as Partial<ReturnType<typeof validFixture>>;
		delete fixture.anchor;
		expect(() => BrandAuditRegistrarSchema.parse(fixture)).toThrow();
	});

	it('rejects deepScan.subdomainInventoryByApex entries missing source', () => {
		const fixture = validFixture();
		fixture.deepScan.subdomainInventoryByApex = {
			'brand-beta.com': { total: 100, dangling: 0, sample: [], partial: false } as never,
		};
		expect(() => BrandAuditRegistrarSchema.parse(fixture)).toThrow();
	});

	it('enforces enrichmentStatus enum', () => {
		const fixture = validFixture();
		fixture.defensiveRegistrations.enrichmentStatus = 'invalid' as never;
		expect(() => BrandAuditRegistrarSchema.parse(fixture)).toThrow();
	});
});
