// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect, vi } from 'vitest';
import { BrandAuditCscSchema, CSC_VIEW_VERSION } from '../src/schemas/brand-audit-csc';
import { buildCscComplement } from '../src/lib/brand-audit-csc-builder';

function validFixture() {
	return {
		viewVersion: 1,
		anchor: {
			apex: 'brand-beta.com',
			primaryRegistrar: { family: 'csc corporate domains', name: 'CSC Corporate Domains, Inc.', ianaId: '299' },
			managedByCsc: true,
		},
		registrarPortfolio: {
			totalApexes: 4,
			byFamily: [
				{ family: 'csc corporate domains', count: 3, percent: 75, exampleApexes: ['brand-beta.com', 'brand-beta.com.au'] },
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
		reportId: 'csc_rpt_abc123',
	};
}

describe('BrandAuditCscSchema', () => {
	it('builds report identifiers with cryptographic randomness', async () => {
		const insecureRandom = vi.spyOn(Math, 'random').mockImplementation(() => {
			throw new Error('Math.random must not mint report identifiers');
		});
		try {
			const report = await buildCscComplement({
				seedDomain: 'example.com',
				primaryRegistrar: '',
				primaryRegistrarSource: 'unknown',
				primaryRegistrarIanaId: null,
				classifiedFindings: [],
				now: () => 1_700_000_000_000,
			});

			expect(report.reportId).toMatch(/^csc_rpt_[a-z0-9]+$/);
			expect(report.reportId.length).toBeGreaterThanOrEqual(32);
		} finally {
			insecureRandom.mockRestore();
		}
	});

	it('exports CSC_VIEW_VERSION === 1', () => {
		expect(CSC_VIEW_VERSION).toBe(1);
	});

	it('accepts a valid v1 fixture', () => {
		const parsed = BrandAuditCscSchema.parse(validFixture());
		expect(parsed.viewVersion).toBe(1);
		expect(parsed.anchor.managedByCsc).toBe(true);
	});

	it('rejects a fixture with viewVersion !== 1', () => {
		const bad = { ...validFixture(), viewVersion: 2 };
		expect(() => BrandAuditCscSchema.parse(bad)).toThrow();
	});

	it('rejects a fixture missing anchor', () => {
		const fixture = validFixture() as Partial<ReturnType<typeof validFixture>>;
		delete fixture.anchor;
		expect(() => BrandAuditCscSchema.parse(fixture)).toThrow();
	});

	it('rejects deepScan.subdomainInventoryByApex entries missing source', () => {
		const fixture = validFixture();
		fixture.deepScan.subdomainInventoryByApex = {
			'brand-beta.com': { total: 100, dangling: 0, sample: [], partial: false } as never,
		};
		expect(() => BrandAuditCscSchema.parse(fixture)).toThrow();
	});

	it('enforces enrichmentStatus enum', () => {
		const fixture = validFixture();
		fixture.defensiveRegistrations.enrichmentStatus = 'invalid' as never;
		expect(() => BrandAuditCscSchema.parse(fixture)).toThrow();
	});
});
