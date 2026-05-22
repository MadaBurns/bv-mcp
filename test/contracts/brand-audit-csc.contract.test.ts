import { describe, it, expect } from 'vitest';
import fastFixture from '../fixtures/csc-complement/ford-com-fast.golden.json';
import fullFixture from '../fixtures/csc-complement/ford-com-full.golden.json';
import { BrandAuditCscSchema, CSC_VIEW_VERSION } from '../../src/schemas/brand-audit-csc';

describe('cscComplement contract', () => {
	it('fast-stage golden fixture parses against current schema', () => {
		const parsed = BrandAuditCscSchema.parse(fastFixture);
		expect(parsed.viewVersion).toBe(CSC_VIEW_VERSION);
		expect(parsed.postureSnapshot.stage).toBe('pending');
		expect(parsed.deepScan.stage).toBe('pending');
	});

	it('full-stage golden fixture parses against current schema', () => {
		const parsed = BrandAuditCscSchema.parse(fullFixture);
		expect(parsed.viewVersion).toBe(CSC_VIEW_VERSION);
		expect(parsed.postureSnapshot.stage).toBe('ready');
		expect(parsed.deepScan.stage).toBe('ready');
		expect(parsed.deepScan.subdomainInventoryByApex['ford.com'].source).toBe('certificate_transparency');
	});

	it('fast fixture .viewVersion === full fixture .viewVersion', () => {
		expect(fastFixture.viewVersion).toBe(fullFixture.viewVersion);
	});
});
