// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import source from '../../scripts/audits/brand-report-qa.mjs?raw';

describe('brand report QA script safety', () => {
	it('accepts domains from argv and validates JSON/PDF report pairs without hard-coded real brands', () => {
		expect(source).toContain('process.argv.slice(2)');
		expect(source).not.toMatch(/amazon\.com|apple\.com|disney\.com|google\.com|microsoft\.com|paypal\.com|stripe\.com|walmart\.com|nike\.com|github\.com/i);
		expect(source).toContain('auditId');
		expect(source).toContain('generatedAt');
		expect(source).toContain('dataQuality');
		expect(source).toContain('pdfinfo');
		expect(source).toContain('depthMode');
	});

	it('requires performance metadata for qa schema v2 and newer sidecars', () => {
		expect(source).toContain('const qaSchemaVersion = sidecar.qaSchemaVersion');
		expect(source).toContain('qaSchemaVersion !== 1 && qaSchemaVersion !== 2 && qaSchemaVersion !== 3 && qaSchemaVersion !== 4');
		expect(source).toContain('qaSchemaVersion >= 2');
		expect(source).toContain('missing performance');
		expect(source).toContain('missing performance.stepStatusCounts');
		expect(source).toContain('missing performance.steps');
	});

	it('requires the tiered owned-portfolio + relationship split for qa schema v3/v4 sidecars', () => {
		expect(source).toContain('qaSchemaVersion === 3 || qaSchemaVersion === 4');
		expect(source).toContain('missing ownedPortfolio');
		expect(source).toContain('missing ownedPortfolio.tenantDeclared');
		expect(source).toContain('missing ownedPortfolio.graphSurfaced');
		expect(source).toContain('missing ownedPortfolio.declaredEvidence');
		expect(source).toContain('missing ownedPortfolio.inferred');
		expect(source).toContain('missing ownedPortfolio.inferred.consolidated');
		expect(source).toContain('missing ownedPortfolio.inferred.shadowIt');
		expect(source).toContain('missing ownedPortfolio.inferred.indeterminate');
		expect(source).toContain('missing impersonationSurface');
		expect(source).toContain('missing performance.tiers');
		expect(source).toContain('missing relationshipSchemaVersion');
		expect(source).toContain('missing registrarSprawl');
		expect(source).toContain('missing vendorDependencies');
	});
});
