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
		expect(source).toContain('qaSchemaVersion !== 1 && qaSchemaVersion !== 2');
		expect(source).toContain('qaSchemaVersion >= 2');
		expect(source).toContain('missing performance');
		expect(source).toContain('missing performance.stepStatusCounts');
		expect(source).toContain('missing performance.steps');
	});
});
