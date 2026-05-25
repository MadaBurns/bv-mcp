// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import brandReportSource from '../../src/tools/brand-audit-get-report.ts?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('tool description accuracy audit', () => {
	it('describes current brand_audit_get_report PDF behavior', () => {
		const tool = TOOLS.find((candidate) => candidate.name === 'brand_audit_get_report');

		expect(tool).toBeDefined();
		expect(tool!.description).toContain('signed PDF URL');
		expect(tool!.description).toContain('pdfPending');
		expect(tool!.description).not.toContain('Phase 3');
		expect(tool!.description).not.toContain('inline JSON only');
	});

	it('keeps source comments aligned with implemented PDF sidecar behavior', () => {
		expect(brandReportSource).not.toContain('R2 PDF mode lands in Phase 3');
		expect(brandReportSource).not.toContain('inline JSON only');
		expect(brandReportSource).toContain('signed PDF URL');
	});
});
