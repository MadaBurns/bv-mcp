// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import brandReportSource from '../../src/tools/brand-audit-get-report.ts?raw';
import { TOOLS } from '../../src/schemas/tool-definitions';

describe('tool description accuracy audit', () => {
	it('describes current brand_audit_get_report PDF behavior', () => {
		const tool = TOOLS.find((candidate) => candidate.name === 'brand_audit_get_report');

		expect(tool).toBeDefined();
		// PDFs are served via the authenticated /reports/ Worker route — the R2
		// binding has no URL-signing API, so "signed PDF URL" was never accurate.
		expect(tool!.description).toContain('pdfUrl');
		expect(tool!.description).toContain('/reports/');
		expect(tool!.description).toContain('pdfPending');
		expect(tool!.description).not.toContain('signed');
		expect(tool!.description).not.toContain('Phase 3');
		expect(tool!.description).not.toContain('inline JSON only');
	});

	it('keeps source comments aligned with implemented PDF sidecar behavior', () => {
		expect(brandReportSource).not.toContain('R2 PDF mode lands in Phase 3');
		expect(brandReportSource).not.toContain('inline JSON only');
		expect(brandReportSource).not.toContain('createSignedUrl');
		expect(brandReportSource).toContain('/reports/');
	});
});
