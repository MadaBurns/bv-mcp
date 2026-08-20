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

	// The check_bimi description is the copy every LLM client reads before
	// choosing the tool. It said the check "Validates … VMC certificate
	// evidence (a=)" — but the a= tag is a bare URL: a Common Mark Certificate
	// (CMC) publishes it identically, and telling the two apart needs a live PKI
	// fetch this check does not perform. Naming the certificate TYPE from a URL
	// is the same defect fixed in the check's own finding prose.
	it('does not claim check_bimi validates a VMC specifically', () => {
		const tool = TOOLS.find((candidate) => candidate.name === 'check_bimi');

		expect(tool).toBeDefined();
		expect(tool!.description).not.toMatch(/VMC certificate evidence/i);
		expect(tool!.description).not.toMatch(/Verified Mark Certificate \(VMC\)(?!\s*or)/i);
		// It must still say WHAT the a= tag is checked for.
		expect(tool!.description).toMatch(/a=/);
		expect(tool!.description).toMatch(/mark certificate|authority evidence/i);
	});

	it('keeps source comments aligned with implemented PDF sidecar behavior', () => {
		expect(brandReportSource).not.toContain('R2 PDF mode lands in Phase 3');
		expect(brandReportSource).not.toContain('inline JSON only');
		expect(brandReportSource).not.toContain('createSignedUrl');
		expect(brandReportSource).toContain('/reports/');
	});
});
