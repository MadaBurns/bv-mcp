/** @vitest-environment node */
import { describe, it, expect } from 'vitest';
import { generatePdf } from '../src/lib/pdf-engine';

describe('PDF Engine (Playwright)', () => {
	it('should generate a valid PDF buffer from HTML', async () => {
		const html = '<h1>Blackveil Test Report</h1><p>This is a test PDF.</p>';
		const buffer = await generatePdf(html);
		
		expect(buffer).toBeDefined();
		expect(buffer.length).toBeGreaterThan(100);
		
		// Check for PDF magic bytes: %PDF-
		const header = buffer.toString('utf-8', 0, 5);
		expect(header).toBe('%PDF-');
	});

	it('should generate a PDF with custom headers and footers', async () => {
		const html = '<h1>Branded Report</h1><div style="height: 1500px;">Long content to force page break</div>';
		const options = {
			displayHeaderFooter: true,
			headerTemplate: '<div style="font-size: 10px; margin-left: 20px;">BLACKVEIL SECURITY</div>',
			footerTemplate: '<div style="font-size: 10px; margin-left: 20px;">Page <span class="pageNumber"></span> of <span class="totalPages"></span></div>',
		};
		const buffer = await generatePdf(html, options);
		
		expect(buffer.length).toBeGreaterThan(100);
		expect(buffer.toString('utf-8', 0, 5)).toBe('%PDF-');
	});
});
