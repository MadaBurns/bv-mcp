// SPDX-License-Identifier: BUSL-1.1
/**
 * src/lib/pdf-engine.ts
 * 
 * Enterprise PDF generation service using Playwright.
 */

import { chromium } from 'playwright';

export interface PdfOptions {
	format?: 'A4' | 'Letter';
	printBackground?: boolean;
	margin?: {
		top?: string;
		right?: string;
		bottom?: string;
		left?: string;
	};
	displayHeaderFooter?: boolean;
	headerTemplate?: string;
	footerTemplate?: string;
}

/**
 * Generate a PDF buffer from an HTML string.
 */
export async function generatePdf(html: string, options: PdfOptions = {}): Promise<Buffer> {
	const browser = await chromium.launch({ headless: true });
	try {
		const context = await browser.newContext();
		const page = await context.newPage();
		
		await page.setContent(html, { waitUntil: 'networkidle' });
		
		const pdf = await page.pdf({
			format: options.format ?? 'A4',
			printBackground: options.printBackground ?? true,
			margin: options.margin ?? {
				top: '20mm',
				right: '20mm',
				bottom: '20mm',
				left: '20mm',
			},
			displayHeaderFooter: options.displayHeaderFooter ?? false,
			headerTemplate: options.headerTemplate ?? ' ',
			footerTemplate: options.footerTemplate ?? ' ',
		});
		
		return Buffer.from(pdf);
	} finally {
		await browser.close();
	}
}
