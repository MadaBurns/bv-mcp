// SPDX-License-Identifier: BUSL-1.1
/**
 * src/lib/pdf-engine.ts
 *
 * Enterprise PDF generation service using Playwright. Test-only — runs in
 * Node via Vitest's `forks` pool (see `poolMatchGlobs` in vitest.config.mts),
 * never in the Cloudflare Worker runtime. The project tsconfig pins
 * `types: ["@cloudflare/workers-types"]` so Node's `Buffer` global isn't
 * visible; the local `declare` below scopes the type to just this file
 * rather than adding `@types/node` to the whole project.
 */

import { chromium } from 'playwright';

// Node-only global; defined at runtime in the Vitest `forks` pool. Typed as
// `Uint8Array` here so consumers see a Web-standard return type.
declare const Buffer: { from(input: ArrayBuffer | Uint8Array): Uint8Array };

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
export async function generatePdf(html: string, options: PdfOptions = {}): Promise<Uint8Array> {
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
