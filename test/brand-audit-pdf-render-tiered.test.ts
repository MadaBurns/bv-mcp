// SPDX-License-Identifier: BUSL-1.1

/**
 * Tiered-mode "Owned Portfolio" section of the pdf-lib brand-audit renderer.
 *
 * Drives `drawOwnedPortfolio` -> `drawSubsectionHeader` / `drawSubsectionRows` and the
 * tier-3 / shadowIt / indeterminate filter predicates through the exported
 * `renderBrandAuditPdf`, with a fixture that has subsection rows in several tiers and a
 * subsection (tier 1) that is deliberately empty.
 */

import { describe, it, expect } from 'vitest';
import { PDFDocument, PDFName, PDFRawStream } from 'pdf-lib';
import type { CheckResult } from '../src/lib/scoring';
import type { Finding } from '../src/lib/scoring';

/** Concatenate every drawn text string (hex-encoded Tj operands) from all page content streams. */
async function extractText(bytes: Uint8Array): Promise<string> {
	const doc = await PDFDocument.load(bytes);
	let out = '';
	for (const [, obj] of doc.context.enumerateIndirectObjects()) {
		if (!(obj instanceof PDFRawStream)) continue;
		const filter = obj.dict.get(PDFName.of('Filter'));
		let data: Uint8Array = obj.contents;
		if (filter && String(filter) === '/FlateDecode') {
			const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream('deflate'));
			data = new Uint8Array(await new Response(stream).arrayBuffer());
		}
		const src = new TextDecoder('latin1').decode(data);
		for (const m of src.matchAll(/<([0-9A-Fa-f]+)>\s*Tj/g)) {
			let s = '';
			for (let i = 0; i < m[1].length; i += 2) s += String.fromCharCode(parseInt(m[1].slice(i, i + 2), 16));
			out += s + '\n';
		}
	}
	return out;
}

function candidate(domain: string, metadata: Record<string, unknown>): Finding {
	return {
		category: 'brand_discovery',
		title: domain,
		severity: 'info',
		detail: '',
		metadata: { candidate: domain, registrar: 'Example Registrar', registrarSource: 'rdap', reasons: [], signals: [], combinedConfidence: 0.8, ...metadata },
	};
}

function tieredResult(): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		passed: true,
		findings: [
			{
				category: 'brand_discovery',
				title: 'Brand audit summary',
				severity: 'info',
				detail: '',
				metadata: { summary: true, target: 'example.com', discoveryMode: 'tiered' },
			},
			// tier 0 -> "Tenant-declared"
			candidate('tier0-declared.example', { bucket: 'consolidated', tier: 0 }),
			// tier 2 -> "Declared evidence"
			candidate('tier2-evidence.example', { bucket: 'consolidated', tier: 2 }),
			// tier undefined consolidated -> falls into inferred (tier 3)
			candidate('tier-undefined.example', { bucket: 'consolidated' }),
			// explicit tier 3 consolidated -> inferred
			candidate('tier3-inferred.example', { bucket: 'consolidated', tier: 3 }),
			// shadowIt defaults to owned_off_primary_registrar -> inferred
			candidate('shadow-owned.example', { bucket: 'shadowIt' }),
			// shadowIt that is NOT owned_off_primary_registrar -> excluded by the predicate
			candidate('shadow-manual.example', { bucket: 'shadowIt', relationshipType: 'manual_review' }),
			// indeterminate (non-vendor) -> inferred
			candidate('indeterminate-open.example', { bucket: 'indeterminate' }),
			// indeterminate vendor dependency -> excluded from owned portfolio
			candidate('indeterminate-vendor.example', { bucket: 'indeterminate', relationshipType: 'authorized_vendor_dependency' }),
		],
	};
}

describe('renderBrandAuditPdf tiered Owned Portfolio', () => {
	it('draws a header and rows for every populated tier, and an empty marker for the empty tier', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		const bytes = await renderBrandAuditPdf(tieredResult(), 'example.com', {
			serverVersion: '3.99.0',
			now: () => new Date('2026-10-19T00:00:00Z').getTime(),
		});

		const parsed = await PDFDocument.load(bytes);
		expect(parsed.getPageCount()).toBeGreaterThan(0);

		const text = await extractText(bytes);
		// drawSubsectionHeader: titles + singular/plural candidate counts.
		expect(text).toContain('Tenant-declared (tier 0)');
		expect(text).toContain('Graph-surfaced (tier 1)');
		expect(text).toContain('Declared evidence (tier 2)');
		expect(text).toContain('Inferred (tier 3)');
		expect(text).toContain('1 candidate');
		expect(text).toContain('0 candidates');
		// Tier 3 bucket: undefined-tier consolidated + tier 3 + owned shadowIt + non-vendor indeterminate = 4.
		expect(text).toContain('4 candidates');
		// drawSubsectionRows: empty subsection (tier 1) -> empty marker; populated -> candidate rows.
		expect(text).toContain('No candidates in this tier.');
		for (const d of [
			'tier0-declared.example',
			'tier2-evidence.example',
			'tier-undefined.example',
			'tier3-inferred.example',
			'shadow-owned.example',
			'indeterminate-open.example',
		]) {
			expect(text, `missing ${d}`).toContain(d);
		}
		// Filter predicates: the non-owned shadowIt row and the vendor-dependency indeterminate row are
		// excluded from the tier-3 count above (4, not 6) and from the Owned Portfolio header total (6, not 8).
		expect(text).toContain('6 candidates');
	});
});
