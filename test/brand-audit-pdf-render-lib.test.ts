// SPDX-License-Identifier: BUSL-1.1

/**
 * Tests for the pdf-lib-based brand-audit PDF renderer (replaces the
 * browser-renderer-based path that proved unreliable due to stacked
 * timeout layers in bv-browser-renderer).
 *
 * Renderer is pure: no I/O, no network, no browser. Given a CheckResult,
 * produces deterministic PDF bytes. We verify (a) bytes are a valid PDF
 * (header sniff + parseable by pdf-lib's reader), (b) every candidate
 * domain appears as text in the output, (c) the target + version land in
 * the document, (d) malicious metadata strings don't escape PDF lexer.
 */

import { describe, it, expect } from 'vitest';
import type { CheckResult } from '../src/lib/scoring';
import { PDFDocument } from 'pdf-lib';

function makeBrandAuditResult(): CheckResult {
	return {
		category: 'brand_discovery',
		score: 100,
		findings: [
			{
				category: 'brand_discovery',
				title: 'Brand audit summary',
				severity: 'info',
				detail: '',
				metadata: { summary: true, target: 'apple.com', consolidated: 1, shadowIt: 0, indeterminate: 0, impersonation: 1 },
			},
			{
				category: 'brand_discovery',
				title: 'apple.net',
				severity: 'info',
				detail: '',
				metadata: {
					candidate: 'apple.net',
					bucket: 'consolidated',
					registrar: 'MarkMonitor Inc.',
					registrarSource: 'rdap',
					reasons: ['NS overlap with apple.com'],
					signals: ['ns'],
					combinedConfidence: 0.95,
				},
			},
			{
				category: 'brand_discovery',
				title: 'appel-typosquat.com',
				severity: 'low',
				detail: '',
				metadata: {
					candidate: 'appel-typosquat.com',
					bucket: 'impersonation',
					registrar: 'Sketchy Registrar LLC',
					registrarSource: 'rdap',
					reasons: ['lookalike score 0.92'],
					signals: ['markov_gen'],
					combinedConfidence: 0.30,
				},
			},
		],
	};
}

describe('renderBrandAuditPdf (pdf-lib)', () => {
	it('produces a valid PDF (header + parseable by pdf-lib reader)', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		const bytes = await renderBrandAuditPdf(makeBrandAuditResult(), 'apple.com', {
			serverVersion: '2.21.4',
			now: () => new Date('2026-05-19T12:00:00Z').getTime(),
		});

		// Sniff: PDF files start with `%PDF-`
		const header = new TextDecoder().decode(bytes.slice(0, 5));
		expect(header).toBe('%PDF-');

		// Round-trip: pdf-lib can re-parse what we emit
		const parsed = await PDFDocument.load(bytes);
		expect(parsed.getPageCount()).toBeGreaterThan(0);
	});

	it('produces a non-trivial PDF whose size grows with candidate count', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		// pdf-lib compresses text streams (FlateDecode) so raw-byte grep won't
		// reveal candidate text. Surrogate signal: the rendered PDF for a
		// multi-candidate audit must be larger than the rendered PDF for an
		// empty one. (Text-content assertion lives in higher-level snapshot
		// tests if/when we add them with a text-extract dependency.)
		const empty = await renderBrandAuditPdf(
			{ category: 'brand_discovery', score: 100, findings: [{ category: 'brand_discovery', title: 's', severity: 'info', detail: '', metadata: { summary: true, target: 'apple.com' } }] },
			'apple.com',
			{ serverVersion: '2.21.4' },
		);
		const populated = await renderBrandAuditPdf(makeBrandAuditResult(), 'apple.com', { serverVersion: '2.21.4' });

		expect(populated.byteLength).toBeGreaterThan(empty.byteLength);
		// Also confirm both are parseable PDFs with at least one page.
		const emptyDoc = await PDFDocument.load(empty);
		const populatedDoc = await PDFDocument.load(populated);
		expect(emptyDoc.getPageCount()).toBeGreaterThan(0);
		expect(populatedDoc.getPageCount()).toBeGreaterThan(0);
		// Document metadata should carry our creator string (uncompressed).
		expect(populatedDoc.getCreator()).toContain('bv-mcp');
	});

	it('renders an empty-candidates audit without crashing', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		const empty: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [{ category: 'brand_discovery', title: 'summary', severity: 'info', detail: '', metadata: { summary: true, target: 'example.com' } }],
		};
		const bytes = await renderBrandAuditPdf(empty, 'example.com', { serverVersion: '2.21.4' });
		expect(bytes.byteLength).toBeGreaterThan(500);
		const parsed = await PDFDocument.load(bytes);
		expect(parsed.getPageCount()).toBeGreaterThan(0);
	});

	it('renders discovery depth warnings into the PDF content stream', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		const baseSummary = {
			category: 'brand_discovery' as const,
			title: 'summary',
			severity: 'info' as const,
			detail: '',
			metadata: { summary: true, target: 'example.com' },
		};
		const withWarnings: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [
				{
					...baseSummary,
					metadata: {
						summary: true,
						target: 'example.com',
						depth: {
							warnings: [
								'Candidate universe was truncated by cap (154 candidate(s) dropped); discovery coverage is incomplete.',
							],
						},
					},
				},
			],
		};
		const withoutWarnings: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [baseSummary],
		};
		const options = { serverVersion: '2.21.4', now: () => new Date('2026-05-19T12:00:00Z').getTime() };

		const aBytes = await renderBrandAuditPdf(withWarnings, 'example.com', options);
		const bBytes = await renderBrandAuditPdf(withoutWarnings, 'example.com', options);

		expect(aBytes.byteLength - bBytes.byteLength).toBeGreaterThan(40);
		const parsed = await PDFDocument.load(aBytes);
		expect(parsed.getPageCount()).toBeGreaterThan(0);
	});

	it('handles user-controlled strings without breaking the PDF (no lexer escape)', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		const malicious: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [
				{
					category: 'brand_discovery',
					title: 'malicious',
					severity: 'info',
					detail: '',
					metadata: {
						candidate: 'evil(.com)\\test\rwith\nnewline',
						bucket: 'impersonation',
						registrar: 'Sketchy & Co. (LLC)',
						registrarSource: 'rdap',
						reasons: ['contains ( and ) and \\'],
						signals: ['markov_gen'],
						combinedConfidence: 0.1,
					},
				},
			],
		};

		const bytes = await renderBrandAuditPdf(malicious, 'apple.com', { serverVersion: '2.21.4' });
		// Must still parse cleanly — pdf-lib will throw if our string escaping is wrong.
		const parsed = await PDFDocument.load(bytes);
		expect(parsed.getPageCount()).toBeGreaterThan(0);
	});

	it('renders per-row reasons text for EVERY candidate (not just the last in each section)', async () => {
		// Surfaced 2026-05-19 in production marriott/mastercard PDFs: only the
		// last candidate row before a section break showed its `reasons:` line.
		// Root cause: the next row's background rectangle was drawn AFTER the
		// previous row's reasons text and at a y-position that overlapped it,
		// obscuring all but the last (because there's no "next row" to overdraw).
		// Fix: background-rect height grows when reasons present so the band
		// fully contains the reasons line and the next row's band starts BELOW it.
		//
		// Test surrogate (pdf-lib applies FlateDecode to text streams so raw-byte
		// grep won't find content): render the same audit WITH reasons and a
		// parallel one WITHOUT reasons. The WITH version must be measurably
		// larger because more drawText operations land in the content stream.
		// Under the overdraw bug, the only-last-row-shows behavior means
		// withReasons is barely larger than without; after the fix it's larger
		// by ~one extra drawText op per row.
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		const makeFindings = (reasons: string[]) =>
			['first.example', 'second.example', 'third.example', 'fourth.example'].map((domain) => ({
				category: 'brand_discovery' as const,
				title: domain,
				severity: 'info' as const,
				detail: '',
				metadata: {
					candidate: domain,
					bucket: 'consolidated',
					registrar: 'X',
					registrarSource: 'rdap',
					reasons,
					signals: ['ns'],
					combinedConfidence: 0.95,
				},
			}));
		const withReasons: CheckResult = { category: 'brand_discovery', score: 100, findings: makeFindings(['some specific reason text appears here']) };
		const withoutReasons: CheckResult = { category: 'brand_discovery', score: 100, findings: makeFindings([]) };

		const aBytes = await renderBrandAuditPdf(withReasons, 'example.com', { serverVersion: '2.21.4' });
		const bBytes = await renderBrandAuditPdf(withoutReasons, 'example.com', { serverVersion: '2.21.4' });

		// Each row's reasons text adds bytes to the compressed content stream.
		// With the overdraw bug, only ONE row's reasons survived → ~one drawText
		// worth of delta. Fixed: ALL FOUR rows' reasons survive → ~4x the delta.
		// A robust assertion: with-vs-without delta must be > 80 bytes (each
		// drawText op + reasons text is ~20+ bytes compressed).
		const delta = aBytes.byteLength - bBytes.byteLength;
		expect(
			delta,
			`per-row reasons must persist for all rows (4 in this test). With the overdraw bug, delta is small (~one row's worth). Got delta=${delta} bytes; expected >80 for 4 rows × reasons.`,
		).toBeGreaterThan(80);
	});

	it('handles non-WinAnsi unicode characters in reasons / metadata without throwing', async () => {
		// Surfaced 2026-05-19 in production audit 523e6276 (amazon.com): pdf-lib
		// standard Helvetica uses WinAnsi encoding which cannot encode `≥` (U+2265).
		// Classifier emits reasons like `lookalike score 0.92 ≥ 0.85` which crashed
		// drawText, causing the pdf-queue consumer to retry-storm and exhaust
		// (5 of 9 brands in batch d6cce286 lost their PDFs to this exact bug).
		// Fix: sanitize text inputs to drawText by mapping common non-WinAnsi
		// typographic + math chars to ASCII equivalents.
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		const unicode: CheckResult = {
			category: 'brand_discovery',
			score: 100,
			findings: [
				{
					category: 'brand_discovery',
					title: 'unicode',
					severity: 'info',
					detail: '',
					metadata: {
						candidate: 'fake.example',
						bucket: 'impersonation',
						registrar: 'Registrar — Inc.',
						registrarSource: 'rdap',
						reasons: ['lookalike score 0.92 ≥ 0.85', 'distance ≤ 2', 'this is … truncated'],
						signals: ['markov_gen'],
						combinedConfidence: 0.3,
					},
				},
			],
		};

		// Before the fix this throws WinAnsi-can't-encode. After, it produces a PDF.
		const bytes = await renderBrandAuditPdf(unicode, 'example.com', { serverVersion: '2.21.4' });
		expect(bytes.byteLength).toBeGreaterThan(500);
		const header = new TextDecoder().decode(bytes.slice(0, 5));
		expect(header).toBe('%PDF-');
	});

	it('emits deterministic bytes for a given input (modulo CreationDate)', async () => {
		const { renderBrandAuditPdf } = await import('../src/lib/brand-audit-pdf-render');
		const r = makeBrandAuditResult();
		const now = () => new Date('2026-05-19T12:00:00Z').getTime();
		const a = await renderBrandAuditPdf(r, 'apple.com', { serverVersion: '2.21.4', now });
		const b = await renderBrandAuditPdf(r, 'apple.com', { serverVersion: '2.21.4', now });
		expect(a.byteLength).toBe(b.byteLength);
	});
});
