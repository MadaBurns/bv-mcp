// SPDX-License-Identifier: BUSL-1.1

/**
 * Brand-audit PDF renderer — pure, in-process, no browser.
 *
 * Replaces the previous bv-browser-renderer service-binding path that proved
 * unreliable due to stacked cross-repo timeout layers (safeFetch +
 * protocolTimeout + page.setContent + page.pdf + Cloudflare server-side limit
 * — all observable as silent 504s on brand-audit renders during the 2026-05-19
 * incident). Uses `pdf-lib`, which is Worker-compatible (pure JS, no
 * Node-specific APIs), so the renderer runs inside the pdf-queue consumer with
 * zero external dependencies.
 *
 * Layout: A4 portrait, four bucket sections (Consolidated / Shadow IT /
 * Indeterminate / Impersonation), one row per candidate. Uses the same data
 * shape (`BrandCandidateRow`) the prior HTML template consumed, so
 * `candidatesFromCheckResult` extraction logic is shared. Multi-page support
 * via `ensureRoom` — if a row would overflow the current page, a new page is
 * added before drawing.
 */

import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from 'pdf-lib';
import type { CheckResult } from './scoring';
import { candidatesFromCheckResult, type BrandAuditBucket, type BrandCandidateRow } from './brand-audit-html-template';

export interface RenderBrandAuditPdfOptions {
	/** Server version for the PDF footer. Threaded from SERVER_VERSION at call time. */
	serverVersion: string;
	/** Clock override for tests (returns ms since epoch). Defaults to Date.now(). */
	now?: () => number;
}

// A4 portrait, points.
const PAGE_WIDTH = 595;
const PAGE_HEIGHT = 842;
const MARGIN = 48;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const FOOTER_RESERVE = 60; // bottom padding so footer text never overlaps content
const ROW_HEIGHT = 14;
const SECTION_GAP = 24;

const COLOR_TEXT = rgb(0.88, 0.88, 0.88);
const COLOR_DIM = rgb(0.55, 0.55, 0.55);
const COLOR_BG = rgb(0, 0, 0);
const COLOR_ACCENT = rgb(0, 1, 0.62); // #00FF9D
const COLOR_BADGE_HIGH = rgb(0, 1, 0.62);
const COLOR_BADGE_MED = rgb(1, 0.8, 0);
const COLOR_BADGE_LOW = rgb(1, 0.3, 0.3);

const BUCKET_ORDER: Array<{ bucket: BrandAuditBucket; title: string }> = [
	{ bucket: 'consolidated', title: 'Consolidated Infrastructure' },
	{ bucket: 'shadowIt', title: 'Registrar Sprawl / Real Shadow IT' },
	{ bucket: 'indeterminate', title: 'Indeterminate' },
	{ bucket: 'impersonation', title: 'Impersonation Signals' },
];

function badgeColor(bucket: BrandAuditBucket) {
	if (bucket === 'consolidated') return COLOR_BADGE_HIGH;
	if (bucket === 'shadowIt') return COLOR_BADGE_MED;
	if (bucket === 'impersonation') return COLOR_BADGE_LOW;
	return COLOR_DIM;
}

/**
 * Map common non-WinAnsi unicode chars to ASCII equivalents. pdf-lib's
 * standard fonts (Helvetica, Courier) embed via WinAnsi which throws on any
 * non-encodable codepoint. Classifier reasons like "lookalike score 0.92 ≥ 0.85"
 * contain ≥ (U+2265) which crashed every render that included impersonation
 * rationale (5 of 9 brands in batch d6cce286 lost their PDFs to this).
 * Any chars NOT in this map AND not in WinAnsi get replaced with '?' as a
 * defensive fallback (last `.replace`).
 */
function winAnsiSafe(s: string): string {
	return s
		.replace(/≥/g, '>=')
		.replace(/≤/g, '<=')
		.replace(/≠/g, '!=')
		.replace(/≈/g, '~')
		.replace(/×/g, 'x')
		.replace(/±/g, '+/-')
		.replace(/—/g, '--')
		.replace(/–/g, '-')
		.replace(/…/g, '...')
		.replace(/[“”]/g, '"')
		.replace(/[‘’]/g, "'")
		.replace(/→/g, '->')
		.replace(/←/g, '<-')
		.replace(/✓/g, 'v')
		.replace(/✗/g, 'x')
		// Strip any remaining > U+00FF that WinAnsi can't encode.
		.replace(/[^\x00-\xff]/g, '?');
}

/**
 * Helper to truncate a string to fit a maximum width when rendered at `size`.
 * pdf-lib's font metric APIs are sync but expensive; for our table layout we
 * use a coarse character-count approximation since fitting is cosmetic.
 * Truncation marker uses ASCII '...' so the result is WinAnsi-safe.
 */
function truncate(s: string, maxChars: number): string {
	const safe = winAnsiSafe(s);
	if (safe.length <= maxChars) return safe;
	return safe.slice(0, Math.max(1, maxChars - 3)) + '...';
}

interface DrawContext {
	doc: PDFDocument;
	page: PDFPage;
	font: PDFFont;
	mono: PDFFont;
	bold: PDFFont;
	cursorY: number;
}

function newPage(ctx: DrawContext): void {
	ctx.page = ctx.doc.addPage([PAGE_WIDTH, PAGE_HEIGHT]);
	ctx.page.drawRectangle({ x: 0, y: 0, width: PAGE_WIDTH, height: PAGE_HEIGHT, color: COLOR_BG });
	ctx.cursorY = PAGE_HEIGHT - MARGIN;
}

function ensureRoom(ctx: DrawContext, needed: number): void {
	if (ctx.cursorY - needed < MARGIN + FOOTER_RESERVE) {
		newPage(ctx);
	}
}

function drawText(ctx: DrawContext, text: string, opts: { x: number; size: number; color?: ReturnType<typeof rgb>; font?: PDFFont }): void {
	// Defense-in-depth: every drawText goes through winAnsiSafe so any caller
	// passing unsanitized text (target name, section title literals, callsite
	// helpers) can't crash the renderer on a stray unicode codepoint.
	ctx.page.drawText(winAnsiSafe(text), {
		x: opts.x,
		y: ctx.cursorY,
		size: opts.size,
		font: opts.font ?? ctx.font,
		color: opts.color ?? COLOR_TEXT,
	});
}

function sectionHeader(ctx: DrawContext, title: string, count: number): void {
	ensureRoom(ctx, 36);
	ctx.cursorY -= SECTION_GAP;
	// Accent dot
	ctx.page.drawRectangle({ x: MARGIN, y: ctx.cursorY + 4, width: 8, height: 8, color: COLOR_ACCENT });
	drawText(ctx, title, { x: MARGIN + 16, size: 14, font: ctx.bold });
	drawText(ctx, `${count} candidate${count === 1 ? '' : 's'}`, { x: PAGE_WIDTH - MARGIN - 90, size: 9, color: COLOR_DIM, font: ctx.mono });
	ctx.cursorY -= 8;
	// Divider line
	ctx.page.drawRectangle({ x: MARGIN, y: ctx.cursorY, width: CONTENT_WIDTH, height: 0.5, color: COLOR_DIM });
	ctx.cursorY -= 16;
}

function drawCandidateRow(ctx: DrawContext, row: BrandCandidateRow): void {
	const hasReasons = row.reasons.length > 0;
	// Row has 2 text lines (domain, metadata) + optional 3rd (reasons). Background
	// rect height must cover ALL of them — the prior 2-line-only height let the
	// next row's bg overdraw the reasons text (surfaced 2026-05-19 in production
	// marriott/mastercard PDFs).
	const textLines = hasReasons ? 3 : 2;
	const rowBgHeight = ROW_HEIGHT * textLines + 4;
	const rowSpacing = 4; // gap between rows

	ensureRoom(ctx, rowBgHeight + rowSpacing);

	// Background bar covers all text lines for this row.
	ctx.page.drawRectangle({
		x: MARGIN,
		y: ctx.cursorY - rowBgHeight + ROW_HEIGHT,
		width: CONTENT_WIDTH,
		height: rowBgHeight,
		color: rgb(0.04, 0.04, 0.04),
	});
	// Domain (left), confidence (right)
	drawText(ctx, truncate(row.domain, 60), { x: MARGIN + 8, size: 10, font: ctx.bold });
	const confText = `${(row.combinedConfidence * 100).toFixed(0)}%`;
	drawText(ctx, confText, { x: PAGE_WIDTH - MARGIN - 36, size: 10, color: badgeColor(row.bucket), font: ctx.mono });
	ctx.cursorY -= ROW_HEIGHT;
	// Metadata line
	const metaParts = [
		`registrar: ${truncate(row.registrar, 30)}`,
		`source: ${row.registrarSource}`,
		`signals: ${row.signals.join(', ') || '—'}`,
	];
	drawText(ctx, truncate(metaParts.join('  ·  '), 90), { x: MARGIN + 8, size: 8, color: COLOR_DIM, font: ctx.mono });
	if (hasReasons) {
		ctx.cursorY -= ROW_HEIGHT;
		drawText(ctx, truncate('reasons: ' + row.reasons.join('; '), 90), { x: MARGIN + 8, size: 8, color: COLOR_DIM });
	}
	ctx.cursorY -= ROW_HEIGHT + rowSpacing;
}

function drawEmptyBucket(ctx: DrawContext, msg: string): void {
	ensureRoom(ctx, ROW_HEIGHT);
	drawText(ctx, msg, { x: MARGIN + 8, size: 9, color: COLOR_DIM });
	ctx.cursorY -= ROW_HEIGHT + 4;
}

function depthWarningsFromCheckResult(result: CheckResult): string[] {
	const summary = result.findings.find((f) => f.metadata?.summary === true);
	const depth = summary?.metadata?.depth;
	if (!depth || typeof depth !== 'object' || Array.isArray(depth)) return [];
	const warnings = (depth as Record<string, unknown>).warnings;
	return Array.isArray(warnings) ? warnings.filter((warning): warning is string => typeof warning === 'string' && warning.length > 0) : [];
}

/** Tiered-mode detection — pipeline stamps `discoveryMode: 'tiered'` on summary metadata when running tiered. */
function isTieredMode(result: CheckResult): boolean {
	const summary = result.findings.find((f) => f.metadata?.summary === true);
	return summary?.metadata?.discoveryMode === 'tiered';
}

/**
 * Tiered-mode row extraction. `BrandCandidateRow` (the legacy contract with the
 * HTML template) deliberately doesn't carry tier/lookalikeScore — we read them
 * straight off the finding metadata here so the legacy PDF path stays
 * byte-identical and the legacy HTML template doesn't need to change.
 */
interface TieredRow extends BrandCandidateRow {
	tier?: 0 | 1 | 2 | 3 | 4;
	lookalikeScore?: number;
	scoreAlertContext?: { alertType: string; transition: string };
}

function tieredRowsFromCheckResult(result: CheckResult): TieredRow[] {
	const base = candidatesFromCheckResult(result);
	const byDomain = new Map<string, BrandCandidateRow>();
	for (const r of base) byDomain.set(r.domain, r);
	const out: TieredRow[] = [];
	for (const f of result.findings) {
		const m = f.metadata;
		if (!m || typeof m.candidate !== 'string') continue;
		// `impersonationSurface` rows are dropped by `candidatesFromCheckResult`
		// (the legacy extractor pins the type to 4 buckets). Construct the row
		// from finding metadata directly so the tier-4 section renders.
		const baseRow: BrandCandidateRow = byDomain.get(m.candidate) ?? {
			domain: m.candidate as string,
			bucket: 'impersonationSurface' as unknown as BrandAuditBucket,
			relationshipType: 'impersonation_surface',
			registrar: typeof m.registrar === 'string' ? m.registrar : 'Unknown',
			registrarSource: typeof m.registrarSource === 'string' ? m.registrarSource : 'unknown',
			reasons: Array.isArray(m.reasons) ? (m.reasons as string[]) : [],
			signals: Array.isArray(m.signals) ? (m.signals as string[]) : [],
			combinedConfidence: typeof m.combinedConfidence === 'number' ? (m.combinedConfidence as number) : 0,
		};
		// Bucket override if the original finding said impersonationSurface but
		// the legacy extractor coerced/dropped it.
		const bucket = typeof m.bucket === 'string' ? (m.bucket as BrandAuditBucket | 'impersonationSurface') : baseRow.bucket;
		const tier =
			m.tier === 0 || m.tier === 1 || m.tier === 2 || m.tier === 3 || m.tier === 4
				? (m.tier as 0 | 1 | 2 | 3 | 4)
				: undefined;
		const lookalikeScore = typeof m.lookalikeScore === 'number' ? (m.lookalikeScore as number) : undefined;
		const scoreAlertCtxRaw = m.scoreAlertContext;
		const scoreAlertContext =
			scoreAlertCtxRaw && typeof scoreAlertCtxRaw === 'object' && !Array.isArray(scoreAlertCtxRaw) &&
			typeof (scoreAlertCtxRaw as { alertType?: unknown }).alertType === 'string' &&
			typeof (scoreAlertCtxRaw as { transition?: unknown }).transition === 'string'
				? {
						alertType: (scoreAlertCtxRaw as { alertType: string }).alertType,
						transition: (scoreAlertCtxRaw as { transition: string }).transition,
					}
				: undefined;
		out.push({
			...baseRow,
			bucket: bucket as BrandAuditBucket,
			...(tier !== undefined ? { tier } : {}),
			...(lookalikeScore !== undefined ? { lookalikeScore } : {}),
			...(scoreAlertContext ? { scoreAlertContext } : {}),
		});
	}
	return out;
}

function drawSubsectionHeader(ctx: DrawContext, title: string, count: number): void {
	ensureRoom(ctx, 20);
	drawText(ctx, title, { x: MARGIN + 4, size: 11, font: ctx.bold });
	drawText(ctx, `${count} candidate${count === 1 ? '' : 's'}`, {
		x: PAGE_WIDTH - MARGIN - 90,
		size: 8,
		color: COLOR_DIM,
		font: ctx.mono,
	});
	ctx.cursorY -= 14;
}

function drawSubsectionRows(ctx: DrawContext, rows: TieredRow[]): void {
	if (rows.length === 0) {
		drawEmptyBucket(ctx, 'No candidates in this tier.');
		return;
	}
	for (const r of rows) {
		drawCandidateRow(ctx, r);
	}
}

function drawOwnedPortfolio(ctx: DrawContext, candidates: TieredRow[]): void {
	const consolidated = candidates.filter((c) => c.bucket === 'consolidated');
	const tenantDeclared = consolidated.filter((c) => c.tier === 0);
	const graphSurfaced = consolidated.filter((c) => c.tier === 1);
	const declaredEvidence = consolidated.filter((c) => c.tier === 2);
	const inferredConsolidated = consolidated.filter((c) => c.tier === undefined || c.tier === 3);
	const inferredShadowIt = candidates.filter((c) => c.bucket === 'shadowIt' && c.relationshipType === 'owned_off_primary_registrar');
	const inferredIndeterminate = candidates.filter((c) => c.bucket === 'indeterminate' && c.relationshipType !== 'authorized_vendor_dependency');
	const total =
		tenantDeclared.length +
		graphSurfaced.length +
		declaredEvidence.length +
		inferredConsolidated.length +
		inferredShadowIt.length +
		inferredIndeterminate.length;

	sectionHeader(ctx, 'Owned Portfolio', total);
	drawSubsectionHeader(ctx, 'Tenant-declared (tier 0)', tenantDeclared.length);
	drawSubsectionRows(ctx, tenantDeclared);
	drawSubsectionHeader(ctx, 'Graph-surfaced (tier 1)', graphSurfaced.length);
	drawSubsectionRows(ctx, graphSurfaced);
	drawSubsectionHeader(ctx, 'Declared evidence (tier 2)', declaredEvidence.length);
	drawSubsectionRows(ctx, declaredEvidence);
	drawSubsectionHeader(
		ctx,
		'Inferred (tier 3)',
		inferredConsolidated.length + inferredShadowIt.length + inferredIndeterminate.length,
	);
	drawSubsectionRows(ctx, [...inferredConsolidated, ...inferredShadowIt, ...inferredIndeterminate]);
}

function drawImpersonationSurface(ctx: DrawContext, candidates: TieredRow[]): void {
	// Rows with bucket === 'impersonationSurface' (T8 classifier output in tiered mode).
	const rows = candidates.filter((c) => (c.bucket as string) === 'impersonationSurface');
	sectionHeader(ctx, 'Impersonation Surface', rows.length);
	if (rows.length === 0) {
		drawEmptyBucket(ctx, 'No tier-4 impersonation candidates surfaced.');
		return;
	}
	for (const r of rows) {
		drawCandidateRow(ctx, r);
	}
}

function drawVendorDependencies(ctx: DrawContext, candidates: BrandCandidateRow[]): void {
	const rows = candidates.filter((c) => c.relationshipType === 'authorized_vendor_dependency');
	if (rows.length === 0) return;
	sectionHeader(ctx, 'Authorized Vendor Dependencies', rows.length);
	for (const row of rows) {
		drawCandidateRow(ctx, row);
	}
}

function drawDepthWarnings(ctx: DrawContext, warnings: string[]): void {
	if (warnings.length === 0) return;
	const visible = warnings.slice(0, 4);
	const extraCount = warnings.length - visible.length;
	ensureRoom(ctx, 26 + (visible.length + (extraCount > 0 ? 1 : 0)) * 11);
	drawText(ctx, 'DISCOVERY DEPTH WARNINGS', { x: MARGIN, size: 9, color: COLOR_BADGE_MED, font: ctx.mono });
	ctx.cursorY -= 12;
	for (const warning of visible) {
		drawText(ctx, truncate(`- ${warning}`, 110), { x: MARGIN + 8, size: 8, color: COLOR_DIM });
		ctx.cursorY -= 11;
	}
	if (extraCount > 0) {
		drawText(ctx, `- ${extraCount} additional warning${extraCount === 1 ? '' : 's'} in JSON metadata`, { x: MARGIN + 8, size: 8, color: COLOR_DIM });
		ctx.cursorY -= 11;
	}
	ctx.cursorY -= 6;
}

function drawHeader(ctx: DrawContext, target: string, dateLabel: string): void {
	drawText(ctx, target.toUpperCase(), { x: MARGIN, size: 28, font: ctx.bold });
	ctx.cursorY -= 22;
	drawText(ctx, 'DISCOVERY INTEL REPORT', { x: MARGIN, size: 10, color: COLOR_ACCENT, font: ctx.mono });
	// Right-aligned metadata
	const metaX = PAGE_WIDTH - MARGIN - 180;
	const metaY = ctx.cursorY + 22;
	ctx.page.drawText(winAnsiSafe(`Project: Brand Audit`), { x: metaX, y: metaY, size: 8, font: ctx.mono, color: COLOR_DIM });
	ctx.page.drawText(winAnsiSafe(`Status:  Automated`), { x: metaX, y: metaY - 10, size: 8, font: ctx.mono, color: COLOR_DIM });
	ctx.page.drawText(winAnsiSafe(`Date:    ${dateLabel}`), { x: metaX, y: metaY - 20, size: 8, font: ctx.mono, color: COLOR_DIM });
	ctx.cursorY -= 16;
	ctx.page.drawRectangle({ x: MARGIN, y: ctx.cursorY, width: CONTENT_WIDTH, height: 0.5, color: COLOR_DIM });
	ctx.cursorY -= 12;
}

function drawFooter(ctx: DrawContext, target: string, serverVersion: string, dateLabel: string): void {
	// Footer goes on every page already drawn.
	const pages = ctx.doc.getPages();
	for (const p of pages) {
		p.drawRectangle({ x: MARGIN, y: MARGIN + 24, width: CONTENT_WIDTH, height: 0.5, color: COLOR_DIM });
		p.drawText(winAnsiSafe(`bv-mcp brand-audit · ${target} · ${dateLabel}`), { x: MARGIN, y: MARGIN + 8, size: 7, font: ctx.mono, color: COLOR_DIM });
		p.drawText(winAnsiSafe(`v${serverVersion}`), { x: PAGE_WIDTH - MARGIN - 40, y: MARGIN + 8, size: 7, font: ctx.mono, color: COLOR_DIM });
	}
}

/**
 * Render a brand-audit CheckResult to PDF bytes.
 *
 * Pure: no I/O, no network. Same return signature as the prior
 * browser-renderer-backed `renderBrandAuditPdf` so the pdf-queue consumer is
 * unchanged.
 */
export async function renderBrandAuditPdf(result: CheckResult, target: string, options: RenderBrandAuditPdfOptions): Promise<Uint8Array> {
	const now = options.now ?? Date.now;
	const dateLabel = new Date(now()).toISOString().slice(0, 10);
	const candidates = candidatesFromCheckResult(result);
	const depthWarnings = depthWarningsFromCheckResult(result);

	const doc = await PDFDocument.create();
	doc.setCreator('bv-mcp brand-audit');
	doc.setProducer('pdf-lib (bv-mcp)');

	const font = await doc.embedFont(StandardFonts.Helvetica);
	const bold = await doc.embedFont(StandardFonts.HelveticaBold);
	const mono = await doc.embedFont(StandardFonts.Courier);

	const ctx: DrawContext = {
		doc,
		page: doc.addPage([PAGE_WIDTH, PAGE_HEIGHT]),
		font,
		mono,
		bold,
		cursorY: PAGE_HEIGHT - MARGIN,
	};
	ctx.page.drawRectangle({ x: 0, y: 0, width: PAGE_WIDTH, height: PAGE_HEIGHT, color: COLOR_BG });

	drawHeader(ctx, target, dateLabel);
	drawDepthWarnings(ctx, depthWarnings);

	for (const { bucket, title } of BUCKET_ORDER) {
		const rows = candidates.filter((r) => r.bucket === bucket && r.relationshipType !== 'authorized_vendor_dependency');
		sectionHeader(ctx, title, rows.length);
		if (rows.length === 0) {
			drawEmptyBucket(ctx, 'No candidates in this bucket.');
		} else {
			for (const row of rows) {
				drawCandidateRow(ctx, row);
			}
		}
	}

	drawVendorDependencies(ctx, candidates);

	// T9 — Tiered-mode reports append two top-level sections after the legacy
	// buckets: Owned Portfolio (4 sub-buckets by tier) + Impersonation Surface
	// (tier-4 lookalikes). Classic-mode runs skip this block — byte-identical
	// PDF output for `discoveryMode !== 'tiered'`.
	if (isTieredMode(result)) {
		const tieredRows = tieredRowsFromCheckResult(result);
		drawOwnedPortfolio(ctx, tieredRows);
		drawImpersonationSurface(ctx, tieredRows);
	}

	drawFooter(ctx, target, options.serverVersion, dateLabel);

	return await doc.save();
}
