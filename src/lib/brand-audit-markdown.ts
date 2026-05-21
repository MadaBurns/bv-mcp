// SPDX-License-Identifier: BUSL-1.1

/**
 * Markdown formatter for brand_audit_single CheckResult.
 *
 * The orchestrator output is a CheckResult — JSON-shaped. This module emits
 * the same data as a compact Markdown summary suitable for chat/CLI display
 * and as the body of an inline `format: 'markdown' | 'both'` response.
 *
 * The PDF renderer in Phase 3 will produce its own HTML template; this is the
 * lightweight inline path that doesn't need Browser Rendering.
 */

import type { CheckResult, Finding } from './scoring';
import { sanitizeOutputText } from './output-sanitize';

type Bucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation' | 'impersonationSurface';
type RelationshipType =
	| 'owned_primary'
	| 'owned_off_primary_registrar'
	| 'authorized_vendor_dependency'
	| 'manual_review'
	| 'impersonation_risk'
	| 'impersonation_surface';

const BUCKET_HEADINGS: Record<Bucket, string> = {
	consolidated: 'Consolidated (owned/operated by the brand)',
	shadowIt: 'Registrar Sprawl / Real Shadow IT (owned off-primary registrar)',
	indeterminate: 'Indeterminate (insufficient evidence — review)',
	impersonation: 'Impersonation candidates (low confidence, likely typo-squat)',
	impersonationSurface: 'Impersonation surface (tier-4 lookalikes)',
};

const BUCKET_ORDER: Bucket[] = ['consolidated', 'shadowIt', 'indeterminate', 'impersonation'];

interface SummaryMeta {
	target: string;
	consolidated: number;
	shadowIt: number;
	indeterminate: number;
	impersonation: number;
	missingControl?: boolean;
	targetRegistrar?: string;
	targetRegistrarSource?: string;
	targetRegistrant?: string | null;
	total?: number;
	discoverySignalStatus?: Record<string, { status: string; error?: string }>;
	depth?: {
		warnings?: unknown;
	};
	/** Pipeline-stamped when `discovery_mode === 'tiered'`. Drives the v3 sections. */
	discoveryMode?: 'classic' | 'tiered';
}

function depthWarnings(meta: Partial<SummaryMeta>): string[] {
	const warnings = meta.depth?.warnings;
	return Array.isArray(warnings) ? warnings.filter((warning): warning is string => typeof warning === 'string' && warning.length > 0) : [];
}

function relationshipType(f: Finding): RelationshipType | null {
	const value = f.metadata?.relationshipType;
	return typeof value === 'string' ? (value as RelationshipType) : null;
}

function isVendorDependency(f: Finding): boolean {
	return relationshipType(f) === 'authorized_vendor_dependency';
}

/**
 * Render a `(defensive registration)` suffix for a candidate finding when
 * the pipeline stamped `metadata.defensive === true`. Defensive candidates
 * are typosquat-shaped domains the brand owns on purpose (e.g.
 * `masterard.com` next to `brand-theta.com`) — without a label customers
 * can't visually distinguish them from operational properties. We label,
 * we never re-bucket.
 */
function defensiveSuffix(f: Finding): string {
	if (f.metadata?.defensive !== true) return '';
	const reason = typeof f.metadata?.defensiveReason === 'string' ? f.metadata.defensiveReason : undefined;
	const reasonText = reason ? ` — ${sanitizeOutputText(reason, 40)}` : '';
	return ` _(defensive registration${reasonText})_`;
}

/** Render `result` from `brandAuditSingle()` as a compact Markdown document. */
export function formatBrandAuditMarkdown(result: CheckResult): string {
	const summary = result.findings.find((f) => f.metadata?.summary === true);
	const summaryMeta = (summary?.metadata ?? {}) as Partial<SummaryMeta>;
	const target = summaryMeta.target ?? 'unknown';
	const lines: string[] = [];

	lines.push(`# Brand Audit — ${sanitizeOutputText(target, 253)}`);
	lines.push('');

	if (summaryMeta.targetRegistrar) {
		const reg = sanitizeOutputText(summaryMeta.targetRegistrar, 100);
		const src = sanitizeOutputText(summaryMeta.targetRegistrarSource ?? 'unknown', 20);
		const registrant = summaryMeta.targetRegistrant ? sanitizeOutputText(summaryMeta.targetRegistrant, 200) : '—';
		lines.push(`**Target registrar:** ${reg} (${src})  `);
		lines.push(`**Target registrant:** ${registrant}`);
		lines.push('');
	}

	const warnings = depthWarnings(summaryMeta);
	if (warnings.length > 0) {
		lines.push('> **Discovery depth warnings:**');
		for (const warning of warnings) {
			lines.push(`> - ${sanitizeOutputText(warning, 500)}`);
		}
		lines.push('');
	}

	const quotaFinding = result.findings.find((f) => f.metadata?.quotaExceeded === true);
	if (quotaFinding) {
		lines.push('> **Quota exceeded** — this audit was refused before discovery ran.');
		lines.push(`> ${sanitizeOutputText(quotaFinding.detail, 500)}`);
		return lines.join('\n');
	}

	if (summaryMeta.missingControl) {
		lines.push('> No candidates surfaced. Discovery either failed across all signals or produced nothing above the confidence threshold.');
		const status = summaryMeta.discoverySignalStatus;
		if (status && typeof status === 'object') {
			lines.push('');
			lines.push('**Discovery status:**');
			for (const [signal, info] of Object.entries(status)) {
				lines.push(`- \`${signal}\`: ${info?.status ?? 'unknown'}${info?.error ? ` — ${sanitizeOutputText(info.error, 200)}` : ''}`);
			}
		}
		return lines.join('\n');
	}

	lines.push(
		`**Counts:** consolidated=${summaryMeta.consolidated ?? 0}  shadowIt=${summaryMeta.shadowIt ?? 0}  indeterminate=${summaryMeta.indeterminate ?? 0}  impersonation=${summaryMeta.impersonation ?? 0}`,
	);
	lines.push('');

	const byBucket: Record<Bucket, Finding[]> = {
		consolidated: [],
		shadowIt: [],
		indeterminate: [],
		impersonation: [],
		impersonationSurface: [],
	};
	for (const f of result.findings) {
		const bucket = f.metadata?.bucket as Bucket | undefined;
		if (bucket && bucket in byBucket) byBucket[bucket].push(f);
	}

	for (const bucket of BUCKET_ORDER) {
		const items = byBucket[bucket].filter((f) => !isVendorDependency(f));
		if (items.length === 0) continue;
		lines.push(`## ${BUCKET_HEADINGS[bucket]} (${items.length})`);
		lines.push('');
		for (const f of items) {
			const domain = sanitizeOutputText(String(f.metadata?.candidate ?? ''), 253);
			const registrar = sanitizeOutputText(String(f.metadata?.registrar ?? 'Unknown'), 100);
			const source = sanitizeOutputText(String(f.metadata?.registrarSource ?? 'unknown'), 20);
			const conf = typeof f.metadata?.combinedConfidence === 'number' ? (f.metadata.combinedConfidence as number).toFixed(2) : '—';
			const signalArr = Array.isArray(f.metadata?.signals) ? (f.metadata!.signals as string[]) : [];
			const signals = signalArr.length > 0 ? sanitizeOutputText(signalArr.join(', '), 200) : '—';
			const note = f.metadata?.note ? ` _(${sanitizeOutputText(String(f.metadata.note), 100)})_` : '';
			const defensive = defensiveSuffix(f);
			lines.push(`- **${domain}**${note}${defensive} — registrar: ${registrar} (${source}) · confidence ${conf} · signals: ${signals}`);
		}
		lines.push('');
	}

	appendVendorDependencies(lines, result.findings.filter(isVendorDependency));

	// T9 — Tiered mode adds two top-level sections after the legacy buckets:
	//   `## Owned Portfolio` (four sub-buckets by tier provenance)
	//   `## Impersonation Surface` (tier-4 lookalikes)
	//
	// `discoveryMode === 'tiered'` is pipeline-stamped; in classic mode the
	// entire block is skipped and the markdown stays byte-identical with the
	// prior renderer.
	if (summaryMeta.discoveryMode === 'tiered') {
		appendOwnedPortfolio(lines, byBucket);
		appendImpersonationSurface(lines, byBucket.impersonationSurface);
	}

	return lines.join('\n').trimEnd();
}

function appendOwnedPortfolio(lines: string[], byBucket: Record<Bucket, Finding[]>): void {
	const consolidated = byBucket.consolidated.filter((f) => !isVendorDependency(f));
	const tenantDeclared = consolidated.filter((f) => f.metadata?.tier === 0);
	const graphSurfaced = consolidated.filter((f) => f.metadata?.tier === 1);
	const declaredEvidence = consolidated.filter((f) => f.metadata?.tier === 2);
	const inferredConsolidated = consolidated.filter(
		(f) => f.metadata?.tier === undefined || f.metadata?.tier === 3,
	);
	const inferredShadowIt = byBucket.shadowIt.filter((f) => relationshipType(f) === 'owned_off_primary_registrar');
	const inferredIndeterminate = byBucket.indeterminate.filter((f) => !isVendorDependency(f));
	const total =
		tenantDeclared.length +
		graphSurfaced.length +
		declaredEvidence.length +
		inferredConsolidated.length +
		inferredShadowIt.length +
		inferredIndeterminate.length;

	lines.push(`## Owned Portfolio (${total})`);
	lines.push('');
	appendPortfolioSubsection(lines, 'Tenant-declared (tier 0)', tenantDeclared);
	appendPortfolioSubsection(lines, 'Graph-surfaced (tier 1)', graphSurfaced);
	appendPortfolioSubsection(lines, 'Declared evidence (tier 2)', declaredEvidence);
	const inferredTotal = inferredConsolidated.length + inferredShadowIt.length + inferredIndeterminate.length;
	lines.push(`### Inferred (tier 3) — ${inferredTotal}`);
	lines.push('');
	appendPortfolioSubsection(lines, 'Consolidated', inferredConsolidated, '#### ');
	appendPortfolioSubsection(lines, 'Shadow IT', inferredShadowIt, '#### ');
	appendPortfolioSubsection(lines, 'Indeterminate', inferredIndeterminate, '#### ');
}

function appendVendorDependencies(lines: string[], items: Finding[]): void {
	if (items.length === 0) return;
	lines.push(`## Authorized Vendor Dependencies (${items.length})`);
	lines.push('');
	for (const f of items) {
		const domain = sanitizeOutputText(String(f.metadata?.candidate ?? ''), 253);
		const registrar = sanitizeOutputText(String(f.metadata?.registrar ?? 'Unknown'), 100);
		const source = sanitizeOutputText(String(f.metadata?.registrarSource ?? 'unknown'), 20);
		const conf = typeof f.metadata?.combinedConfidence === 'number' ? (f.metadata.combinedConfidence as number).toFixed(2) : '—';
		const signalArr = Array.isArray(f.metadata?.signals) ? (f.metadata!.signals as string[]) : [];
		const signals = signalArr.length > 0 ? sanitizeOutputText(signalArr.join(', '), 200) : '—';
		const defensive = defensiveSuffix(f);
		lines.push(`- **${domain}**${defensive} — registrar: ${registrar} (${source}) · confidence ${conf} · signals: ${signals}`);
	}
	lines.push('');
}

function appendPortfolioSubsection(lines: string[], title: string, items: Finding[], heading = '### '): void {
	lines.push(`${heading}${title} (${items.length})`);
	lines.push('');
	if (items.length === 0) {
		lines.push('_No candidates in this tier._');
		lines.push('');
		return;
	}
	for (const f of items) {
		const domain = sanitizeOutputText(String(f.metadata?.candidate ?? ''), 253);
		const registrar = sanitizeOutputText(String(f.metadata?.registrar ?? 'Unknown'), 100);
		const source = sanitizeOutputText(String(f.metadata?.registrarSource ?? 'unknown'), 20);
		const conf = typeof f.metadata?.combinedConfidence === 'number' ? (f.metadata.combinedConfidence as number).toFixed(2) : '—';
		const defensive = defensiveSuffix(f);
		lines.push(`- **${domain}**${defensive} — registrar: ${registrar} (${source}) · confidence ${conf}`);
	}
	lines.push('');
}

function appendImpersonationSurface(lines: string[], items: Finding[]): void {
	lines.push(`## Impersonation Surface (${items.length})`);
	lines.push('');
	if (items.length === 0) {
		lines.push('_No tier-4 impersonation candidates surfaced._');
		lines.push('');
		return;
	}
	for (const f of items) {
		const domain = sanitizeOutputText(String(f.metadata?.candidate ?? ''), 253);
		const lookalike = typeof f.metadata?.lookalikeScore === 'number' ? (f.metadata.lookalikeScore as number).toFixed(2) : '—';
		const signalArr = Array.isArray(f.metadata?.signals) ? (f.metadata!.signals as string[]) : [];
		const signals = signalArr.length > 0 ? sanitizeOutputText(signalArr.join(', '), 200) : '—';
		const alertCtx = f.metadata?.scoreAlertContext;
		const alertSuffix =
			alertCtx && typeof alertCtx === 'object' && 'alertType' in alertCtx && 'transition' in alertCtx
				? ` · alert: ${sanitizeOutputText(String((alertCtx as { alertType: unknown }).alertType), 50)} (${sanitizeOutputText(String((alertCtx as { transition: unknown }).transition), 50)})`
				: '';
		lines.push(`- **${domain}** — lookalike ${lookalike} · signals: ${signals}${alertSuffix}`);
	}
	lines.push('');
}
