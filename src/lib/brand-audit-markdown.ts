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

type Bucket = 'consolidated' | 'shadowIt' | 'indeterminate' | 'impersonation';

const BUCKET_HEADINGS: Record<Bucket, string> = {
	consolidated: 'Consolidated (owned/operated by the brand)',
	shadowIt: 'Shadow IT (potentially-related, non-aligned ownership)',
	indeterminate: 'Indeterminate (insufficient evidence — review)',
	impersonation: 'Impersonation candidates (low confidence, likely typo-squat)',
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
}

function depthWarnings(meta: Partial<SummaryMeta>): string[] {
	const warnings = meta.depth?.warnings;
	return Array.isArray(warnings) ? warnings.filter((warning): warning is string => typeof warning === 'string' && warning.length > 0) : [];
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

	const byBucket: Record<Bucket, Finding[]> = { consolidated: [], shadowIt: [], indeterminate: [], impersonation: [] };
	for (const f of result.findings) {
		const bucket = f.metadata?.bucket as Bucket | undefined;
		if (bucket && bucket in byBucket) byBucket[bucket].push(f);
	}

	for (const bucket of BUCKET_ORDER) {
		const items = byBucket[bucket];
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
			lines.push(`- **${domain}**${note} — registrar: ${registrar} (${source}) · confidence ${conf} · signals: ${signals}`);
		}
		lines.push('');
	}

	return lines.join('\n').trimEnd();
}
