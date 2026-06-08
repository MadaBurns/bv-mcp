// SPDX-License-Identifier: BUSL-1.1
/** OSINT investigation tools — thin fail-soft proxies over bv-recon osint-worker workflows. */
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import {
	callReconInvestigateStart,
	callReconInvestigationStatus,
	callReconInvestigationReport,
	type ReconBinding,
	type ReconInvestigationType,
} from '../lib/recon-binding';
import { sanitizeDnsData } from '../lib/output-sanitize';

const CATEGORY = 'osint_investigation' as CheckCategory;

export interface ReconToolOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
}

function unprovisioned(detail: string): CheckResult {
	return buildCheckResult(CATEGORY, [createFinding(CATEGORY, 'OSINT investigation unavailable', 'info', detail, { unprovisioned: true })]) as CheckResult;
}

export async function osintInvestigateStart(type: ReconInvestigationType, query: string, options: ReconToolOptions = {}): Promise<CheckResult> {
	const started = await callReconInvestigateStart(options.reconBinding, options.reconAuthToken, type, query);
	if (!started) return unprovisioned(`OSINT ${type} investigation is not provisioned in this deployment for ${query}.`);
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			`OSINT ${type} investigation started`,
			'info',
			`Started ${type} investigation for ${query} (id ${started.investigationId}). Poll with osint_investigation_status.`,
			{
				investigationId: started.investigationId,
				type,
				status: started.status ?? 'running',
				pollWith: 'osint_investigation_status',
			},
		),
	]) as CheckResult;
}

export const osintInvestigateDomainStart = (q: string, o?: ReconToolOptions) => osintInvestigateStart('domain', q, o);
export const osintInvestigateInfrastructureStart = (q: string, o?: ReconToolOptions) => osintInvestigateStart('deep_infrastructure', q, o);
export const osintInvestigateSupplyChainStart = (q: string, o?: ReconToolOptions) => osintInvestigateStart('supply_chain', q, o);

/**
 * Lightweight progress/summary fields surfaced by `osint_investigation_status`.
 * Deliberately EXCLUDES the heavy `findings[]` array — that belongs to the
 * report endpoint. Inlining it here blew past the MCP token cap (53 KB+).
 */
const STATUS_META_KEYS = [
	'id',
	'type',
	'query',
	'status',
	'workflowId',
	'progress',
	'totalChecks',
	'completedChecks',
	'foundCount',
	'aiAnalysis',
	'reportR2Key',
	'options',
	'createdAt',
	'updatedAt',
	'completedAt',
] as const;

/** Per-finding fields kept in the report. Drops the multi-KB `rawData` blob (and `evidenceR2Key`). */
const FINDING_KEEP_KEYS = ['type', 'severity', 'title', 'details', 'confidence', 'platform', 'platformCategory', 'url', 'createdAt'] as const;

/** Hard cap on findings returned in a single report response, to stay under the MCP token cap. */
const REPORT_MAX_FINDINGS = 100;

/** Defensive cap on any single string field (the upstream AI summary can be malformed/huge). */
const MAX_META_STRING = 8_000;

/** Recursion ceiling for nested kept-field sanitization — drop absurdly-deep upstream nesting. */
const MAX_META_DEPTH = 6;

/**
 * Defensive shaping for any string value before it enters finding metadata /
 * structuredContent. Upstream bv-recon strings (the AI-generated investigation
 * `summary`/`aiAnalysis` and all third-party finding fields) are model-facing and
 * attacker-influenceable — the structuredContent channel is the only otherwise-
 * unsanitized path to the calling LLM (the prose `detail` is already sanitized by
 * `createFinding`). Run every string through the same output sanitizer the prose
 * channel uses (`sanitizeDnsData`: strips C0/ANSI control bytes, neutralizes
 * markdown/HTML injection incl. code-fence backticks, collapses newlines) so
 * injected instructions can't reach the LLM here, THEN apply the length clamp on
 * the cleaned text. Kept fields can be object/array-valued (`details`, `aiAnalysis`,
 * `progress`, `options`) — recurse into arrays and plain objects so every nested
 * string is sanitized too (else nested injection payloads reach the LLM raw),
 * bounded by `MAX_META_DEPTH`. Scalars (number/boolean/null) pass through unchanged
 * at any depth (they can't carry injection); only nested containers hit the cap.
 *
 * Sanitize the FULL string, THEN clamp — `sanitizeDnsData` collapses whitespace
 * many-to-one, so coarse-slicing the input first could silently drop content a
 * compressible prefix pushes past the slice. This path is operator-only (BV_RECON)
 * and these strings are not multi-MB, so the full sweep is acceptable.
 */
function capString(v: unknown, depth = 0): unknown {
	if (typeof v === 'string') {
		const sanitized = sanitizeDnsData(v);
		return sanitized.length > MAX_META_STRING ? sanitized.slice(0, MAX_META_STRING) : sanitized;
	}
	if (v === null || typeof v !== 'object') return v; // numbers/booleans/null pass through at any depth
	if (depth >= MAX_META_DEPTH) return undefined; // stop unbounded recursion into nested containers
	if (Array.isArray(v)) return v.map((item) => capString(item, depth + 1));
	const out: Record<string, unknown> = {};
	for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = capString(val, depth + 1);
	return out;
}

function projectStatusMeta(s: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const k of STATUS_META_KEYS) if (k in s) out[k] = capString(s[k]);
	return out;
}

function shapeFinding(f: unknown): Record<string, unknown> {
	const src = (f && typeof f === 'object' ? f : {}) as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const k of FINDING_KEEP_KEYS) if (k in src) out[k] = capString(src[k]);
	return out;
}

function projectReportMeta(r: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	// Upstream summary TEXT lives under `investigationSummary`; the bare `summary`
	// key is reserved as the codebase-wide "summary finding" boolean sentinel.
	if ('summary' in r) out.investigationSummary = capString(r.summary);
	if ('total' in r) out.total = r.total;
	const raw = Array.isArray(r.findings) ? r.findings : [];
	out.findings = raw.slice(0, REPORT_MAX_FINDINGS).map(shapeFinding);
	if (raw.length > REPORT_MAX_FINDINGS) {
		out.findingsTruncated = true;
		out.findingsTotal = raw.length;
	}
	return out;
}

function shortText(s: string, max: number): string {
	return s.length > max ? s.slice(0, max) : s;
}

export async function osintInvestigationStatus(id: string, options: ReconToolOptions = {}): Promise<CheckResult> {
	const s = await callReconInvestigationStatus(options.reconBinding, options.reconAuthToken, id);
	if (!s) return unprovisioned(`Investigation status unavailable for ${id} (unprovisioned or not found).`);
	const status = typeof s.status === 'string' ? s.status : 'unknown';
	const parts = [`status=${status}`];
	if (typeof s.completedChecks === 'number' && typeof s.totalChecks === 'number') parts.push(`${s.completedChecks}/${s.totalChecks} checks`);
	if (typeof s.foundCount === 'number') parts.push(`${s.foundCount} found`);
	if (typeof s.summary === 'string' && s.summary.trim()) parts.push(s.summary.trim());
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Investigation ${id}`, 'info', shortText(parts.join(' · '), 800), {
			...projectStatusMeta(s),
			...(typeof s.summary === 'string' ? { investigationSummary: capString(s.summary) } : {}),
			summary: true,
			investigationId: id,
		}),
	]) as CheckResult;
}

export async function osintInvestigationReport(id: string, options: ReconToolOptions = {}): Promise<CheckResult> {
	const r = await callReconInvestigationReport(options.reconBinding, options.reconAuthToken, id);
	if (!r) return unprovisioned(`Investigation report unavailable for ${id} (unprovisioned or not ready).`);
	const total = typeof r.total === 'number' ? r.total : Array.isArray(r.findings) ? r.findings.length : 0;
	const summary = typeof r.summary === 'string' ? r.summary.trim() : '';
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Investigation ${id} report`, 'info', shortText(`${total} findings.${summary ? ` ${summary}` : ''}`, 1200), {
			...projectReportMeta(r),
			summary: true,
			investigationId: id,
		}),
	]) as CheckResult;
}
