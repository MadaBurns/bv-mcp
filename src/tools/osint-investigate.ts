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
	type BindingDegradationSink,
} from '../lib/recon-binding';

const CATEGORY = 'osint_investigation' as CheckCategory;

export interface ReconToolOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
	reconJobKv?: KVNamespace;
	principalId?: string;
	onBindingDegradation?: BindingDegradationSink;
}

function unprovisioned(detail: string): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, 'OSINT investigation unavailable', 'info', detail, { unprovisioned: true }),
	]) as CheckResult;
}

const OSINT_OWNER_TTL_SECONDS = 24 * 60 * 60;
const SAFE_INVESTIGATION_ID = /^[A-Za-z0-9._:-]+$/;

function ownerKey(id: string): string {
	return `osint-investigation-owner:${id}`;
}

function notOwned(id: string): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, 'OSINT investigation not available', 'info', `OSINT investigation ${id} is not owned by this principal.`, {
			notOwned: true,
			investigationId: id,
		}),
	]) as CheckResult;
}

async function rememberInvestigationOwner(id: string | undefined, options: ReconToolOptions): Promise<void> {
	if (!id || !options.reconJobKv || !options.principalId || !SAFE_INVESTIGATION_ID.test(id)) return;
	await options.reconJobKv.put(ownerKey(id), options.principalId, { expirationTtl: OSINT_OWNER_TTL_SECONDS }).catch(() => undefined);
}

async function investigationOwnerMismatch(id: string, options: ReconToolOptions): Promise<boolean> {
	if (!options.reconJobKv || !SAFE_INVESTIGATION_ID.test(id)) return false;
	const owner = await options.reconJobKv.get(ownerKey(id)).catch(() => null);
	return Boolean(owner && owner !== options.principalId);
}

export async function osintInvestigateStart(
	type: ReconInvestigationType,
	query: string,
	options: ReconToolOptions = {},
): Promise<CheckResult> {
	const started = await callReconInvestigateStart(
		options.reconBinding,
		options.reconAuthToken,
		type,
		query,
		undefined,
		undefined,
		options.onBindingDegradation,
	);
	if (!started) return unprovisioned(`OSINT ${type} investigation is not provisioned in this deployment for ${query}.`);
	await rememberInvestigationOwner(started.investigationId, options);
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
const FINDING_KEEP_KEYS = [
	'type',
	'severity',
	'title',
	'details',
	'confidence',
	'platform',
	'platformCategory',
	'url',
	'createdAt',
] as const;

/** Hard cap on findings returned in a single report response, to stay under the MCP token cap. */
const REPORT_MAX_FINDINGS = 100;

// These projections handle the TOKEN-CAP concern (allowlisting which upstream
// keys survive + truncating the findings[] array) — NOT injection. F7 string
// neutralization + length clamp + depth-bounded recursion of every surviving
// upstream string now happens at the `createFinding` chokepoint
// (`@blackveil/dns-checks/scoring`), so the former per-value `sanitizeUpstreamValue`
// wrapping here was removed as redundant. The key allowlisting below MUST stay.

function projectStatusMeta(s: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	for (const k of STATUS_META_KEYS) if (k in s) out[k] = s[k];
	return out;
}

function shapeFinding(f: unknown): Record<string, unknown> {
	const src = (f && typeof f === 'object' ? f : {}) as Record<string, unknown>;
	const out: Record<string, unknown> = {};
	for (const k of FINDING_KEEP_KEYS) if (k in src) out[k] = src[k];
	return out;
}

function projectReportMeta(r: Record<string, unknown>): Record<string, unknown> {
	const out: Record<string, unknown> = {};
	// Upstream summary TEXT lives under `investigationSummary`; the bare `summary`
	// key is reserved as the codebase-wide "summary finding" boolean sentinel.
	if ('summary' in r) out.investigationSummary = r.summary;
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
	if (await investigationOwnerMismatch(id, options)) return notOwned(id);
	const s = await callReconInvestigationStatus(options.reconBinding, options.reconAuthToken, id, undefined, options.onBindingDegradation);
	if (!s) return unprovisioned(`Investigation status unavailable for ${id} (unprovisioned or not found).`);
	const status = typeof s.status === 'string' ? s.status : 'unknown';
	const parts = [`status=${status}`];
	if (typeof s.completedChecks === 'number' && typeof s.totalChecks === 'number')
		parts.push(`${s.completedChecks}/${s.totalChecks} checks`);
	if (typeof s.foundCount === 'number') parts.push(`${s.foundCount} found`);
	if (typeof s.summary === 'string' && s.summary.trim()) parts.push(s.summary.trim());
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Investigation ${id}`, 'info', shortText(parts.join(' · '), 800), {
			...projectStatusMeta(s),
			...(typeof s.summary === 'string' ? { investigationSummary: s.summary } : {}),
			summary: true,
			investigationId: id,
		}),
	]) as CheckResult;
}

export async function osintInvestigationReport(id: string, options: ReconToolOptions = {}): Promise<CheckResult> {
	if (await investigationOwnerMismatch(id, options)) return notOwned(id);
	const r = await callReconInvestigationReport(options.reconBinding, options.reconAuthToken, id, undefined, options.onBindingDegradation);
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
