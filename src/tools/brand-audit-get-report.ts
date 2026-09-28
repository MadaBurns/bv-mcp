// SPDX-License-Identifier: BUSL-1.1

/**
 * brand_audit_get_report — fetch a per-target or audit-aggregate result.
 *
 * Read-only D1 lookup. Owner-scoped — someone else's auditId surfaces as
 * `notFound`, never `accessDenied` (ID-enumeration defense, same as
 * brand_audit_status).
 *
 * Modes:
 *   - `{ auditId, target }` → per-target CheckResult JSON from `brand_audit_targets.result_json`.
 *     Returns `notReady` when the target row status is queued/running, `notFound`
 *     when the row doesn't exist, and the parsed JSON when status=completed.
 *   - `{ auditId }` (no target) → audit-level aggregate. `brand_audits.results_json`
 *     when present; otherwise (the normal case — no writer populates it, #1129)
 *     derived on read from the per-target rows: per-target summary + bucket
 *     rollup over targets that completed with a measured result. With no such
 *     target it abstains (`aggregateUnavailable`, `checkStatus: 'error'`).
 *     Same ready/notReady gating against the audit row's status.
 *
 * When a completed target has `pdf_r2_key`, the response metadata includes
 * `pdfUrl` — the authenticated `/reports/{auditId}/{target}.pdf` download
 * route (same bearer credential as the MCP call; owner-scoped). Absolute when
 * the public origin is known, otherwise a relative path (internal callers).
 * `pdfPending` is surfaced only when the audit's format actually requests a
 * PDF (`markdown`/`both` — the PDF queue fanout condition) and the render
 * hasn't landed yet; `format=json` callers never see a pending signal.
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import type { BrandAuditStatus } from '../lib/db/brand-audit-schema';
import { BRAND_AUDIT_TARGET_DEADLINE_MS } from '../lib/brand-audit-reaper';
import type { BrandAuditStepStore } from '../lib/brand-audit-step-store';

import { BRAND_DISCOVERY_CATEGORY as CATEGORY } from '../lib/brand-audit-category';

export interface BrandAuditGetReportArgs {
	auditId: string;
	target?: string;
}

export interface BrandAuditGetReportDeps {
	db: D1Database;
	/**
	 * Public origin (e.g. https://dns-mcp.blackveilsecurity.com) used to build
	 * the absolute PDF download URL. When omitted (internal service-binding
	 * path), `pdfUrl` is a relative `/reports/...` path.
	 */
	publicOrigin?: string;
	/** Clock override for tests + dead-zone closure. */
	now?: () => number;
	/** Step store for registrar complement pipeline steps. When omitted, registrarComplement is not attached. */
	stepStore?: BrandAuditStepStore;
}

interface AuditRowSlim {
	id: string;
	owner_id: string;
	status: BrandAuditStatus;
	results_json: string | null;
	format: string;
}

interface TargetRowSlim {
	audit_id: string;
	target: string;
	status: BrandAuditStatus;
	result_json: string | null;
	pdf_r2_key: string | null;
	error: string | null;
	completed_at: number | null;
	created_at: number;
}

function errorResult(flag: string, message: string, extra: Record<string, unknown> = {}): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Brand audit get report: ${flag}`, 'high', message, { [flag]: true, ...extra }),
	]);
}

function safeParse(json: string | null): unknown {
	if (!json) return null;
	try {
		return JSON.parse(json);
	} catch {
		return null;
	}
}

interface AggregateTargetRow {
	target: string;
	status: BrandAuditStatus;
	result_json: string | null;
	pdf_r2_key?: string | null;
	error: string | null;
}

const BUCKET_KEYS = ['consolidated', 'shadowIt', 'indeterminate', 'impersonation', 'impersonationSurface'] as const;
type BucketKey = (typeof BUCKET_KEYS)[number];

interface TargetAggregateEntry {
	target: string;
	status: BrandAuditStatus;
	/** True only when the target completed with a stored, measured (`checkStatus` absent/'completed') result. */
	measured: boolean;
	error: string | null;
	hasPdf: boolean;
	score?: number;
	passed?: boolean;
	total?: number;
	consolidated?: number;
	shadowIt?: number;
	indeterminate?: number;
	impersonation?: number;
	impersonationSurface?: number;
}

function num(v: unknown): number {
	return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

/**
 * Build the audit-level result from the per-target rows (#1129).
 *
 * A target contributes to the rollup only when it did not fail AND its stored
 * CheckResult parses AND that result reports a measurement (`checkStatus`
 * absent or 'completed' — a discovery-never-ran target stores the not-assessed
 * shape and is listed but not counted). The audit verdict follows the worst
 * measured target (min score / all passed); when no target is measured the
 * result abstains in the not-assessed shape (`checkStatus: 'error'`, score 0,
 * passed false, partial) instead of the `buildCheckResult` default of a clean
 * 100 over zero evidence.
 */
function buildDerivedAggregateResult(
	auditId: string,
	status: BrandAuditStatus,
	format: string,
	rows: AggregateTargetRow[],
): CheckResult {
	const targetStatusCounts = { queued: 0, running: 0, completed: 0, failed: 0 };
	const rollup: Record<'totalCandidates' | BucketKey, number> = {
		totalCandidates: 0,
		consolidated: 0,
		shadowIt: 0,
		indeterminate: 0,
		impersonation: 0,
		impersonationSurface: 0,
	};
	const measuredScores: number[] = [];
	let allMeasuredPassed = true;

	const targets: TargetAggregateEntry[] = rows.map((row) => {
		if (row.status in targetStatusCounts) targetStatusCounts[row.status]++;
		const entry: TargetAggregateEntry = {
			target: row.target,
			status: row.status,
			measured: false,
			error: row.error ?? null,
			hasPdf: Boolean(row.pdf_r2_key),
		};
		if (row.status === 'failed') return entry;
		const parsed = safeParse(row.result_json) as Partial<CheckResult> | null;
		if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.findings)) return entry;
		if (parsed.checkStatus !== undefined && parsed.checkStatus !== 'completed') return entry;

		const summary = parsed.findings.find((f) => f?.metadata?.summary === true)?.metadata ?? {};
		entry.measured = true;
		entry.score = num(parsed.score);
		entry.passed = parsed.passed === true;
		let bucketSum = 0;
		for (const key of BUCKET_KEYS) {
			const n = num(summary[key]);
			if (key !== 'impersonationSurface' || n > 0) entry[key] = n;
			rollup[key] += n;
			if (key !== 'impersonationSurface') bucketSum += n;
		}
		entry.total = typeof summary.total === 'number' ? summary.total : bucketSum;
		rollup.totalCandidates += entry.total;
		measuredScores.push(entry.score);
		if (!entry.passed) allMeasuredPassed = false;
		return entry;
	});

	const measuredTargets = measuredScores.length;
	if (measuredTargets === 0) {
		const base = buildCheckResult(CATEGORY, [
			createFinding(
				CATEGORY,
				`Brand audit ${auditId} aggregate: not available`,
				'info',
				`status=${status} format=${format} — no target completed with a measured result (${rows.length} target row(s)), so there is no audit-level aggregate. Use brand_audit_status for per-target errors.`,
				{
					summary: true,
					auditId,
					status,
					format,
					aggregate: null,
					aggregateUnavailable: true,
					targetStatusCounts,
					targets,
				},
			),
		]);
		return { ...base, score: 0, passed: false, checkStatus: 'error', partial: true };
	}

	if (rollup.impersonationSurface === 0) delete (rollup as Partial<typeof rollup>).impersonationSurface;
	const aggregate = {
		source: 'derived_from_targets' as const,
		totalTargets: rows.length,
		measuredTargets,
		targetStatusCounts,
		rollup,
		targets,
	};
	const base = buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			`Brand audit ${auditId} aggregate: ${status}`,
			'info',
			`status=${status} format=${format} measuredTargets=${measuredTargets}/${rows.length} candidates=${rollup.totalCandidates}`,
			{ summary: true, auditId, status, format, aggregate },
		),
	]);
	return {
		...base,
		score: Math.min(...measuredScores),
		passed: allMeasuredPassed,
		...(measuredTargets < rows.length ? { partial: true } : {}),
	};
}

export async function brandAuditGetReport(
	args: BrandAuditGetReportArgs,
	ownerId: string,
	deps: BrandAuditGetReportDeps,
): Promise<CheckResult> {
	const { auditId, target } = args;
	if (typeof auditId !== 'string' || auditId.trim().length === 0) {
		return errorResult('invalidInput', 'auditId is required.');
	}

	const auditRow = (await deps.db
		.prepare(
			'SELECT id, owner_id, status, results_json, format FROM brand_audits WHERE id = ? LIMIT 1',
		)
		.bind(auditId)
		.first()) as AuditRowSlim | null;

	if (!auditRow || auditRow.owner_id !== ownerId) {
		return errorResult('notFound', `No brand audit found with id ${auditId}.`, { auditId });
	}

	if (target) {
		const targetRow = (await deps.db
			.prepare(
				'SELECT audit_id, target, status, result_json, pdf_r2_key, error, completed_at, created_at FROM brand_audit_targets WHERE audit_id = ? AND target = ? LIMIT 1',
			)
			.bind(auditId, target.trim().toLowerCase())
			.first()) as TargetRowSlim | null;

		if (!targetRow) {
			return errorResult('notFound', `Target ${target} not in audit ${auditId}.`, { auditId, target });
		}

		// Dead-zone closure (2026-05-21 brand-beta.example.com hang). A `running` target past
		// its budget deadline is one the consumer couldn't self-flip — surface
		// it as terminal-failed here so the customer doesn't get told "poll
		// again" for the next 15 minutes. Mirrors the closure in
		// `brand_audit_status`. Best-effort UPDATE persists the flip; failure is
		// swallowed because the response is the durability contract.
		const now = (deps.now ?? Date.now)();
		const isStuck = targetRow.status === 'running' && now - targetRow.created_at > BRAND_AUDIT_TARGET_DEADLINE_MS;
		if (isStuck) {
			try {
				await deps.db
					.prepare(
						"UPDATE brand_audit_targets SET status = 'failed', error = ?, completed_at = ? WHERE audit_id = ? AND target = ? AND status = 'running'",
					)
					.bind(
						`read-path: target stuck >${Math.floor(BRAND_AUDIT_TARGET_DEADLINE_MS / 60_000)}min; consumer cap did not flip status`,
						now,
						auditId,
						targetRow.target,
					)
					.run();
			} catch {
				// Best-effort — next read or reaper tick retries the persistence.
			}
		}

		const parsed = safeParse(targetRow.result_json);
		const renderedStatus: BrandAuditStatus =
			targetRow.status === 'failed' || isStuck
				? 'failed'
				: auditRow.status === 'completed' && parsed !== null
					? 'completed'
					: targetRow.status;

		if (renderedStatus !== 'completed' && renderedStatus !== 'failed') {
			return errorResult(
				'notReady',
				`Target ${target} is currently ${targetRow.status}. Poll again with brand_audit_status.`,
				{ auditId, target, currentStatus: targetRow.status },
			);
		}

		// PDF URL: when the PDF queue consumer has populated pdf_r2_key, point the
		// caller at the authenticated /reports/ download route (streams the bytes
		// from R2 under the same bearer credential; owner-scoped in the route).
		// `pdfPending: true` only when the audit format actually queues a PDF
		// (markdown/both — see brand-audit-consumer's fanout condition) and the
		// render hasn't landed yet; format=json never produces one.
		let pdfUrl: string | null = null;
		let pdfPending = false;
		const pdfRequested = auditRow.format === 'markdown' || auditRow.format === 'both';
		if (targetRow.pdf_r2_key) {
			const path = `/reports/${encodeURIComponent(auditId)}/${encodeURIComponent(targetRow.target)}.pdf`;
			pdfUrl = deps.publicOrigin ? `${deps.publicOrigin}${path}` : path;
		} else if (renderedStatus === 'completed' && pdfRequested) {
			pdfPending = true;
		}

		// Registrar complement: prefer full scan payload; fall back to fast scan. Attach
		// only when the step-store is provisioned (operator deploys). A missing
		// stepStore is a no-op — the field is simply absent from the response.
		let registrarComplement: unknown = undefined;
		if (deps.stepStore) {
			const normalizedTarget = target.trim().toLowerCase();
			const fullRegistrar = await deps.stepStore.get(auditId, normalizedTarget, 'registrar_complement_full');
			const fastRegistrar = await deps.stepStore.get(auditId, normalizedTarget, 'registrar_complement_fast');
			const registrarPayload = (fullRegistrar?.status === 'completed' ? fullRegistrar.payload : null) ?? (fastRegistrar?.status === 'completed' ? fastRegistrar.payload : null);
			if (registrarPayload !== null && registrarPayload !== undefined) {
				registrarComplement = registrarPayload;
			}
		}

		return buildCheckResult(CATEGORY, [
			createFinding(
				CATEGORY,
				`Brand audit ${auditId} target ${target}: ${targetRow.status}`,
				'info',
				`status=${renderedStatus} completedAt=${targetRow.completed_at ? new Date(targetRow.completed_at).toISOString() : '—'}`,
				{
					summary: true,
					auditId,
					target: targetRow.target,
					status: renderedStatus,
					result: parsed,
					error: isStuck
						? `read-path: target stuck >${Math.floor(BRAND_AUDIT_TARGET_DEADLINE_MS / 60_000)}min; consumer cap did not flip status`
						: targetRow.error,
					pdfUrl,
					pdfPending,
					...(registrarComplement !== undefined ? { registrarComplement } : {}),
				},
			),
		]);
	}

	// Aggregate-mode dead-zone closure (2026-05-21 production fix). Mirror the
	// per-target closure: when every target is terminal-via-synthesis but the
	// orchestrator never wrote the batch row, the audit row's `status` stays
	// 'running' forever and the customer is told to keep polling. Fetch
	// targets, decide if the batch is in fact terminal, persist (best-effort)
	// and treat the audit as terminal in this response. We don't WRITE a
	// synthesized `results_json`; the aggregate below is derived on read from
	// the per-target rows (#1129).
	let renderedAuditStatus: BrandAuditStatus = auditRow.status;
	if (auditRow.status === 'queued' || auditRow.status === 'running') {
		const now = (deps.now ?? Date.now)();
		const targetRows = await deps.db
			.prepare(
				'SELECT audit_id, target, status, created_at, completed_at FROM brand_audit_targets WHERE audit_id = ?',
			)
			.bind(auditId)
			.all<{ status: BrandAuditStatus; created_at: number; result_json?: string | null }>();
		const rows = targetRows.results ?? [];
		const counts = {
			queued: rows.filter((r) => r.status === 'queued').length,
			running: rows.filter((r) => r.status === 'running' && now - r.created_at <= BRAND_AUDIT_TARGET_DEADLINE_MS).length,
			stuck: rows.filter((r) => r.status === 'running' && now - r.created_at > BRAND_AUDIT_TARGET_DEADLINE_MS).length,
			completed: rows.filter((r) => r.status === 'completed').length,
			failed: rows.filter((r) => r.status === 'failed').length,
		};
		const allTerminal = rows.length > 0 && counts.queued === 0 && counts.running === 0;
		if (allTerminal) {
			const completedCount = counts.completed;
			renderedAuditStatus = completedCount > 0 ? 'completed' : 'failed';
			try {
				await deps.db
					.prepare(
						"UPDATE brand_audits SET status = ?, completed_targets = ?, completed_at = ?, updated_at = ? WHERE id = ? AND status IN ('queued', 'running')",
					)
					.bind(renderedAuditStatus, completedCount, now, now, auditId)
					.run();
			} catch {
				// Best-effort — next reader retries the flip.
			}
		}
	}

	if (renderedAuditStatus !== 'completed' && renderedAuditStatus !== 'failed') {
		return errorResult(
			'notReady',
			`Audit ${auditId} is currently ${renderedAuditStatus}. Poll again with brand_audit_status.`,
			{ auditId, currentStatus: renderedAuditStatus },
		);
	}

	const stored = safeParse(auditRow.results_json);
	if (stored === null) {
		// #1129 — nothing writes `brand_audits.results_json`, so the aggregate is
		// derived on read from the per-target rows (only targets that actually
		// completed with a measured result feed the rollup).
		const rows =
			(
				await deps.db
					.prepare(
						'SELECT target, status, result_json, pdf_r2_key, error FROM brand_audit_targets WHERE audit_id = ? ORDER BY target',
					)
					.bind(auditId)
					.all<AggregateTargetRow>()
			).results ?? [];
		return buildDerivedAggregateResult(auditId, renderedAuditStatus, auditRow.format, rows);
	}

	const aggregate = stored;
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			`Brand audit ${auditId} aggregate: ${renderedAuditStatus}`,
			'info',
			`status=${renderedAuditStatus} format=${auditRow.format}`,
			{
				summary: true,
				auditId,
				status: renderedAuditStatus,
				format: auditRow.format,
				aggregate,
			},
		),
	]);
}
