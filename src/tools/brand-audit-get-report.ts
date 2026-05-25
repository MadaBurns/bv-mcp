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
 *   - `{ auditId }` (no target) → audit-level aggregate JSON from
 *     `brand_audits.results_json`. Same ready/notReady gating against the audit
 *     row's status.
 *
 * When a completed target has `pdf_r2_key` and the R2 binding is available,
 * the response metadata includes a signed PDF URL. Otherwise completed targets
 * surface `pdfPending` so callers can poll again.
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import type { BrandAuditStatus } from '../lib/db/brand-audit-schema';
import { BRAND_AUDIT_TARGET_DEADLINE_MS } from '../lib/brand-audit-reaper';
import type { BrandAuditStepStore } from '../lib/brand-audit-step-store';

const CATEGORY = 'brand_discovery';

export interface BrandAuditGetReportArgs {
	auditId: string;
	target?: string;
}

export interface BrandAuditGetReportDeps {
	db: D1Database;
	/** R2 bucket for brand-audit PDFs. When omitted, get-report falls back to inline JSON. */
	bucket?: { createSignedUrl?: (input: { key: string; expiresInSeconds: number }) => Promise<string> };
	/** TTL for the signed URL — defaults to 7 days, override for tests. */
	signedUrlTtlSeconds?: number;
	/** Clock override for tests + dead-zone closure. */
	now?: () => number;
	/** Step store for CSC complement pipeline steps. When omitted, cscComplement is not attached. */
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

		// PDF URL: when the PDF queue consumer has populated pdf_r2_key AND we
		// have an R2 binding wired, mint a 7-day signed URL. Otherwise surface
		// `pdfPending: true` so the caller knows to poll again.
		let pdfUrl: string | null = null;
		let pdfPending = false;
		if (targetRow.pdf_r2_key) {
			if (deps.bucket && typeof deps.bucket.createSignedUrl === 'function') {
				try {
					const { generateR2SignedUrl } = await import('../lib/r2-signed-url');
					pdfUrl = await generateR2SignedUrl(
						deps.bucket as { createSignedUrl?: (input: { key: string; expiresInSeconds: number }) => Promise<string> },
						targetRow.pdf_r2_key,
						deps.signedUrlTtlSeconds,
					);
				} catch {
					// R2 binding present but signing failed — fall back to inline JSON.
					pdfUrl = null;
				}
			}
		} else if (renderedStatus === 'completed') {
			// Result is ready but PDF hasn't been rendered yet. May be format=json
			// (no PDF requested) OR the PDF queue is still processing.
			pdfPending = true;
		}

		// CSC complement: prefer full scan payload; fall back to fast scan. Attach
		// only when the step-store is provisioned (operator deploys). A missing
		// stepStore is a no-op — the field is simply absent from the response.
		let cscComplement: unknown = undefined;
		if (deps.stepStore) {
			const normalizedTarget = target.trim().toLowerCase();
			const fullCsc = await deps.stepStore.get(auditId, normalizedTarget, 'csc_complement_full');
			const fastCsc = await deps.stepStore.get(auditId, normalizedTarget, 'csc_complement_fast');
			const cscPayload = (fullCsc?.status === 'completed' ? fullCsc.payload : null) ?? (fastCsc?.status === 'completed' ? fastCsc.payload : null);
			if (cscPayload !== null && cscPayload !== undefined) {
				cscComplement = cscPayload;
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
					...(cscComplement !== undefined ? { cscComplement } : {}),
				},
			),
		]);
	}

	// Aggregate-mode dead-zone closure (2026-05-21 production fix). Mirror the
	// per-target closure: when every target is terminal-via-synthesis but the
	// orchestrator never wrote the batch row, the audit row's `status` stays
	// 'running' forever and the customer is told to keep polling. Fetch
	// targets, decide if the batch is in fact terminal, persist (best-effort)
	// and treat the audit as terminal in this response. We don't synthesize
	// `results_json` itself — the orchestrator's aggregate report data is
	// genuinely lost when it dies mid-flight. The customer can fall back to
	// per-target gets to recover the data we have.
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

	const aggregate = safeParse(auditRow.results_json);
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
