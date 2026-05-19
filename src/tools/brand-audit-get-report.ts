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
 * R2 PDF mode lands in Phase 3 — this tool returns inline JSON only.
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import type { BrandAuditStatus } from '../lib/db/brand-audit-schema';

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
				'SELECT audit_id, target, status, result_json, pdf_r2_key, error, completed_at FROM brand_audit_targets WHERE audit_id = ? AND target = ? LIMIT 1',
			)
			.bind(auditId, target.trim().toLowerCase())
			.first()) as TargetRowSlim | null;

		if (!targetRow) {
			return errorResult('notFound', `Target ${target} not in audit ${auditId}.`, { auditId, target });
		}

		const parsed = safeParse(targetRow.result_json);
		const renderedStatus: BrandAuditStatus =
			targetRow.status === 'failed'
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
					error: targetRow.error,
					pdfUrl,
					pdfPending,
				},
			),
		]);
	}

	if (auditRow.status !== 'completed' && auditRow.status !== 'failed') {
		return errorResult(
			'notReady',
			`Audit ${auditId} is currently ${auditRow.status}. Poll again with brand_audit_status.`,
			{ auditId, currentStatus: auditRow.status },
		);
	}

	const aggregate = safeParse(auditRow.results_json);
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			`Brand audit ${auditId} aggregate: ${auditRow.status}`,
			'info',
			`status=${auditRow.status} format=${auditRow.format}`,
			{
				summary: true,
				auditId,
				status: auditRow.status,
				format: auditRow.format,
				aggregate,
			},
		),
	]);
}
