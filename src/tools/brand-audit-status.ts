// SPDX-License-Identifier: BUSL-1.1

/**
 * brand_audit_status — read-only progress check for an enqueued brand audit.
 *
 * Reads `brand_audits` + `brand_audit_targets` from BRAND_AUDIT_DB. Owner-scoped:
 * an audit row is only visible to its owner (owner_id === principalId). A request
 * for someone else's auditId returns `notFound`, NOT `accessDenied` — defending
 * against ID enumeration. Worker code never confirms the existence of an audit
 * the caller doesn't own.
 *
 * Returns a `CheckResult` whose summary metadata carries:
 *   { auditId, status, progress: 'N/M', completed, total, targets: [{ target, status, error? }] }
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import type { BrandAuditStatus } from '../lib/db/brand-audit-schema';
import { BRAND_AUDIT_TARGET_DEADLINE_MS } from '../lib/brand-audit-reaper';

const CATEGORY = 'brand_discovery';

export interface BrandAuditStatusDeps {
	db: D1Database;
	now?: () => number;
}

interface BrandAuditRow {
	id: string;
	owner_id: string;
	status: BrandAuditStatus;
	total_targets: number;
	completed_targets: number;
	format: string;
	created_at: number;
	updated_at: number;
	completed_at: number | null;
}

interface BrandAuditTargetRow {
	audit_id: string;
	target: string;
	status: BrandAuditStatus;
	created_at: number;
	completed_at: number | null;
	error: string | null;
	pdf_r2_key: string | null;
	result_json: string | null;
}

function errorResult(flag: string, message: string, extra: Record<string, unknown> = {}): CheckResult {
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Brand audit status: ${flag}`, 'high', message, { [flag]: true, ...extra }),
	]);
}

export async function brandAuditStatus(
	auditId: string,
	ownerId: string,
	deps: BrandAuditStatusDeps,
): Promise<CheckResult> {
	if (typeof auditId !== 'string' || auditId.trim().length === 0) {
		return errorResult('invalidInput', 'auditId is required.');
	}

	let audit: BrandAuditRow | null = null;
	let targets: BrandAuditTargetRow[] = [];
	try {
		audit = (await deps.db
			.prepare(
				'SELECT id, owner_id, status, total_targets, completed_targets, format, created_at, updated_at, completed_at FROM brand_audits WHERE id = ? LIMIT 1',
			)
			.bind(auditId)
			.first()) as BrandAuditRow | null;

		if (audit && audit.owner_id === ownerId) {
			const all = await deps.db
				.prepare(
					'SELECT audit_id, target, status, created_at, completed_at, error, pdf_r2_key, result_json FROM brand_audit_targets WHERE audit_id = ? ORDER BY created_at ASC, target ASC',
				)
				.bind(auditId)
				.all<BrandAuditTargetRow>();
			targets = all.results ?? [];
		}
	} catch (err) {
		return errorResult(
			'readFailure',
			`Failed to read brand audit row: ${err instanceof Error ? err.message : String(err)}`,
			{ auditId },
		);
	}

	if (!audit || audit.owner_id !== ownerId) {
		return errorResult('notFound', `No brand audit found with id ${auditId}.`, { auditId });
	}

	const now = (deps.now ?? Date.now)();
	const progress = `${audit.completed_targets}/${audit.total_targets}`;

	// Dead-zone closure (2026-05-21 brand-zeta.com hang). A `running` target whose
	// row is older than BRAND_AUDIT_TARGET_DEADLINE_MS is past the point where
	// the consumer could have flipped it itself — its worker was killed before
	// the catch handler ran (CPU-saturated tier-1 brands starve the abort-fire
	// macrotask). The cron reaper would catch it eventually, but the customer
	// polling this endpoint shouldn't have to wait an extra cron tick. We:
	//   1. Surface it as `failed` in the response so the customer sees terminal
	//      progress immediately.
	//   2. Fire a best-effort UPDATE so the next reader (and the reaper) see
	//      consistent state. Failure is swallowed — the next reaper tick or
	//      polling read will retry the same flip.
	const deadZoneTargets: BrandAuditTargetRow[] = [];
	const renderedTargets = targets.map((t) => {
		const hasResultJson = typeof t.result_json === 'string' && t.result_json.length > 0;
		const isStuck = t.status === 'running' && now - t.created_at > BRAND_AUDIT_TARGET_DEADLINE_MS;
		if (isStuck) {
			deadZoneTargets.push(t);
		}
		let renderedStatus: BrandAuditStatus = t.status;
		if (isStuck) {
			renderedStatus = 'failed';
		} else if (audit.status === 'completed' && t.status !== 'failed' && hasResultJson) {
			renderedStatus = 'completed';
		}
		return {
			row: t,
			status: renderedStatus,
			completedAt: renderedStatus === 'completed' ? t.completed_at ?? audit.completed_at : t.completed_at,
			synthesisedError: isStuck
				? `target stuck >${Math.floor(BRAND_AUDIT_TARGET_DEADLINE_MS / 60_000)}min in running; consumer cap did not flip status (read-path closure)`
				: null,
		};
	});

	// Fire-and-forget persistence of synthesised failures. We await each UPDATE
	// (single-row D1 writes are sub-50ms typically) so the next read by anyone
	// — customer, reaper, brand_audit_get_report — observes the corrected
	// state. We swallow throws because the response payload is the durability
	// contract for the polling customer; persistence catches up on subsequent
	// reads / the next reaper tick.
	if (deadZoneTargets.length > 0) {
		for (const t of deadZoneTargets) {
			try {
				await deps.db
					.prepare(
						"UPDATE brand_audit_targets SET status = 'failed', error = ?, completed_at = ? WHERE audit_id = ? AND target = ? AND status = 'running'",
					)
					.bind(
						`read-path: target stuck >${Math.floor(BRAND_AUDIT_TARGET_DEADLINE_MS / 60_000)}min; consumer cap did not flip status`,
						now,
						t.audit_id,
						t.target,
					)
					.run();
			} catch {
				// Best-effort — see comment above.
			}
		}
	}
	const targetStatusCounts = {
		queued: renderedTargets.filter((t) => t.status === 'queued').length,
		running: renderedTargets.filter((t) => t.status === 'running').length,
		completed: renderedTargets.filter((t) => t.status === 'completed').length,
		failed: renderedTargets.filter((t) => t.status === 'failed').length,
	};
	const ageMs = Math.max(0, now - audit.created_at);
	const updatedAgeMs = Math.max(0, now - audit.updated_at);
	const warnings: string[] = [];
	if (targetStatusCounts.queued > 0 && updatedAgeMs > 300_000) {
		warnings.push(`Audit has ${targetStatusCounts.queued} queued target(s) and has not updated for ${updatedAgeMs}ms.`);
	}
	const summary = createFinding(
		CATEGORY,
		`Brand audit ${auditId}: ${audit.status} (${progress})`,
		'info',
		`status=${audit.status} progress=${progress} format=${audit.format} created=${new Date(audit.created_at).toISOString()} updatedAgeMs=${updatedAgeMs}`,
		{
			summary: true,
			auditId: audit.id,
			status: audit.status,
			progress,
			completed: audit.completed_targets,
			total: audit.total_targets,
			format: audit.format,
			createdAt: audit.created_at,
			updatedAt: audit.updated_at,
			completedAt: audit.completed_at,
			ageMs,
			updatedAgeMs,
			targetStatusCounts,
			warnings,
			targets: renderedTargets.map(({ row, status, completedAt, synthesisedError }) => ({
				target: row.target,
				status,
				createdAt: row.created_at,
				completedAt,
				error: synthesisedError ?? row.error,
				hasPdf: row.pdf_r2_key !== null,
			})),
		},
	);

	return buildCheckResult(CATEGORY, [summary]);
}
