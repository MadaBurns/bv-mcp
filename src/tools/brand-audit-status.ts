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
					'SELECT audit_id, target, status, created_at, completed_at, error, pdf_r2_key FROM brand_audit_targets WHERE audit_id = ? ORDER BY created_at ASC, target ASC',
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
	const targetStatusCounts = {
		queued: targets.filter((t) => t.status === 'queued').length,
		running: targets.filter((t) => t.status === 'running').length,
		completed: targets.filter((t) => t.status === 'completed').length,
		failed: targets.filter((t) => t.status === 'failed').length,
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
			targets: targets.map((t) => ({
				target: t.target,
				status: t.status,
				createdAt: t.created_at,
				completedAt: t.completed_at,
				error: t.error,
				hasPdf: t.pdf_r2_key !== null,
			})),
		},
	);

	return buildCheckResult(CATEGORY, [summary]);
}
