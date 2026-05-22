// SPDX-License-Identifier: BUSL-1.1

/**
 * brand_audit_single — synchronous brand-portfolio audit for a single target.
 *
 * Composes three existing pieces:
 *   1. `discoverBrandDomains` (with all 8 signals by default) — finds candidate
 *      domains plausibly related to the target.
 *   2. `checkRdapLookup` per candidate (concurrency=10) — populates registrar
 *      and registrant for the classifier.
 *   3. `classifyCandidate` — buckets each candidate into one of:
 *        consolidated | shadowIt | indeterminate | impersonation
 *      and stamps `relationshipType` so real off-primary registrar sprawl is
 *      separated from authorized vendor dependencies.
 *
 * Returns a `CheckResult` with one finding per candidate (bucket carried in
 * metadata + severity) plus a summary finding that aggregates per-bucket counts.
 *
 * Severity-by-bucket mapping (the audit's risk lens, not the discoverer's):
 *   consolidated   → info     (owned/operated by the brand — no action)
 *   indeterminate  → low      (insufficient evidence — review queue)
 *   shadowIt       → medium   (owned/controlled domain on off-primary registrar)
 *   impersonation  → high     (low confidence + no infra share — likely typo-squat)
 */

import { buildCheckResult, createFinding, type CheckResult } from '../lib/scoring';
import { runBrandAuditPipeline, type BrandAuditPipelineDeps, type BrandAuditPipelineOptions } from '../lib/brand-audit-pipeline';

/**
 * brand-audit findings emit under the existing `brand_discovery` category to
 * avoid adding a new CheckCategory to the scoring union. Adding one shifts the
 * hardening-tier denominator (every domain's perfect-pass score drops by 1)
 * for zero scoring benefit — this tool's value is the bucket classification,
 * not a score contribution. The bucket lives in `metadata.bucket`.
 */
const CATEGORY = 'brand_discovery';

export type BrandAuditSingleOptions = BrandAuditPipelineOptions;

/** Quota-check signature — the orchestrator calls this once per audit with `count=1`. */
export type EnforceBrandAuditQuota = (count: number) => Promise<{ allowed: boolean; remaining?: number; limit?: number; retryAfterMs?: number }>;

export interface BrandAuditSingleDeps extends BrandAuditPipelineDeps {
	enforceQuota?: EnforceBrandAuditQuota;
}

function buildAsyncHandoffResult(target: string, deadlineMs?: number): CheckResult {
	return {
		...buildCheckResult(CATEGORY, [
			createFinding(
				CATEGORY,
				'Brand audit requires async processing',
				'info',
				'This brand audit exceeded the synchronous MCP response budget. Use brand_audit_batch_start, then poll brand_audit_status and fetch the final report with brand_audit_get_report.',
				{
					asyncHandoff: true,
					timedOut: true,
					target,
					recommendedTool: 'brand_audit_batch_start',
					...(typeof deadlineMs === 'number' ? { deadlineMs } : {}),
				},
			),
		]),
		partial: true,
	} as CheckResult;
}

/**
 * Run a brand audit on a single target.
 *
 * Programmer-error throws (invalid seed domain) propagate from `discoverBrandDomains`.
 * Discovery failures surface as a `missingControl: true` summary finding with zero candidates.
 */
export async function brandAuditSingle(
	target: string,
	options: BrandAuditSingleOptions = {},
	deps: BrandAuditSingleDeps = {},
): Promise<CheckResult> {
	const enforce = deps.enforceQuota;
	if (enforce) {
		const verdict = await enforce(1);
		if (!verdict.allowed) {
			const retryHint = typeof verdict.retryAfterMs === 'number' ? ` retry after ${Math.ceil(verdict.retryAfterMs / 1000)}s` : '';
			return buildCheckResult(CATEGORY, [
				createFinding(
					CATEGORY,
					'Brand-audit quota exceeded',
					'high',
					`Monthly quota of ${verdict.limit ?? 0} targets reached for this principal.${retryHint}`,
					{ quotaExceeded: true, target, limit: verdict.limit ?? 0, remaining: verdict.remaining ?? 0, retryAfterMs: verdict.retryAfterMs },
				),
			]);
		}
	}

	if (options.timeoutBehavior === 'async_handoff' && typeof options.deadlineMs === 'number' && Number.isFinite(options.deadlineMs)) {
		const now = options.now ?? Date.now;
		const delayMs = Math.max(0, options.deadlineMs - now());
		const controller = options.signal ? null : new AbortController();
		const pipelineOptions = controller ? { ...options, signal: controller.signal } : options;
		let timeoutId: ReturnType<typeof setTimeout> | undefined;
		const timeout = new Promise<CheckResult>((resolve) => {
			timeoutId = setTimeout(() => {
				controller?.abort(new Error('brand_audit_single sync budget exhausted'));
				resolve(buildAsyncHandoffResult(target, options.deadlineMs));
			}, delayMs);
		});
		try {
			return await Promise.race([runBrandAuditPipeline(target, pipelineOptions, deps), timeout]);
		} finally {
			if (timeoutId) clearTimeout(timeoutId);
		}
	}

	return runBrandAuditPipeline(target, options, deps);
}
