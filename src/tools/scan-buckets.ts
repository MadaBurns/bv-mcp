// SPDX-License-Identifier: BUSL-1.1
/** Cloud-bucket discovery tools — thin fail-soft proxies over bv-recon's bucket-scanner. */
import { buildCheckResult, createFinding } from '../lib/scoring';
import type { CheckResult, CheckCategory } from '../lib/scoring';
import { callReconBucketScanStart, callReconBucketScanStatus, callReconBucketFindings, type ReconBinding } from '../lib/recon-binding';
import { sanitizeUpstreamObject, sanitizeUpstreamValue } from '../lib/sanitize-upstream';

const CATEGORY = 'bucket_scan' as CheckCategory;

export interface ReconToolOptions {
	reconBinding?: ReconBinding;
	reconAuthToken?: string;
}

function unprovisioned(detail: string): CheckResult {
	return buildCheckResult(CATEGORY, [createFinding(CATEGORY, 'Bucket scanning unavailable', 'info', detail, { unprovisioned: true })]) as CheckResult;
}

export async function scanBucketsStart(args: { target: string; providers?: string[] }, options: ReconToolOptions = {}): Promise<CheckResult> {
	const started = await callReconBucketScanStart(options.reconBinding, options.reconAuthToken, { target: args.target, providers: args.providers });
	if (!started) return unprovisioned(`Bucket discovery is not provisioned in this deployment for ${args.target}.`);
	return buildCheckResult(CATEGORY, [
		createFinding(
			CATEGORY,
			'Bucket scan started',
			'info',
			`Bucket discovery started for ${args.target} (scanId ${started.scanId}). Poll with scan_buckets_status.`,
			{
				// F7: sanitize all upstream values; explicit keys below must use the
				// sanitized forms too, else they re-introduce raw upstream into metadata.
				...sanitizeUpstreamObject(started),
				scanId: sanitizeUpstreamValue(started.scanId),
				status: sanitizeUpstreamValue(started.status ?? 'running'),
				pollWith: 'scan_buckets_status',
			},
		),
	]) as CheckResult;
}

export async function scanBucketsStatus(args: { scanId: string }, options: ReconToolOptions = {}): Promise<CheckResult> {
	const s = await callReconBucketScanStatus(options.reconBinding, options.reconAuthToken, args.scanId);
	if (!s) return unprovisioned(`Bucket scan status is unavailable for ${args.scanId} (unprovisioned or not found).`);
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Bucket scan ${args.scanId}`, 'info', JSON.stringify(s).slice(0, 800), {
			...sanitizeUpstreamObject(s), // F7: sanitize opaque upstream payload
			summary: true,
			scanId: args.scanId, // caller input (already validated) — safe
		}),
	]) as CheckResult;
}

export async function scanBucketsFindings(args: { scanId?: string }, options: ReconToolOptions = {}): Promise<CheckResult> {
	const f = await callReconBucketFindings(options.reconBinding, options.reconAuthToken, args.scanId);
	if (!f) return unprovisioned('Bucket findings are unavailable (unprovisioned or no scan).');
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, 'Bucket findings', 'info', JSON.stringify(f).slice(0, 800), {
			...sanitizeUpstreamObject(f), // F7: sanitize opaque upstream payload
			summary: true,
		}),
	]) as CheckResult;
}
