// SPDX-License-Identifier: BUSL-1.1

/**
 * Deep-scan queue-job wrapper.
 *
 * Reads the fast-stage cscComplement payload from the step-store, picks the
 * top-N apexes to deep-scan (anchor + registrarPortfolio.byFamily example
 * apexes + shadowItHighlights), invokes runDeepScan, merges the result back
 * into the step-store at key 'csc_complement_full' with status 'completed'.
 */

import { runDeepScan } from './brand-audit-csc-deepscan';
import type { BrandAuditCsc } from '../schemas/brand-audit-csc';
import type { BrandAuditStepStore } from './brand-audit-step-store';

const MAX_DEEPSCAN_APEXES = 25;

export interface RunDeepScanJobInput {
	auditId: string;
	target: string;
	stepStore: BrandAuditStepStore;
	internalCall: (tool: string, args: { domain: string }) => Promise<unknown>;
}

/**
 * Read fast-stage payload from step-store, run runDeepScan against top-N apexes
 * (deduped from byFamily example apexes + shadowIt highlights), merge result
 * into a 'csc_complement_full' step-store record.
 *
 * Idempotent: if csc_complement_fast is missing or not completed, returns
 * without doing anything. Caller (queue consumer) acks unconditionally.
 */
export async function runDeepScanFromStepStore(input: RunDeepScanJobInput): Promise<void> {
	const fast = await input.stepStore.get(input.auditId, input.target, 'csc_complement_fast');
	if (!fast || fast.status !== 'completed') return;
	const fastPayload = fast.payload as BrandAuditCsc;

	const apexSet = new Set<string>([fastPayload.anchor.apex]);
	for (const family of fastPayload.registrarPortfolio.byFamily) {
		for (const a of family.exampleApexes) apexSet.add(a);
	}
	for (const s of fastPayload.shadowItHighlights) apexSet.add(s.apex);
	const apexes = Array.from(apexSet).slice(0, MAX_DEEPSCAN_APEXES);

	const deepResult = await runDeepScan({
		anchorApex: fastPayload.anchor.apex,
		apexes,
		internalCall: input.internalCall,
	});

	const merged: BrandAuditCsc = {
		...fastPayload,
		postureSnapshot: deepResult.postureSnapshot,
		deepScan: deepResult.deepScan,
	};

	await input.stepStore.put({
		auditId: input.auditId,
		target: input.target,
		step: 'csc_complement_full',
		status: 'completed',
		payload: merged,
	});
}
