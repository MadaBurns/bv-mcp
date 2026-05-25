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

export async function osintInvestigationStatus(id: string, options: ReconToolOptions = {}): Promise<CheckResult> {
	const s = await callReconInvestigationStatus(options.reconBinding, options.reconAuthToken, id);
	if (!s) return unprovisioned(`Investigation status unavailable for ${id} (unprovisioned or not found).`);
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Investigation ${id}`, 'info', JSON.stringify(s).slice(0, 800), { ...s, summary: true, investigationId: id }),
	]) as CheckResult;
}

export async function osintInvestigationReport(id: string, options: ReconToolOptions = {}): Promise<CheckResult> {
	const r = await callReconInvestigationReport(options.reconBinding, options.reconAuthToken, id);
	if (!r) return unprovisioned(`Investigation report unavailable for ${id} (unprovisioned or not ready).`);
	return buildCheckResult(CATEGORY, [
		createFinding(CATEGORY, `Investigation ${id} report`, 'info', JSON.stringify(r).slice(0, 1200), { ...r, summary: true, investigationId: id }),
	]) as CheckResult;
}
