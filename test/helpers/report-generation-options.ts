// SPDX-License-Identifier: BUSL-1.1

export type ReportDepthMode = 'standard' | 'deep';
export type ReportPlannerMode = 'off' | 'observe' | 'enforce';

export interface ReportGenerationOptions {
	depthMode: ReportDepthMode;
	plannerMode: ReportPlannerMode;
	brandAliases: string[];
	runId: string;
	requestedAt: string;
}

export interface ReportGenerationEnv {
	BV_REPORT_DEPTH?: string;
	BV_BRAND_AUDIT_PLANNER_MODE?: string;
	BV_BRAND_ALIASES?: string;
	BV_REPORT_RUN_ID?: string;
	BV_REPORT_REQUESTED_AT?: string;
	TARGET_DOMAIN?: string;
}

function normalizeAlias(alias: string): string | null {
	const normalized = alias.trim().toLowerCase().replace(/\s+/g, ' ');
	if (normalized.length < 2 || normalized.length > 64) return null;
	if (!/^[a-z0-9][a-z0-9 -]*[a-z0-9]$/.test(normalized)) return null;
	return normalized;
}

export function parseReportGenerationEnv(env: ReportGenerationEnv = process.env): ReportGenerationOptions {
	const rawDepth = (env.BV_REPORT_DEPTH ?? 'deep').trim().toLowerCase();
	if (rawDepth !== 'standard' && rawDepth !== 'deep') {
		throw new Error(`BV_REPORT_DEPTH must be standard or deep; received ${env.BV_REPORT_DEPTH}`);
	}
	const rawPlannerMode = (env.BV_BRAND_AUDIT_PLANNER_MODE ?? 'enforce').trim().toLowerCase();
	if (rawPlannerMode !== 'off' && rawPlannerMode !== 'observe' && rawPlannerMode !== 'enforce') {
		throw new Error(`BV_BRAND_AUDIT_PLANNER_MODE must be off, observe, or enforce; received ${env.BV_BRAND_AUDIT_PLANNER_MODE}`);
	}

	const seen = new Set<string>();
	const brandAliases: string[] = [];
	for (const rawAlias of (env.BV_BRAND_ALIASES ?? '').split(',')) {
		const alias = normalizeAlias(rawAlias);
		if (!alias || seen.has(alias)) continue;
		seen.add(alias);
		brandAliases.push(alias);
	}

	const requestedAt = env.BV_REPORT_REQUESTED_AT ?? new Date().toISOString();
	const runId = env.BV_REPORT_RUN_ID ?? `report-${Date.now().toString(36)}`;
	return {
		depthMode: rawDepth,
		plannerMode: rawPlannerMode,
		brandAliases,
		runId,
		requestedAt,
	};
}

export function buildBrandAuditBatchStartArgs(target: string, options: ReportGenerationOptions) {
	return {
		domains: [target],
		min_confidence: 0.1,
		format: 'json' as const,
		depth: options.depthMode,
		planner_mode: options.plannerMode,
		...(options.brandAliases.length > 0 ? { brand_aliases: options.brandAliases } : {}),
	};
}

export function buildLocalDiscoveryOptions(options: ReportGenerationOptions) {
	return {
		min_confidence: 0.1,
		depth: options.depthMode,
		planner_mode: options.plannerMode,
		...(options.brandAliases.length > 0 ? { brand_aliases: options.brandAliases } : {}),
	};
}
