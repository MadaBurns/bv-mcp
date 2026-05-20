// SPDX-License-Identifier: BUSL-1.1

export type ReportDepthMode = 'standard' | 'deep';
export type ReportPlannerMode = 'off' | 'observe' | 'enforce';
/**
 * Discovery mode override surfaced as the `discovery_mode` arg on the MCP
 * call. Pairs with the schema enum in `src/schemas/tool-args.ts` — the
 * worker only accepts `'classic' | 'tiered'`. The replay script
 * (`scripts/brand-discovery-tier-replay.mjs`) pre-maps `baseline` → `classic`
 * before spawning the spec, so this helper never sees `baseline`.
 */
export type ReportDiscoveryMode = 'classic' | 'tiered';

export interface ReportGenerationOptions {
	depthMode: ReportDepthMode;
	plannerMode: ReportPlannerMode;
	brandAliases: string[];
	runId: string;
	requestedAt: string;
	/** Undefined → omit `discovery_mode` from the request (BSL invariance — schema default `'classic'` wins). */
	discoveryMode?: ReportDiscoveryMode;
}

export interface ReportGenerationEnv {
	BV_REPORT_DEPTH?: string;
	BV_BRAND_AUDIT_PLANNER_MODE?: string;
	BV_BRAND_ALIASES?: string;
	BV_REPORT_RUN_ID?: string;
	BV_REPORT_REQUESTED_AT?: string;
	TARGET_DOMAIN?: string;
	/**
	 * Discovery mode override emitted by
	 * `scripts/brand-discovery-tier-replay.mjs` to exercise tiered vs classic
	 * end-to-end. Must be `'classic'` or `'tiered'` — anything else fails fast
	 * so misconfigured runs don't silently fall back.
	 */
	BV_REPORT_DISCOVERY_MODE?: string;
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
	const rawPlannerMode = (env.BV_BRAND_AUDIT_PLANNER_MODE ?? 'observe').trim().toLowerCase();
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

	// BV_REPORT_DISCOVERY_MODE: optional override threaded through to the MCP
	// payload and the local discovery path. Validated against the worker's
	// schema enum (`src/schemas/tool-args.ts`: `'classic' | 'tiered'`) so the
	// replay run fails fast instead of dropping the value downstream. Anything
	// other than `classic`/`tiered` raises; unset → undefined → omitted from
	// both build paths (BSL invariance, schema default wins).
	let discoveryMode: ReportDiscoveryMode | undefined;
	const rawDiscoveryMode = env.BV_REPORT_DISCOVERY_MODE?.trim().toLowerCase();
	if (rawDiscoveryMode !== undefined && rawDiscoveryMode.length > 0) {
		if (rawDiscoveryMode !== 'classic' && rawDiscoveryMode !== 'tiered') {
			throw new Error(`BV_REPORT_DISCOVERY_MODE must be classic or tiered; received ${env.BV_REPORT_DISCOVERY_MODE}`);
		}
		discoveryMode = rawDiscoveryMode;
	}

	return {
		depthMode: rawDepth,
		plannerMode: rawPlannerMode,
		brandAliases,
		runId,
		requestedAt,
		...(discoveryMode ? { discoveryMode } : {}),
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
		// discovery_mode: surface only when explicitly set so BSL self-host
		// runs of the report script keep the schema default (`'classic'`).
		...(options.discoveryMode ? { discovery_mode: options.discoveryMode } : {}),
	};
}

export function buildLocalDiscoveryOptions(options: ReportGenerationOptions) {
	return {
		min_confidence: 0.1,
		depth: options.depthMode,
		planner_mode: options.plannerMode,
		...(options.brandAliases.length > 0 ? { brand_aliases: options.brandAliases } : {}),
		...(options.discoveryMode ? { discovery_mode: options.discoveryMode } : {}),
	};
}
