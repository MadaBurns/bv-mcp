// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import {
	buildBrandAuditBatchStartArgs,
	buildLocalDiscoveryOptions,
	parseReportGenerationEnv,
} from './helpers/report-generation-options';

describe('report generation option helpers', () => {
	it('passes planner mode through MCP and local discovery paths for benchmark runs', () => {
		const options = parseReportGenerationEnv({
			TARGET_DOMAIN: 'example.com',
			BV_BRAND_AUDIT_PLANNER_MODE: 'enforce',
		});

		expect(options.plannerMode).toBe('enforce');
		expect(buildBrandAuditBatchStartArgs('example.com', options)).toMatchObject({
			planner_mode: 'enforce',
		});
		expect(buildLocalDiscoveryOptions(options)).toMatchObject({
			planner_mode: 'enforce',
		});
	});

	it('defaults to enforce mode when BV_BRAND_AUDIT_PLANNER_MODE is unset', () => {
		// Locks in the post-chaos default flip. Reverting to 'observe' here is
		// a config regression that breaks benchmark reproducibility — keep the
		// orchestrator default ('enforce') and this helper default aligned.
		const options = parseReportGenerationEnv({ TARGET_DOMAIN: 'example.com' });
		expect(options.plannerMode).toBe('enforce');
		expect(buildBrandAuditBatchStartArgs('example.com', options)).toMatchObject({
			planner_mode: 'enforce',
		});
	});

	it('rejects unknown planner modes before starting report generation', () => {
		expect(() =>
			parseReportGenerationEnv({
				TARGET_DOMAIN: 'example.com',
				BV_BRAND_AUDIT_PLANNER_MODE: 'optimistic',
			}),
		).toThrow('BV_BRAND_AUDIT_PLANNER_MODE must be off, observe, or enforce');
	});

	it('threads BV_REPORT_DISCOVERY_MODE=tiered into batch-start and local discovery options', () => {
		// Wiring test for the replay script (`scripts/brand-discovery-tier-replay.mjs`):
		// when the env arrives as `tiered`, both the MCP request payload and the
		// local in-process discovery call must surface it. The schema enum on
		// `tool-args.ts` only accepts `'classic' | 'tiered'` — `baseline` is
		// pre-mapped to `classic` by the replay script before it spawns.
		const options = parseReportGenerationEnv({
			TARGET_DOMAIN: 'example.com',
			BV_REPORT_DISCOVERY_MODE: 'tiered',
		});
		expect(options.discoveryMode).toBe('tiered');
		expect(buildBrandAuditBatchStartArgs('example.com', options)).toMatchObject({
			discovery_mode: 'tiered',
		});
		expect(buildLocalDiscoveryOptions(options)).toMatchObject({
			discovery_mode: 'tiered',
		});
	});

	it('omits discovery_mode when BV_REPORT_DISCOVERY_MODE is unset (BSL invariance)', () => {
		const options = parseReportGenerationEnv({ TARGET_DOMAIN: 'example.com' });
		expect(options.discoveryMode).toBeUndefined();
		expect(buildBrandAuditBatchStartArgs('example.com', options)).not.toHaveProperty('discovery_mode');
		expect(buildLocalDiscoveryOptions(options)).not.toHaveProperty('discovery_mode');
	});

	it('rejects BV_REPORT_DISCOVERY_MODE values outside the schema enum', () => {
		// `baseline` is the replay-script alias, NOT a worker-visible value.
		// The replay script remaps it to `classic` BEFORE spawning the spec —
		// the spec's helper sees only `classic`/`tiered`. Any other value is
		// rejected here so the replay run fails fast instead of silently
		// dropping the override on the floor downstream.
		expect(() =>
			parseReportGenerationEnv({ TARGET_DOMAIN: 'example.com', BV_REPORT_DISCOVERY_MODE: 'baseline' }),
		).toThrow('BV_REPORT_DISCOVERY_MODE must be classic or tiered');
	});
});
