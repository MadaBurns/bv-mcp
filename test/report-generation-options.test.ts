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
});
