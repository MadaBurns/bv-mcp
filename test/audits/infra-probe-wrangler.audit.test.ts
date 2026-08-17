// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import mainWranglerSource from '../../wrangler.jsonc?raw';
import infraProbeWranglerSource from '../../wrangler.infra-probe.jsonc?raw';
import publishWorkflowSource from '../../.github/workflows/publish.yml?raw';

interface WranglerConfig {
	name?: string;
	compatibility_date?: string;
	services?: Array<{ binding?: string; service?: string }>;
}

const mainConfig = JSON.parse(mainWranglerSource) as WranglerConfig;
const infraProbeConfig = JSON.parse(infraProbeWranglerSource) as WranglerConfig;

describe('infra probe wrangler wiring', () => {
	it('binds the main MCP worker to the infra probe worker', () => {
		expect(infraProbeConfig.name).toBe('bv-infra-probe');
		expect(mainConfig.services).toContainEqual({
			binding: 'BV_INFRA_PROBE',
			service: infraProbeConfig.name,
		});
	});

	it('keeps the infra probe worker on the same compatibility date as the MCP worker', () => {
		expect(infraProbeConfig.compatibility_date).toBe(mainConfig.compatibility_date);
	});

	it('keeps its legacy Cloudflare deploy steps fenced off in CI', () => {
		const guardIndex = publishWorkflowSource.indexOf('CI deploy is not supported');
		const exitIndex = publishWorkflowSource.indexOf('exit 1', guardIndex);
		const infraDeployIndex = publishWorkflowSource.indexOf('wrangler.infra-probe.jsonc');

		expect(guardIndex, 'publish.yml must declare the manual-deploy guard').toBeGreaterThan(-1);
		expect(exitIndex, 'the manual-deploy guard must fail the CI job').toBeGreaterThan(guardIndex);
		expect(infraDeployIndex, 'publish.yml must retain the legacy deploy sequence for auditability').toBeGreaterThan(exitIndex);
	});
});
