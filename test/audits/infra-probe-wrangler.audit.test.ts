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

	it('deploys the infra probe worker before the main MCP worker in releases', () => {
		const infraDeployIndex = publishWorkflowSource.indexOf('wrangler.infra-probe.jsonc');
		const mainDeployIndex = publishWorkflowSource.indexOf('wrangler.jsonc');

		expect(infraDeployIndex, 'publish.yml must deploy bv-infra-probe during releases').toBeGreaterThan(-1);
		expect(mainDeployIndex, 'publish.yml must deploy the main MCP worker during releases').toBeGreaterThan(-1);
		expect(infraDeployIndex, 'bv-infra-probe must deploy before the main service binding references it').toBeLessThan(
			mainDeployIndex,
		);
	});
});
