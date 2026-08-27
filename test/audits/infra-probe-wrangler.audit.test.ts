// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import mainWranglerSource from '../../wrangler.jsonc?raw';
import infraProbeWranglerSource from '../../wrangler.infra-probe.jsonc?raw';
import whoisWranglerSource from '../../packages/bv-whois/wrangler.jsonc?raw';
import deployWorkflowSource from '../../.github/workflows/deploy-prod.yml?raw';

interface WranglerConfig {
	name?: string;
	compatibility_date?: string;
	workers_dev?: boolean;
	preview_urls?: boolean;
	services?: Array<{ binding?: string; service?: string }>;
}

const mainConfig = JSON.parse(mainWranglerSource) as WranglerConfig;
const infraProbeConfig = JSON.parse(infraProbeWranglerSource) as WranglerConfig;
const whoisConfig = JSON.parse(whoisWranglerSource) as WranglerConfig;

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

	it('keeps service-binding-only sidecars off public workers.dev and preview routes', () => {
		for (const config of [infraProbeConfig, whoisConfig]) {
			expect(config.workers_dev, `${config.name} must not expose a workers.dev route`).toBe(false);
			expect(config.preview_urls, `${config.name} must not expose preview URLs`).toBe(false);
		}
	});

	// Until #717/#718 this test pinned the infra-probe deploy INSIDE publish.yml's
	// `deploy-cloudflare` job, and asserted it sat after that job's `exit 1`
	// guard — i.e. it pinned a step that could never run, which is why the claim
	// "publish.yml deploys the probe worker before the main one" was false for as
	// long as it was written down. The step now lives on the one deploy path that
	// actually ships (deploy-prod.yml), so the ordering is a real invariant:
	// the main Worker's BV_INFRA_PROBE service binding targets `bv-infra-probe`
	// by name, so that Worker must exist before the binding can resolve.
	it('deploys the infra probe worker before the main Worker on the authoritative deploy path', () => {
		// Anchor on the `run:` step bodies, not bare command text — the file's
		// header comment also names `npm run deploy:prod`, and matching that
		// would compare a comment's position against a step's.
		const infraDeployIndex = deployWorkflowSource.indexOf('run: npx wrangler deploy -c wrangler.infra-probe.jsonc');
		const mainDeployIndex = deployWorkflowSource.indexOf('run: npm run deploy:prod');

		expect(infraDeployIndex, 'deploy-prod.yml must deploy the infra probe worker').toBeGreaterThan(-1);
		expect(mainDeployIndex, 'deploy-prod.yml must deploy the main Worker via deploy:prod').toBeGreaterThan(-1);
		expect(infraDeployIndex, 'the infra probe must be deployed BEFORE the Worker that binds to it').toBeLessThan(mainDeployIndex);
	});

	// The removed jobs were reachable-looking dead ends: `exit 1` as step one,
	// under `environment: production`, so each tag queued an approval that could
	// only fail. Re-adding one is a regression, not a rollback.
	it('keeps the fenced-off "CI deploy is not supported" stub out of the tree', () => {
		expect(deployWorkflowSource, 'deploy-prod.yml must be a real deploy, not a fenced-off stub').not.toContain(
			'CI deploy is not supported',
		);
	});
});
