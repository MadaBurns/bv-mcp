// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import mainWranglerSource from '../../wrangler.jsonc?raw';
import whoisWranglerSource from '../../packages/bv-whois/wrangler.jsonc?raw';
import infraProbeCfConfigSource from '../../packages/bv-infra-probe/cloudflare.config.ts?raw';
import infraProbeWranglerToolingSource from '../../packages/bv-infra-probe/wrangler.config.ts?raw';
import whoisCfConfigSource from '../../packages/bv-whois/cloudflare.config.ts?raw';
import whoisWranglerToolingSource from '../../packages/bv-whois/wrangler.config.ts?raw';
import packageLockSource from '../../package-lock.json?raw';
import deployWorkflowSource from '../../.github/workflows/deploy-prod.yml?raw';

interface WranglerConfig {
	name?: string;
	compatibility_date?: string;
	compatibility_flags?: string[];
	workers_dev?: boolean;
	preview_urls?: boolean;
	services?: Array<{ binding?: string; service?: string }>;
	kv_namespaces?: Array<{ binding?: string; id?: string }>;
}

const mainConfig = JSON.parse(mainWranglerSource) as WranglerConfig;
// bv-whois/wrangler.jsonc carries leading `//` comment lines (test-only config note), which JSON.parse rejects.
const whoisConfig = JSON.parse(whoisWranglerSource.replace(/^\s*\/\/.*$/gm, '')) as WranglerConfig;

describe('infra probe wrangler wiring', () => {
	it('keeps the bv-whois sidecar off public workers.dev and preview routes', () => {
		expect(whoisConfig.workers_dev, `${whoisConfig.name} must not expose a workers.dev route`).toBe(false);
		expect(whoisConfig.preview_urls, `${whoisConfig.name} must not expose preview URLs`).toBe(false);
	});

	// `deploy:infra-probe` runs `cf deploy` from packages/bv-infra-probe/ (config only — the entry stays in
	// src/). This TS config is the single source of truth for the Worker now that the root
	// wrangler.infra-probe.jsonc is retired (SQ-240); the sidecar drift gate reads it via an explicit
	// `--name` pinned in scripts/sidecar-deploy-drift.ts and audited against `name` here.
	describe('packages/bv-infra-probe/cloudflare.config.ts (cf deploy)', () => {
		const cfName = /\bname:\s*['"]([^'"]+)['"]/.exec(infraProbeCfConfigSource)?.[1];
		const cfCompatibilityDate = /\bcompatibilityDate:\s*['"]([^'"]+)['"]/.exec(infraProbeCfConfigSource)?.[1];

		it('deploys the Worker the main MCP worker binds BV_INFRA_PROBE to', () => {
			expect(cfName).toBe('bv-infra-probe');
			expect(mainConfig.services).toContainEqual({ binding: 'BV_INFRA_PROBE', service: cfName });
		});

		it('keeps the same compatibility date as the MCP worker', () => {
			expect(cfCompatibilityDate).toBe(mainConfig.compatibility_date);
		});

		it('stays off public workers.dev and preview routes', () => {
			expect(infraProbeCfConfigSource).toMatch(/\bworkersDev:\s*false\b/);
			expect(infraProbeCfConfigSource).toMatch(/\bpreviewUrls:\s*false\b/);
		});

		it('declares no bindings or triggers (the probe is called only via the service binding, with no cron)', () => {
			expect(infraProbeCfConfigSource).not.toMatch(/\bbindings\./);
			expect(infraProbeCfConfigSource).not.toMatch(/\btriggers\./);
			// Raw-object-literal form: cf's schema keeps bindings under `env:` and triggers under `triggers:`.
			expect(infraProbeCfConfigSource).not.toMatch(/\benv\s*:/);
			expect(infraProbeCfConfigSource).not.toMatch(/\btriggers\s*:/);
		});

		it('points at the entry that stays in the main Worker tree', () => {
			expect(infraProbeCfConfigSource).toMatch(/\bentrypoint:\s*['"]\.\.\/\.\.\/src\/workers\/infra-probe\.ts['"]/);
		});

		it('uploads source maps via the wrangler tooling config', () => {
			expect(infraProbeWranglerToolingSource).toMatch(/\buploadSourceMaps:\s*true\b/);
		});

		// cf discovers wrangler ONLY at <package>/node_modules/wrangler (no upward resolution). npm hoists a
		// wrangler that satisfies the root's version to the root, so this package pins a version the root does not
		// hold; if a bump makes it match, it re-hoists and `cf build` fails with "wrangler ... is not installed".
		it('keeps a nested wrangler install so cf can discover it', () => {
			expect(packageLockSource).toContain('"packages/bv-infra-probe/node_modules/wrangler"');
		});
	});

	// `deploy:whois` runs `cf deploy` from packages/bv-whois/. cloudflare.config.ts is the deploy config; wrangler.jsonc stays
	// as the TEST-ONLY config (cloudflareTest cannot load a cf config), so the two must agree on everything that matters at runtime.
	describe('packages/bv-whois/cloudflare.config.ts (cf deploy) parity with wrangler.jsonc', () => {
		const cfName = /\bname:\s*['"]([^'"]+)['"]/.exec(whoisCfConfigSource)?.[1];
		const cfCompatibilityDate = /\bcompatibilityDate:\s*['"]([^'"]+)['"]/.exec(whoisCfConfigSource)?.[1];
		const cfFlags = [...(/\bcompatibilityFlags:\s*\[([^\]]*)\]/.exec(whoisCfConfigSource)?.[1] ?? '').matchAll(/['"]([^'"]+)['"]/g)].map(
			(m) => m[1],
		);
		const cfKv = /\b(\w+):\s*bindings\.kv\(\s*\{\s*id:\s*['"]([^'"]+)['"]/.exec(whoisCfConfigSource);
		const jsoncKv = whoisConfig.kv_namespaces?.[0];

		it('deploys the same Worker name as the test config', () => {
			expect(cfName).toBe('bv-whois');
			expect(cfName).toBe(whoisConfig.name);
		});

		it('keeps the same compatibility date as the test config and the MCP worker', () => {
			expect(cfCompatibilityDate).toBe(whoisConfig.compatibility_date);
			expect(cfCompatibilityDate).toBe(mainConfig.compatibility_date);
		});

		it('carries both compatibility flags of the test config', () => {
			expect(whoisConfig.compatibility_flags).toEqual(expect.arrayContaining(['global_fetch_strictly_public', 'nodejs_compat']));
			expect([...cfFlags].sort()).toEqual([...(whoisConfig.compatibility_flags ?? [])].sort());
		});

		it('declares the WHOIS_CACHE KV binding with the same id as the test config', () => {
			expect(whoisConfig.kv_namespaces).toHaveLength(1);
			expect(jsoncKv?.binding).toBe('WHOIS_CACHE');
			expect(cfKv?.[1]).toBe(jsoncKv?.binding);
			expect(cfKv?.[2]).toBe(jsoncKv?.id);
		});

		it('stays off public workers.dev and preview routes', () => {
			expect(whoisCfConfigSource).toMatch(/\bworkersDev:\s*false\b/);
			expect(whoisCfConfigSource).toMatch(/\bpreviewUrls:\s*false\b/);
		});

		it('points at the same entry as the test config', () => {
			expect(whoisCfConfigSource).toMatch(/\bentrypoint:\s*['"]src\/index\.ts['"]/);
		});

		it('uploads source maps via the wrangler tooling config', () => {
			expect(whoisWranglerToolingSource).toMatch(/\buploadSourceMaps:\s*true\b/);
		});

		// Same constraint as bv-infra-probe: cf finds wrangler only at <package>/node_modules/wrangler.
		it('keeps a nested wrangler install so cf can discover it', () => {
			expect(packageLockSource).toContain('"packages/bv-whois/node_modules/wrangler"');
		});
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
		const infraDeployIndex = deployWorkflowSource.indexOf('run: npm run deploy:infra-probe');
		const mainDeployIndex = deployWorkflowSource.indexOf('run: npm run deploy:prod');

		expect(infraDeployIndex, 'deploy-prod.yml must deploy the infra probe worker via the gated npm script').toBeGreaterThan(-1);
		expect(mainDeployIndex, 'deploy-prod.yml must deploy the main Worker via deploy:prod').toBeGreaterThan(-1);
		expect(infraDeployIndex, 'the infra probe must be deployed BEFORE the Worker that binds to it').toBeLessThan(mainDeployIndex);
	});

	it('does not ship the infra probe worker via a raw wrangler call, bypassing the gated npm script', () => {
		expect(deployWorkflowSource, 'deploy-prod.yml must use npm run deploy:infra-probe, not a bare wrangler deploy').not.toContain(
			'run: npx wrangler deploy -c wrangler.infra-probe.jsonc',
		);
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
