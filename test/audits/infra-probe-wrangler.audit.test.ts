// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import mainWranglerSource from '../../wrangler.jsonc?raw';
import whoisWranglerSource from '../../packages/bv-whois/wrangler.jsonc?raw';
import infraProbeCfConfigSource from '../../packages/bv-infra-probe/cloudflare.config.ts?raw';
import infraProbeWranglerToolingSource from '../../packages/bv-infra-probe/wrangler.config.ts?raw';
import whoisCfConfigSource from '../../packages/bv-whois/cloudflare.config.ts?raw';
import whoisWranglerToolingSource from '../../packages/bv-whois/wrangler.config.ts?raw';
import ctIndexWranglerSource from '../../packages/bv-ct-index/wrangler.jsonc?raw';
import ctIndexCfConfigSource from '../../packages/bv-ct-index/cloudflare.config.ts?raw';
import ctIndexWranglerToolingSource from '../../packages/bv-ct-index/wrangler.config.ts?raw';
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
	main?: string;
	routes?: unknown;
	route?: unknown;
	triggers?: { crons?: string[] };
	r2_buckets?: Array<{ binding?: string; bucket_name?: string }>;
	d1_databases?: Array<{ binding?: string; database_name?: string; database_id?: string }>;
	queues?: {
		producers?: Array<{ binding?: string; queue?: string }>;
		consumers?: Array<{ queue?: string; max_batch_size?: number; max_batch_timeout?: number; max_retries?: number }>;
	};
	secrets?: { required?: string[] };
}

const mainConfig = JSON.parse(mainWranglerSource) as WranglerConfig;
// bv-whois/wrangler.jsonc carries leading `//` comment lines (test-only config note), which JSON.parse rejects.
const whoisConfig = JSON.parse(whoisWranglerSource.replace(/^\s*\/\/.*$/gm, '')) as WranglerConfig;
const ctIndexConfig = JSON.parse(ctIndexWranglerSource.replace(/^\s*\/\/.*$/gm, '')) as WranglerConfig;

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

	// `deploy:ct-index` runs `cf deploy` from packages/bv-ct-index/. Same split as bv-whois: cloudflare.config.ts deploys,
	// wrangler.jsonc is the TEST-ONLY config, so the two must agree on everything that matters at runtime.
	describe('packages/bv-ct-index/cloudflare.config.ts (cf deploy) parity with wrangler.jsonc', () => {
		const src = ctIndexCfConfigSource;
		const one = (re: RegExp) => re.exec(src)?.slice(1) ?? [];
		const consumerSource = /\btriggers\.queue\((\{[^}]*\})\)/.exec(src)?.[1] ?? '';
		const consumerField = (field: string) => Number(new RegExp(`\\b${field}:\\s*(\\d+)`).exec(consumerSource)?.[1]);

		it('deploys exactly the Worker named bv-ct-index, as the test config does', () => {
			// US-12 hard constraint: deploy is upsert-by-name, so any other name would create or overwrite a different Worker.
			expect(one(/\bname:\s*['"]([^'"]+)['"]/)[0]).toBe('bv-ct-index');
			expect(ctIndexConfig.name).toBe('bv-ct-index');
		});

		it('keeps the compatibility date and flags of the test config and the MCP worker', () => {
			expect(one(/\bcompatibilityDate:\s*['"]([^'"]+)['"]/)[0]).toBe(ctIndexConfig.compatibility_date);
			expect(ctIndexConfig.compatibility_date).toBe(mainConfig.compatibility_date);
			const cfFlags = [...(one(/\bcompatibilityFlags:\s*\[([^\]]*)\]/)[0] ?? '').matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1]);
			expect(cfFlags).toEqual(ctIndexConfig.compatibility_flags);
		});

		it('runs the tailer cron every minute and the compactor hourly, in both configs', () => {
			const cfCrons = [...src.matchAll(/\btriggers\.scheduled\(\{\s*schedule:\s*['"]([^'"]+)['"]/g)].map((m) => m[1]);
			expect(ctIndexConfig.triggers?.crons).toEqual(['* * * * *', '17 * * * *']);
			expect(cfCrons).toEqual(ctIndexConfig.triggers?.crons);
		});

		it('binds the same R2 bucket, D1 database (same id) and queue producer as the test config', () => {
			expect(ctIndexConfig.r2_buckets).toEqual([{ binding: 'INDEX', bucket_name: 'bv-ct-index' }]);
			expect(one(/\bINDEX:\s*bindings\.r2\(\{\s*name:\s*['"]([^'"]+)['"]/)).toEqual(['bv-ct-index']);

			const d1 = ctIndexConfig.d1_databases ?? [];
			expect(d1).toHaveLength(1);
			expect(d1[0]?.binding).toBe('CURSORS');
			expect(d1[0]?.database_name).toBe('bv-ct-index-cursors');
			expect(one(/\bCURSORS:\s*bindings\.d1\(\{\s*name:\s*['"]([^'"]+)['"],\s*id:\s*['"]([^'"]+)['"]/)).toEqual([
				d1[0]?.database_name,
				d1[0]?.database_id,
			]);

			expect(ctIndexConfig.queues?.producers).toEqual([{ binding: 'ENTRIES', queue: 'bv-ct-index-entries' }]);
			expect(one(/\bENTRIES:\s*bindings\.queue\(\{\s*name:\s*['"]([^'"]+)['"]/)).toEqual(['bv-ct-index-entries']);
		});

		it('consumes its own queue with the same bounded batch settings as the test config', () => {
			const consumers = ctIndexConfig.queues?.consumers ?? [];
			expect(consumers).toHaveLength(1);
			const [consumer] = consumers;
			expect(consumer?.queue).toBe('bv-ct-index-entries');
			expect(one(/\btriggers\.queue\(\{\s*name:\s*['"]([^'"]+)['"]/)).toEqual([consumer?.queue]);
			expect(consumer?.max_batch_size).toBeGreaterThan(0);
			expect(consumer?.max_batch_timeout).toBeGreaterThan(0);
			expect(consumerField('maxBatchSize')).toBe(consumer?.max_batch_size);
			expect(consumerField('maxBatchTimeout')).toBe(consumer?.max_batch_timeout);
			expect(consumerField('maxRetries')).toBe(consumer?.max_retries);
		});

		it('requires the CT_INDEX_ADMIN_KEY secret in both configs', () => {
			expect(ctIndexConfig.secrets?.required).toEqual(['CT_INDEX_ADMIN_KEY']);
			expect(src).toMatch(/\bCT_INDEX_ADMIN_KEY:\s*bindings\.secret\(\)/);
		});

		it('stays off workers.dev, preview URLs and routes', () => {
			expect(ctIndexConfig.workers_dev).toBe(false);
			expect(ctIndexConfig.preview_urls).toBe(false);
			expect(ctIndexConfig.routes).toBeUndefined();
			expect(ctIndexConfig.route).toBeUndefined();
			expect(src).toMatch(/\bworkersDev:\s*false\b/);
			expect(src).toMatch(/\bpreviewUrls:\s*false\b/);
			expect(src).not.toMatch(/\b(routes|domains)\s*:/);
		});

		it('points at the same entry as the test config', () => {
			expect(ctIndexConfig.main).toBe('src/index.ts');
			expect(src).toMatch(/\bentrypoint:\s*['"]src\/index\.ts['"]/);
		});

		it('uploads source maps via the wrangler tooling config', () => {
			expect(ctIndexWranglerToolingSource).toMatch(/\buploadSourceMaps:\s*true\b/);
		});

		// Same constraint as bv-whois: cf finds wrangler only at <package>/node_modules/wrangler.
		it('keeps a nested wrangler install so cf can discover it', () => {
			expect(packageLockSource).toContain('"packages/bv-ct-index/node_modules/wrangler"');
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
