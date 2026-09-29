// SPDX-License-Identifier: BUSL-1.1

/**
 * Every `deploy:*` script that bundles a Worker importing `@blackveil/dns-checks`
 * must BUILD that package first (#1115).
 *
 * `@blackveil/dns-checks` is an in-repo workspace whose `dist/` is a build
 * output. On a fresh release worktree (`git worktree add … vX.Y.Z && npm ci`)
 * there is no `dist/`, so wrangler fails with `Could not resolve
 * "@blackveil/dns-checks/whois"`. The main checkout hid this for months because
 * an earlier `npm run build` had left `dist/` behind.
 *
 * The importer set is DERIVED from source, not hard-coded: each deploy script's
 * wrangler config names its `main`, and this spec walks the static + dynamic
 * import graph from there. A sidecar that starts importing the package
 * transitively (bv-infra-probe does, via src/lib/dns.ts → dns-transport.ts)
 * fails here without anyone having to remember to list it.
 *
 * Runs in the Workers pool, which has no filesystem — sources arrive via
 * `import.meta.glob(…, '?raw')`, the same mechanism the chokepoint audits use.
 */

import { describe, expect, it } from 'vitest';
import packageJsonRaw from '../package.json?raw';

const SOURCES = {
	...(import.meta.glob('../src/**/*.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
	...(import.meta.glob('../packages/*/src/**/*.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
};

const WRANGLER_CONFIGS = {
	...(import.meta.glob('../wrangler*.jsonc', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
	...(import.meta.glob('../packages/*/wrangler.jsonc', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
	// `cf migrate` packages (bv-infra-probe) carry their entry in cloudflare.config.ts, not a wrangler jsonc.
	...(import.meta.glob('../packages/*/cloudflare.config.ts', { query: '?raw', import: 'default', eager: true }) as Record<string, string>),
};

const PACKAGE = '@blackveil/dns-checks';
const BUILD_STEP = 'npm -w packages/dns-checks run build';

/**
 * `wrangler.production.jsonc` is generated at deploy time by
 * scripts/inject-private-config.cjs from the public `wrangler.jsonc` (which owns
 * `main`), so it is never on disk to glob.
 */
const GENERATED_CONFIG_SOURCE: Record<string, string> = { 'wrangler.production.jsonc': 'wrangler.jsonc' };

const scripts = (JSON.parse(packageJsonRaw) as { scripts: Record<string, string> }).scripts;

function dirname(path: string): string {
	const i = path.lastIndexOf('/');
	return i === -1 ? '' : path.slice(0, i);
}

/** Normalises `a/b/../c/./d` to `a/c/d`, keeping leading `..` segments. */
function normalise(path: string): string {
	const out: string[] = [];
	for (const seg of path.split('/')) {
		if (seg === '.' || seg === '') continue;
		if (seg === '..' && out.length > 0 && out[out.length - 1] !== '..') out.pop();
		else out.push(seg);
	}
	return out.join('/');
}

/** Value imports only — `import type` / `export type` are erased and never bundled. */
function importSpecifiers(source: string): string[] {
	const specs: string[] = [];
	const staticRe = /^\s*(?:import|export)\s+(?!type\b)(?:[\s\S]*?\sfrom\s+)?['"]([^'"]+)['"]/gm;
	const dynamicRe = /\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;
	for (const re of [staticRe, dynamicRe]) {
		for (const m of source.matchAll(re)) specs.push(m[1]!);
	}
	return specs;
}

function resolveRelative(from: string, spec: string, sources: Record<string, string>): string | null {
	const base = normalise(`${dirname(from)}/${spec}`);
	const candidates = [base, `${base}.ts`, `${base}/index.ts`, base.replace(/\.js$/, '.ts')];
	// Glob keys keep their leading `../` (relative to test/).
	return candidates.map((c) => `../${c.replace(/^\.\.\//, '')}`).find((c) => c in sources) ?? null;
}

/** True when `entry` reaches `@blackveil/dns-checks` (any subpath) through value imports. */
export function reachesPackage(entry: string, sources: Record<string, string>, pkg = PACKAGE): boolean {
	const seen = new Set<string>();
	const stack = [entry];
	while (stack.length > 0) {
		const file = stack.pop()!;
		if (seen.has(file)) continue;
		seen.add(file);
		for (const spec of importSpecifiers(sources[file] ?? '')) {
			if (spec === pkg || spec.startsWith(`${pkg}/`)) return true;
			if (!spec.startsWith('.')) continue;
			const next = resolveRelative(file, spec, sources);
			if (next) stack.push(next);
		}
	}
	return false;
}

/** Each `&&` step of a script that bundles a Worker, mapped to the wrangler config it bundles. */
function bundledConfigs(script: string): { step: number; config: string }[] {
	const out: { step: number; config: string }[] = [];
	script.split('&&').forEach((raw, step) => {
		const seg = raw.trim();
		const workspace = /^npm -w (packages\/[^\s]+) run deploy\b/.exec(seg);
		if (workspace) {
			out.push({ step, config: `${workspace[1]}/wrangler.jsonc` });
			return;
		}
		if (/\bwrangler (?:deploy|versions upload)\b/.test(seg)) {
			const cfg = /--config\s+(\S+)/.exec(seg)?.[1] ?? 'wrangler.jsonc';
			out.push({ step, config: GENERATED_CONFIG_SOURCE[cfg] ?? cfg });
		}
	});
	return out;
}

/** Violations: bundling steps whose entry imports the package with no prior build step. */
export function missingBuild(script: string, entryFor: (config: string) => string, sources: Record<string, string>): string[] {
	const steps = script.split('&&').map((s) => s.trim());
	const buildAt = steps.findIndex((s) => s === BUILD_STEP);
	return bundledConfigs(script)
		.filter(({ config }) => reachesPackage(entryFor(config), sources))
		.filter(({ step }) => buildAt === -1 || buildAt > step)
		.map(({ config }) => config);
}

function entryFor(config: string): string {
	// `packages/X/wrangler.jsonc` is the config id bundledConfigs derives from `npm -w packages/X run deploy`;
	// a `cf migrate` package has `packages/X/cloudflare.config.ts` instead, whose entry key is `entrypoint`.
	const raw = WRANGLER_CONFIGS[`../${config}`] ?? WRANGLER_CONFIGS[`../${dirname(config)}/cloudflare.config.ts`];
	if (raw === undefined) throw new Error(`wrangler config not found: ${config}`);
	const main = /"main"\s*:\s*"([^"]+)"/.exec(raw)?.[1] ?? /\bentrypoint\s*:\s*['"]([^'"]+)['"]/.exec(raw)?.[1];
	if (!main) throw new Error(`no "main" or "entrypoint" in ${config}`);
	return `../${normalise(`${dirname(config)}/${main}`)}`;
}

const DEPLOY_SCRIPTS = Object.entries(scripts).filter(([name]) => name.startsWith('deploy:'));

describe('deploy scripts build @blackveil/dns-checks before bundling an importer (#1115)', () => {
	it('positive control: the globs see worker sources and configs', () => {
		expect(Object.keys(SOURCES).length).toBeGreaterThan(50);
		expect(SOURCES['../packages/bv-whois/src/index.ts']).toBeDefined();
		expect(Object.keys(WRANGLER_CONFIGS)).toEqual(
			expect.arrayContaining([
				'../wrangler.jsonc',
				'../wrangler.infra-probe.jsonc',
				'../packages/bv-whois/wrangler.jsonc',
				'../packages/bv-infra-probe/cloudflare.config.ts',
			]),
		);
		// The cf-migrated package resolves to the root-tree entry it points at, and that entry reaches dns-checks.
		expect(entryFor('packages/bv-infra-probe/wrangler.jsonc')).toBe('../src/workers/infra-probe.ts');
		expect(reachesPackage('../src/workers/infra-probe.ts', SOURCES)).toBe(true);
	});

	it('every bundling deploy script resolves to an entry file that exists', () => {
		const bundling = DEPLOY_SCRIPTS.filter(([, s]) => bundledConfigs(s).length > 0).map(([n]) => n);
		expect(bundling).toEqual(expect.arrayContaining(['deploy:prod', 'deploy:whois', 'deploy:infra-probe']));
		for (const [, script] of DEPLOY_SCRIPTS) {
			for (const { config } of bundledConfigs(script)) expect(SOURCES[entryFor(config)], config).toBeDefined();
		}
	});

	it('the import walk discriminates: bv-whois reaches the package, a leaf module does not', () => {
		expect(reachesPackage('../packages/bv-whois/src/index.ts', SOURCES)).toBe(true);
		expect(reachesPackage('../src/lib/request-body.ts', SOURCES)).toBe(false);
		const fixture = {
			'../a.ts': "import type { X } from '@blackveil/dns-checks';\nimport { y } from './b';",
			'../b.ts': 'export const y = 1;',
		};
		expect(reachesPackage('../a.ts', fixture)).toBe(false);
		fixture['../b.ts'] = "export { z } from '@blackveil/dns-checks/whois';";
		expect(reachesPackage('../a.ts', fixture)).toBe(true);
	});

	it('the ordering rule discriminates: a build AFTER the bundle step does not count', () => {
		const fixture = { '../packages/w/src/index.ts': "import { p } from '@blackveil/dns-checks/whois';" };
		const entry = () => '../packages/w/src/index.ts';
		expect(missingBuild(`npm -w packages/w run deploy`, entry, fixture)).toEqual(['packages/w/wrangler.jsonc']);
		expect(missingBuild(`npm -w packages/w run deploy && ${BUILD_STEP}`, entry, fixture)).toEqual(['packages/w/wrangler.jsonc']);
		expect(missingBuild(`${BUILD_STEP} && npm -w packages/w run deploy`, entry, fixture)).toEqual([]);
	});

	it.each(DEPLOY_SCRIPTS)('%s builds @blackveil/dns-checks before bundling any importer', (_name, script) => {
		expect(missingBuild(script, entryFor, SOURCES)).toEqual([]);
	});
});
