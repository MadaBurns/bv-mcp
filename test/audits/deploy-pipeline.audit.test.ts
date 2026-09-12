// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import packageJsonSource from '../../package.json?raw';
import deployPrivateSource from '../../scripts/deploy-private.mjs?raw';
import injectScriptSource from '../../scripts/inject-private-config.cjs?raw';

interface PackageJson {
	scripts?: Record<string, string>;
}

const pkg = JSON.parse(packageJsonSource) as PackageJson;

describe('deploy:prod pipeline integrity', () => {
	const deployScript = pkg.scripts?.['deploy:prod'] ?? '';

	it('exposes a deploy:prod script', () => {
		expect(deployScript, 'package.json must define a deploy:prod script').not.toBe('');
	});

	// F2: deploy:prod must rebuild @blackveil/dns-checks before deploying so wrangler
	// never bundles a stale dist/ (previously caused a real prod ReferenceError).
	it('rebuilds @blackveil/dns-checks as part of deploy:prod', () => {
		expect(deployScript, 'deploy:prod must build the dns-checks package before deploying').toContain(
			'npm -w packages/dns-checks run build',
		);
	});

	it('builds dns-checks BEFORE running wrangler deploy', () => {
		const buildIndex = deployScript.indexOf('npm -w packages/dns-checks run build');
		const deployIndex = deployScript.indexOf('wrangler deploy');
		expect(buildIndex, 'deploy:prod must contain the dns-checks build step').toBeGreaterThan(-1);
		expect(deployIndex, 'deploy:prod must contain a wrangler deploy step').toBeGreaterThan(-1);
		expect(buildIndex, 'the dns-checks build must run before wrangler deploy').toBeLessThan(deployIndex);
	});

	// #945: deploy:prod deploys the MCP Worker ONLY. bv-whois and bv-infra-probe have
	// their own configs and their own deploy commands, and until this gate existed
	// nothing invoked them — both were months stale behind a fully green deploy.
	it('refuses production deployment until the sidecar Workers are proven current', () => {
		expect(deployScript, 'deploy:prod must run the sidecar deploy-drift gate').toContain('npm run check:sidecar-freshness');
	});

	it('runs the sidecar gate BEFORE wrangler deploy (and early, before the build)', () => {
		const sidecarIndex = deployScript.indexOf('npm run check:sidecar-freshness');
		const deployIndex = deployScript.indexOf('wrangler deploy');
		const buildIndex = deployScript.indexOf('npm -w packages/dns-checks run build');
		expect(sidecarIndex).toBeGreaterThan(-1);
		expect(sidecarIndex, 'the sidecar gate must run before wrangler deploy').toBeLessThan(deployIndex);
		// ~2s of wrangler reads; failing after a full dns-checks build wastes the
		// operator's time for no added signal.
		expect(sidecarIndex, 'the sidecar gate must fail before the dns-checks build').toBeLessThan(buildIndex);
	});

	it('exposes the deploy command the sidecar gate tells the operator to run', () => {
		// A gate that names a command package.json does not define is a dead end.
		expect(pkg.scripts?.['deploy:whois'] ?? '').toBe('npm -w packages/bv-whois run deploy');
		expect(pkg.scripts?.['deploy:infra-probe'] ?? '').toContain('wrangler.infra-probe.jsonc');
	});

	it('also gates the private deploy helper — the second door must not be a bypass', () => {
		const gateIndex = deployPrivateSource.indexOf('sidecar-deploy-drift-check.ts');
		const deployIndex = deployPrivateSource.indexOf("[wranglerCliPath, 'deploy'");
		expect(gateIndex, 'deploy-private.mjs must run the sidecar deploy-drift gate').toBeGreaterThan(-1);
		expect(gateIndex, 'the sidecar gate must run before wrangler deploy').toBeLessThan(deployIndex);
	});

	// #945 review: the sidecar gate's evidence is `git log HEAD -- <watchPaths>`, which can
	// only see commits that are ANCESTORS of HEAD. On a checkout behind origin/main a
	// sidecar commit that landed upstream but not locally is invisible, the drift list comes
	// back empty, and the gate reports `fresh` — a false green in a fail-closed gate. The
	// freshness check is what proves HEAD ⊇ origin/main, so it MUST precede the sidecar gate
	// on every door. deploy:prod / deploy:prod:staged get it from their npm chains; this door
	// runs it explicitly, and once did not.
	it('runs the freshness gate BEFORE the sidecar gate on the private door — HEAD-based drift evidence is worthless on a stale checkout', () => {
		const freshnessIndex = deployPrivateSource.indexOf('deploy-freshness-check.ts');
		const sidecarIndex = deployPrivateSource.indexOf('sidecar-deploy-drift-check.ts');
		expect(freshnessIndex, 'deploy-private.mjs must run the deploy-freshness gate').toBeGreaterThan(-1);
		expect(sidecarIndex, 'deploy-private.mjs must run the sidecar deploy-drift gate').toBeGreaterThan(-1);
		expect(freshnessIndex, 'freshness must prove HEAD ⊇ origin/main before the sidecar gate trusts `git log HEAD`').toBeLessThan(
			sidecarIndex,
		);
	});

	// Same ordering on the two npm doors, asserted from the scripts themselves so a
	// reordering of the chain cannot silently invert the dependency.
	it.each(['deploy:prod', 'deploy:prod:staged'])('runs the freshness gate before the sidecar gate in %s', (scriptName) => {
		const script = pkg.scripts?.[scriptName] ?? '';
		const freshnessIndex = script.indexOf('check:deploy-freshness');
		const sidecarIndex = script.indexOf('check:sidecar-freshness');
		expect(freshnessIndex, `${scriptName} must run check:deploy-freshness`).toBeGreaterThan(-1);
		expect(sidecarIndex, `${scriptName} must run check:sidecar-freshness`).toBeGreaterThan(-1);
		expect(freshnessIndex, 'freshness must precede the sidecar gate').toBeLessThan(sidecarIndex);
	});

	it('refuses production deployment until the remote Brand Audit schema preflight passes', () => {
		const preflightIndex = deployScript.indexOf('brand-audit-schema-preflight.mjs');
		const deployIndex = deployScript.indexOf('wrangler deploy');
		expect(preflightIndex).toBeGreaterThan(-1);
		expect(preflightIndex).toBeLessThan(deployIndex);
	});

	it('also gates the private deploy helper before its Wrangler deploy call', () => {
		const preflightIndex = deployPrivateSource.indexOf('brand-audit-schema-preflight.mjs');
		const deployIndex = deployPrivateSource.indexOf("[wranglerCliPath, 'deploy'");
		expect(preflightIndex).toBeGreaterThan(-1);
		expect(deployIndex).toBeGreaterThan(-1);
		expect(preflightIndex).toBeLessThan(deployIndex);
	});

	// The private overlay is a partial overlay, not a standalone config. Deploying it
	// directly drops the public base (routes, cron triggers, limits, tail consumers) AND
	// every fail-closed gate in the injector, which is how this door once deployed without
	// PROFILE_ACCUMULATOR. It must deploy the injected config instead.
	it('routes the private deploy helper through the config injector', () => {
		const injectIndex = deployPrivateSource.indexOf('scripts/inject-private-config.cjs');
		const deployIndex = deployPrivateSource.indexOf("[wranglerCliPath, 'deploy'");
		expect(injectIndex, 'deploy-private.mjs must run the injector').toBeGreaterThan(-1);
		expect(injectIndex, 'the injector must run before wrangler deploy').toBeLessThan(deployIndex);
	});

	it('never hands the raw private overlay to wrangler deploy', () => {
		const deployCall = deployPrivateSource.slice(deployPrivateSource.indexOf("[wranglerCliPath, 'deploy'"));
		expect(deployCall, 'the deploy call must use the generated production config').toContain('generatedConfigPath');
		expect(deployCall, 'deploying the overlay directly bypasses every injector gate').not.toContain('privateConfigPath');
	});

	// The staged path exists so a version can be smoke-tested before it takes traffic. It
	// is only safe if it carries the SAME gates — a staged path that skipped the dns-checks
	// rebuild or the schema preflight would upload a version those gates never vetted.
	describe('staged rollout path', () => {
		const stagedScript = pkg.scripts?.['deploy:prod:staged'] ?? '';

		it('runs every gate deploy:prod runs', () => {
			expect(stagedScript, 'package.json must define a deploy:prod:staged script').not.toBe('');
			for (const gate of [
				'npm run check:deploy-freshness',
				'npm run check:sidecar-freshness',
				'npm run check:release-integrity',
				'npm -w packages/dns-checks run build',
				'node scripts/inject-private-config.cjs',
				'brand-audit-schema-preflight.mjs',
				'npm run check:bindings:prod',
			]) {
				expect(stagedScript, `deploy:prod:staged must run the ${gate} gate`).toContain(gate);
			}
		});

		it('uploads a version instead of routing traffic to it', () => {
			expect(stagedScript, 'the staged path must upload a version, not deploy one').toContain('wrangler versions upload');
			expect(stagedScript, 'the staged path must not send traffic to the new version').not.toContain('wrangler deploy');
		});

		it('exposes the promote and trigger steps a version upload does not perform', () => {
			// `versions upload` deliberately leaves triggers alone, so cron/route changes need
			// an explicit `triggers deploy` — otherwise a staged rollout silently drops them.
			expect(pkg.scripts?.['deploy:prod:promote'] ?? '').toContain('wrangler versions deploy');
			expect(pkg.scripts?.['deploy:prod:triggers'] ?? '').toContain('wrangler triggers deploy');
		});
	});
});

describe('inject-private-config fail-closed on missing overlay', () => {
	// F3: a genuinely-absent private overlay must hard-fail the deploy (process.exit(1))
	// rather than `return` 0, which would let the `&&` chain proceed to wrangler against
	// a stale/wrong generated config (the silent-misconfigured-deploy class).
	// The missing-overlay branch is gated on !fs.existsSync(privateConfigPath) and
	// runs before the script reads/parses the overlay (parseJsonc(fs.readFileSync(privateConfigPath...)).
	function missingOverlayBranch(): string {
		const start = injectScriptSource.indexOf('existsSync(privateConfigPath)');
		const end = injectScriptSource.indexOf('parseJsonc(fs.readFileSync(privateConfigPath');
		expect(start, 'inject script must guard on existsSync(privateConfigPath)').toBeGreaterThan(-1);
		expect(end, 'inject script must parse the overlay after the guard').toBeGreaterThan(start);
		return injectScriptSource.slice(start, end);
	}

	it('hard-fails (process.exit(1)) when the private overlay is absent', () => {
		expect(missingOverlayBranch(), 'the missing-overlay branch must hard-fail rather than return 0').toContain('process.exit(1)');
	});

	it('does not silently `return` from the missing-overlay branch', () => {
		expect(missingOverlayBranch(), 'a bare return would let the deploy proceed against a stale config').not.toMatch(/\breturn\b/);
	});
});
