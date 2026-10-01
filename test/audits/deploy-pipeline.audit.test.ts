// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import deployProdWorkflowSource from '../../.github/workflows/deploy-prod.yml?raw';
import cfPackageJsonSource from '../../packages/bv-dns-security-mcp/package.json?raw';
import packageJsonSource from '../../package.json?raw';
import deployPrivateSource from '../../scripts/deploy-private.mjs?raw';
import promoteSource from '../../scripts/deploy-prod-promote.mjs?raw';
import injectScriptSource from '../../scripts/inject-private-config.cjs?raw';

interface PackageJson {
	scripts?: Record<string, string>;
}

const pkg = JSON.parse(packageJsonSource) as PackageJson;
const cfPkg = JSON.parse(cfPackageJsonSource) as PackageJson;

// Phase 5 (US-8): the main Worker ships through `cf`, run from the config-only workspace package
// packages/bv-dns-security-mcp (cf refuses to build at an npm workspace root). The root scripts keep every
// gate and END by handing off to that package's script, which hard-codes `--mode production`: a bare
// `cf deploy` silently ships the public-only config shape (cloudflare.config.ts names that shape
// bv-dns-security-mcp-dev so a forgotten flag cannot strip production's private bindings), so the mode must be
// in the script text and never left to the caller.
const CF_PACKAGE_RUN = 'npm -w packages/bv-dns-security-mcp run';
/** The final step of deploy:prod / deploy:prod:staged. (?![\w:-]) keeps `run deploy` from matching `run deploy:staged`. */
const SHIP_STEP = /npm -w packages\/bv-dns-security-mcp run deploy(:staged)?(?![\w:-])/;
/** Every gate in front of the ship step, in order. Unchanged by Phase 5: only the ship step moved to cf. */
const GATES_BEFORE_SHIP = [
	'npm run check:deploy-freshness',
	'npm run check:sidecar-freshness',
	'npm run check:release-integrity',
	'npm -w packages/dns-checks run build',
	'npm run check:bindings',
	'node scripts/inject-private-config.cjs',
	'node scripts/brand-audit-schema-preflight.mjs --config wrangler.production.jsonc',
	'node scripts/access-log-schema-preflight.mjs --config wrangler.production.jsonc',
	'npm run check:bindings:prod',
];
/** Every cf script in the config package starts with this overlay-env guard (see the BV_DEPLOY_OVERLAY_PATH test below). */
const OVERLAY_GUARD = 'npm run guard:overlay-env && ';
/** deploy-private.mjs's cf spawn: marker used to locate the ship step in its source. */
const PRIVATE_SHIP = "[cfCliPath, 'deploy', '--mode', 'production'";

describe('deploy:prod pipeline integrity', () => {
	const deployScript = pkg.scripts?.['deploy:prod'] ?? '';

	it('exposes a deploy:prod script', () => {
		expect(deployScript, 'package.json must define a deploy:prod script').not.toBe('');
	});

	// F2: deploy:prod must rebuild @blackveil/dns-checks before deploying so the bundler
	// never bundles a stale dist/ (previously caused a real prod ReferenceError).
	it('rebuilds @blackveil/dns-checks as part of deploy:prod', () => {
		expect(deployScript, 'deploy:prod must build the dns-checks package before deploying').toContain(
			'npm -w packages/dns-checks run build',
		);
	});

	it('builds dns-checks BEFORE running cf deploy', () => {
		const buildIndex = deployScript.indexOf('npm -w packages/dns-checks run build');
		const deployIndex = deployScript.search(SHIP_STEP);
		expect(buildIndex, 'deploy:prod must contain the dns-checks build step').toBeGreaterThan(-1);
		expect(deployIndex, 'deploy:prod must end in the cf deploy hand-off').toBeGreaterThan(-1);
		expect(buildIndex, 'the dns-checks build must run before cf deploy').toBeLessThan(deployIndex);
	});

	// Phase 5: ONLY the final step changed (`npx wrangler deploy --minify --config wrangler.production.jsonc` ->
	// the cf hand-off). Pinning the whole chain, not just relative order, proves no gate was dropped, reordered
	// or reworded in the swap. The injector still runs first: the D1 preflights and check:bindings:prod read the
	// wrangler.production.jsonc it writes, and that file is also the rollback config.
	it.each([
		['deploy:prod', `${CF_PACKAGE_RUN} deploy`],
		['deploy:prod:staged', `${CF_PACKAGE_RUN} deploy:staged`],
	])('%s is exactly the existing gate chain followed by the cf hand-off', (scriptName, handOff) => {
		const steps = (pkg.scripts?.[scriptName] ?? '').split(' && ');
		expect(steps).toEqual([...GATES_BEFORE_SHIP, handOff]);
	});

	it('does not ship, upload, promote or apply triggers through wrangler on the npm doors', () => {
		for (const scriptName of ['deploy:prod', 'deploy:prod:staged', 'deploy:prod:promote', 'deploy:prod:triggers']) {
			const script = pkg.scripts?.[scriptName] ?? '';
			expect(script, `${scriptName} must not call wrangler deploy / versions / triggers`).not.toMatch(
				/wrangler (deploy|versions|triggers)/,
			);
		}
	});

	// A bare `cf deploy` ships the public-only config, and `--prebuilt` would reuse stale build output. Every cf
	// command that evaluates cloudflare.config.ts therefore carries `--mode production` in the script text.
	it('hard-codes --mode production on every cf command that evaluates the config, and never deploys --prebuilt', () => {
		for (const name of ['deploy', 'deploy:staged', 'deploy:triggers']) {
			const script = cfPkg.scripts?.[name] ?? '';
			expect(script, `packages/bv-dns-security-mcp must define ${name}`).toMatch(/^npm run guard:overlay-env && cf /);
			expect(script, `${name} must pass --mode production explicitly`).toContain('--mode production');
			expect(script, `${name} must build fresh, never reuse build output`).not.toContain('--prebuilt');
		}
		expect(cfPkg.scripts?.deploy).toBe(`${OVERLAY_GUARD}cf deploy --mode production`);
		expect(cfPkg.scripts?.['deploy:staged']).toBe(`${OVERLAY_GUARD}cf workers versions create --mode production`);
		expect(cfPkg.scripts?.['deploy:triggers']).toBe(`${OVERLAY_GUARD}cf workers triggers deploy --mode production`);
	});

	// cf is only reachable through the config package: the root hoists the sidecars' older cf (beta.5, which
	// cannot type the function-form config), and cf finds the nested wrangler only from its own cwd.
	it('invokes cf only through the pinned config package, never as a bare root command', () => {
		for (const [name, script] of Object.entries(pkg.scripts ?? {})) {
			expect(script, `root script ${name} must not call cf directly`).not.toMatch(/(^|[ &;|])cf /);
		}
	});

	// BV_DEPLOY_OVERLAY_PATH is a probe hook in cloudflare.config.ts that points production mode at another
	// overlay file (e.g. the placeholder example). No deploy door may ever set it, and every door that evaluates the
	// config must REFUSE to run when an operator shell exports it: the deployed overlay would not be the one the
	// injector validated (SQ-257 seam 7). The guard really aborting is exercised in cloudflare-config.node.test.ts.
	it('never sets the BV_DEPLOY_OVERLAY_PATH probe hook in a deploy door', () => {
		for (const [label, source] of [
			['package.json', packageJsonSource],
			['packages/bv-dns-security-mcp/package.json', cfPackageJsonSource],
			['scripts/deploy-private.mjs', deployPrivateSource],
			['scripts/deploy-prod-promote.mjs', promoteSource],
			['.github/workflows/deploy-prod.yml', deployProdWorkflowSource],
		] as const) {
			expect(source, `${label} must not set the overlay-path probe hook`).not.toMatch(/BV_DEPLOY_OVERLAY_PATH\s*[=:]/);
		}
		// The root scripts, the promote script and the workflow reach cf only through the guarded package scripts.
		for (const [label, source] of [
			['package.json', packageJsonSource],
			['scripts/deploy-prod-promote.mjs', promoteSource],
			['.github/workflows/deploy-prod.yml', deployProdWorkflowSource],
		] as const) {
			expect(source, `${label} neither sets nor needs the overlay-path probe hook`).not.toContain('BV_DEPLOY_OVERLAY_PATH');
		}
	});

	it('refuses to run any cf door, or the private deploy helper, while BV_DEPLOY_OVERLAY_PATH is set', () => {
		const guard = cfPkg.scripts?.['guard:overlay-env'] ?? '';
		expect(guard, 'the guard script must read the hook and exit non-zero').toMatch(
			/process\.env\.BV_DEPLOY_OVERLAY_PATH[\s\S]*process\.exit\(1\)/,
		);
		for (const name of ['deploy', 'deploy:staged', 'deploy:triggers']) {
			expect(cfPkg.scripts?.[name], `${name} must run the overlay-env guard before cf`).toMatch(/^npm run guard:overlay-env && cf /);
		}
		const guardIndex = deployPrivateSource.indexOf('process.env.BV_DEPLOY_OVERLAY_PATH');
		expect(guardIndex, 'deploy-private.mjs must refuse when the hook is set').toBeGreaterThan(-1);
		expect(deployPrivateSource.slice(guardIndex, guardIndex + 400), 'the refusal must exit non-zero').toContain('process.exit(1)');
		// Before the first gate, so a doomed deploy does no work.
		expect(guardIndex).toBeLessThan(deployPrivateSource.indexOf('deploy-freshness-check'));
	});

	// The pinned cf (a devDependency of the config package) arrives with the workflow's `npm ci`.
	it('deploy-prod.yml installs dependencies and restores the overlay before the gated deploy', () => {
		const ciIndex = deployProdWorkflowSource.indexOf('run: npm ci');
		const overlayIndex = deployProdWorkflowSource.indexOf('Reconstruct private deploy overlay');
		const deployIndex = deployProdWorkflowSource.indexOf('run: npm run deploy:prod');
		expect(ciIndex, 'the workflow must npm ci (installs the pinned cf)').toBeGreaterThan(-1);
		expect(deployIndex, 'the workflow must deploy through the gated npm script').toBeGreaterThan(-1);
		expect(ciIndex, 'npm ci must run before the deploy').toBeLessThan(deployIndex);
		expect(overlayIndex, 'the overlay is restored before the deploy').toBeGreaterThan(-1);
		expect(overlayIndex).toBeLessThan(deployIndex);
		expect(deployProdWorkflowSource, 'the workflow must not call cf or wrangler deploy around the gated script').not.toMatch(
			/run: .*(cf deploy|wrangler deploy)/,
		);
	});

	// #945: deploy:prod deploys the MCP Worker ONLY. bv-whois and bv-infra-probe have
	// their own configs and their own deploy commands, and until this gate existed
	// nothing invoked them — both were months stale behind a fully green deploy.
	it('refuses production deployment until the sidecar Workers are proven current', () => {
		expect(deployScript, 'deploy:prod must run the sidecar deploy-drift gate').toContain('npm run check:sidecar-freshness');
	});

	it('runs the sidecar gate BEFORE cf deploy (and early, before the build)', () => {
		const sidecarIndex = deployScript.indexOf('npm run check:sidecar-freshness');
		const deployIndex = deployScript.search(SHIP_STEP);
		const buildIndex = deployScript.indexOf('npm -w packages/dns-checks run build');
		expect(sidecarIndex).toBeGreaterThan(-1);
		expect(sidecarIndex, 'the sidecar gate must run before cf deploy').toBeLessThan(deployIndex);
		// ~2s of wrangler reads; failing after a full dns-checks build wastes the
		// operator's time for no added signal.
		expect(sidecarIndex, 'the sidecar gate must fail before the dns-checks build').toBeLessThan(buildIndex);
	});

	it('exposes the deploy command the sidecar gate tells the operator to run', () => {
		// A gate that names a command package.json does not define is a dead end.
		expect(pkg.scripts?.['deploy:whois'] ?? '').toContain('npm -w packages/bv-whois run deploy');
		expect(pkg.scripts?.['deploy:infra-probe'] ?? '').toContain('npm -w packages/bv-infra-probe run deploy');
	});

	// #1082: deploy:whois and deploy:infra-probe used to hand off straight to
	// wrangler with no freshness or release-tag proof - a checkout behind
	// origin/main, or one not sitting on a tagged release, could ship a sidecar
	// with zero warning. Both doors run the applicable subset of deploy:prod's
	// gate chain from the repo root (so they resolve the same origin/main and
	// version-surface files deploy:prod does), before their own deploy call.
	// check:sidecar-freshness is deliberately excluded from both - it exists to
	// gate the MCP Worker deploy on the sidecars being current, so wiring it
	// into a sidecar's OWN deploy would block the exact command that fixes
	// staleness.
	describe.each([
		['deploy:whois', 'npm -w packages/bv-whois run deploy'],
		['deploy:infra-probe', 'npm -w packages/bv-infra-probe run deploy'],
	])('%s gate chain', (scriptName, deployCommand) => {
		const script = pkg.scripts?.[scriptName] ?? '';

		it('runs the deploy-freshness and release-integrity gates', () => {
			expect(script, `${scriptName} must run check:deploy-freshness`).toContain('npm run check:deploy-freshness');
			expect(script, `${scriptName} must run the sidecar-mode release-integrity gate`).toContain('npm run check:release-integrity:sidecar');
			expect(script.replace('check:release-integrity:sidecar', ''), `${scriptName} must not run the tag-pinned deploy-mode gate`).not.toContain('check:release-integrity');
		});

		it('does not run check:sidecar-freshness against itself', () => {
			expect(script, `${scriptName} must not gate on the sidecar-freshness check it exists to satisfy`).not.toContain(
				'check:sidecar-freshness',
			);
		});

		it('runs the gates before its own deploy call, in freshness-then-release-integrity order', () => {
			const freshnessIndex = script.indexOf('npm run check:deploy-freshness');
			const releaseIndex = script.indexOf('npm run check:release-integrity:sidecar');
			const deployIndex = script.indexOf(deployCommand);
			expect(deployIndex, `${scriptName} must contain its own deploy command`).toBeGreaterThan(-1);
			expect(freshnessIndex, 'freshness must precede release-integrity').toBeLessThan(releaseIndex);
			expect(releaseIndex, 'both gates must precede the sidecar deploy').toBeLessThan(deployIndex);
		});
	});

	it('also gates the private deploy helper — the second door must not be a bypass', () => {
		const gateIndex = deployPrivateSource.indexOf('sidecar-deploy-drift-check.ts');
		const deployIndex = deployPrivateSource.indexOf(PRIVATE_SHIP);
		expect(gateIndex, 'deploy-private.mjs must run the sidecar deploy-drift gate').toBeGreaterThan(-1);
		expect(deployIndex, 'deploy-private.mjs must contain the cf production deploy call').toBeGreaterThan(-1);
		expect(gateIndex, 'the sidecar gate must run before cf deploy').toBeLessThan(deployIndex);
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
		const deployIndex = deployScript.search(SHIP_STEP);
		expect(preflightIndex).toBeGreaterThan(-1);
		expect(preflightIndex).toBeLessThan(deployIndex);
	});

	it('also gates the private deploy helper before its cf deploy call', () => {
		const preflightIndex = deployPrivateSource.indexOf('brand-audit-schema-preflight.mjs');
		const deployIndex = deployPrivateSource.indexOf(PRIVATE_SHIP);
		expect(preflightIndex).toBeGreaterThan(-1);
		expect(deployIndex).toBeGreaterThan(-1);
		expect(preflightIndex).toBeLessThan(deployIndex);
	});

	// SQ-187: INTELLIGENCE_DB bound to an unmigrated database (the state a database_id repoint in the
	// private overlay can produce) makes every fire-and-forget access-log insert throw with nothing to
	// surface it. The preflight reads the GENERATED config, so on every door it must run after the
	// injector and before the Worker ships.
	it.each(['deploy:prod', 'deploy:prod:staged'])('runs the access-log schema preflight after injection and before shipping in %s', (scriptName) => {
		const script = pkg.scripts?.[scriptName] ?? '';
		const injectIndex = script.indexOf('node scripts/inject-private-config.cjs');
		const preflightIndex = script.indexOf('node scripts/access-log-schema-preflight.mjs --config wrangler.production.jsonc');
		const shipIndex = script.search(SHIP_STEP);
		expect(preflightIndex, `${scriptName} must run the access-log schema preflight against the generated config`).toBeGreaterThan(-1);
		expect(injectIndex, 'the preflight reads the injected config, so the injector must run first').toBeLessThan(preflightIndex);
		expect(shipIndex, `${scriptName} must end in the cf deploy / versions hand-off`).toBeGreaterThan(-1);
		expect(preflightIndex, 'the preflight must run before the Worker ships').toBeLessThan(shipIndex);
	});

	it('also runs the access-log schema preflight on the private deploy helper, after injection and before deploy', () => {
		const injectIndex = deployPrivateSource.indexOf('scripts/inject-private-config.cjs');
		const preflightIndex = deployPrivateSource.indexOf("['scripts/access-log-schema-preflight.mjs', '--config', generatedConfigPath]");
		const deployIndex = deployPrivateSource.indexOf(PRIVATE_SHIP);
		expect(preflightIndex, 'deploy-private.mjs must run the access-log schema preflight against the generated config').toBeGreaterThan(-1);
		expect(injectIndex, 'the preflight reads the injected config, so the injector must run first').toBeLessThan(preflightIndex);
		expect(preflightIndex, 'the preflight must run before cf deploy').toBeLessThan(deployIndex);
	});

	// The private overlay is a partial overlay, not a standalone config. Deploying it
	// directly drops the public base (routes, cron triggers, limits, tail consumers) AND
	// every fail-closed gate in the injector, which is how this door once deployed without
	// PROFILE_ACCUMULATOR. The injector (and cloudflare.config.ts production mode, which merges the
	// overlay through the same helper) is the only way the overlay reaches a deploy.
	it('routes the private deploy helper through the config injector', () => {
		const injectIndex = deployPrivateSource.indexOf('scripts/inject-private-config.cjs');
		const deployIndex = deployPrivateSource.indexOf(PRIVATE_SHIP);
		expect(injectIndex, 'deploy-private.mjs must run the injector').toBeGreaterThan(-1);
		expect(injectIndex, 'the injector must run before cf deploy').toBeLessThan(deployIndex);
	});

	// cf has no --config: it evaluates ./cloudflare.config.ts in its cwd, so the deploy MUST run from the config
	// package, in production mode, through that package's pinned cf — never the root's hoisted older one.
	it('spawns the config package\'s own cf in production mode, from the config package, never the raw overlay', () => {
		const deployCall = deployPrivateSource.slice(deployPrivateSource.indexOf(PRIVATE_SHIP));
		expect(deployCall, 'deploying the overlay directly bypasses every injector gate').not.toContain('privateConfigPath');
		expect(deployCall, 'cf takes no --config; passing one would not select the overlay').not.toContain("'--config'");
		expect(deployCall, 'cf must run with the config package as its cwd').toContain('cwd: cfProjectDir');
		expect(deployPrivateSource, 'the cf binary must be the config package\'s pinned install').toContain(
			"packages/bv-dns-security-mcp/node_modules/.bin/cf",
		);
		expect(deployPrivateSource, 'the wrangler deploy spawn is gone').not.toContain('wranglerCliPath');
	});

	// Promote takes an EXPLICIT version id (never "latest"), passes the strategy cf requires live (--dry-run does
	// not check it), and fails closed without an id: a guessed id would roll traffic to whatever was uploaded last.
	describe('promote / triggers doors', () => {
		it('promote is the fail-closed script and triggers goes through the config package', () => {
			expect(pkg.scripts?.['deploy:prod:promote']).toBe('node scripts/deploy-prod-promote.mjs');
			// Unlike `wrangler triggers deploy`, `cf workers triggers deploy` BUILDS the Worker to read its triggers, and the
			// build resolves @blackveil/dns-checks from dist/ — so the package is rebuilt first (test/deploy-dns-checks-build.spec.ts).
			expect(pkg.scripts?.['deploy:prod:triggers']).toBe(
				`npm -w packages/dns-checks run build && ${CF_PACKAGE_RUN} deploy:triggers`,
			);
		});

		it('builds cf workers deployments create with the explicit-version strategy form and no bypass flag', () => {
			// Code only: the header comment names the flags it deliberately does not pass.
			const code = promoteSource
				.split('\n')
				.filter((line) => !line.trim().startsWith('//'))
				.join('\n');
			expect(code).toContain("'workers', 'deployments', 'create'");
			expect(code).toContain("'--worker', PRODUCTION_WORKER_NAME");
			expect(code).toContain("'--strategy', 'percentage'");
			expect(code).toContain("'--versions'");
			expect(code, 'never bypass the deployment checks').not.toContain('--bypass-deployment-checks');
			expect(code, 'the removed wrangler-era flag').not.toContain('--force');
		});
	});

	// The staged path exists so a version can be smoke-tested before it takes traffic. It
	// is only safe if it carries the SAME gates — a staged path that skipped the dns-checks
	// rebuild or the schema preflight would upload a version those gates never vetted.
	describe('staged rollout path', () => {
		const stagedScript = pkg.scripts?.['deploy:prod:staged'] ?? '';

		it('runs every gate deploy:prod runs', () => {
			expect(stagedScript, 'package.json must define a deploy:prod:staged script').not.toBe('');
			for (const gate of GATES_BEFORE_SHIP) {
				expect(stagedScript, `deploy:prod:staged must run the ${gate} gate`).toContain(gate);
			}
		});

		it('uploads a version instead of routing traffic to it', () => {
			expect(stagedScript, 'the staged path must upload a version, not deploy one').toContain(`${CF_PACKAGE_RUN} deploy:staged`);
			expect(cfPkg.scripts?.['deploy:staged'], 'the staged path must create a version, not a deployment').toBe(
				`${OVERLAY_GUARD}cf workers versions create --mode production`,
			);
			expect(stagedScript, 'the staged path must not send traffic to the new version').not.toMatch(/run deploy(?![\w:-])/);
			expect(stagedScript).not.toContain('cf deploy');
		});

		it('exposes the promote and trigger steps a version upload does not perform', () => {
			// A version upload deliberately leaves triggers alone, so cron/route changes need
			// an explicit triggers deploy — otherwise a staged rollout silently drops them.
			expect(pkg.scripts?.['deploy:prod:promote'] ?? '').toContain('deploy-prod-promote.mjs');
			expect(pkg.scripts?.['deploy:prod:triggers'] ?? '').toContain('deploy:triggers');
			expect(cfPkg.scripts?.['deploy:triggers']).toContain('cf workers triggers deploy');
		});
	});
});

describe('inject-private-config fail-closed on missing overlay', () => {
	// F3: a genuinely-absent private overlay must hard-fail the deploy (process.exit(1))
	// rather than `return` 0, which would let the `&&` chain proceed to the deploy against
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
