import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const privateConfigPath = '.dev/wrangler.deploy.jsonc';
const generatedConfigPath = 'wrangler.production.jsonc';

if (!existsSync(privateConfigPath)) {
	console.error(`Missing ${privateConfigPath}.`);
	console.error(
		'Copy wrangler.private.example.jsonc to .dev/wrangler.deploy.jsonc and replace the placeholder bindings with real Cloudflare resource identifiers.',
	);
	process.exit(1);
}

const require = createRequire(import.meta.url);
const wranglerCliPath = require.resolve('wrangler');
const tsxCliPath = require.resolve('tsx/cli');

/** Run one deploy step, streaming its output and aborting the deploy on any non-zero exit. */
function runStep(argv, description) {
	const step = spawnSync(process.execPath, argv, { stdio: 'inherit' });
	if (step.error) {
		console.error(`${description} failed: ${step.error.message}`);
		process.exit(1);
	}
	if (step.status !== 0) {
		process.exit(step.status ?? 1);
	}
}

// The overlay is an OVERLAY, not a standalone config. Deploying it directly skips the
// public wrangler.jsonc base — routes, cron triggers, limits, tail consumers — and every
// fail-closed gate in inject-private-config.cjs: the production security vars, the
// unknown-overlay-key guard, and the required-secrets declaration. Deploying the overlay
// as-is once meant shipping without PROFILE_ACCUMULATOR, because the example overlay
// carried its own stale `durable_objects` copy. Always deploy the injected config.
// This is the SECOND deploy door and it skips the `deploy:prod` npm chain entirely,
// so every gate wired there has to be re-wired here or it is simply a bypass. The
// sidecar deploy-drift gate (#945) blocks when bv-whois / bv-infra-probe are behind
// their source — neither this door nor `deploy:prod` deploys them, and their drift is
// invisible in an otherwise-green run (bv-whois shipped 4 source commits stale for 3
// months). Runs first: it is ~2s and must fail before any build work.
// Override: BV_ALLOW_STALE_SIDECARS=1.
//
// ORDER IS LOAD-BEARING — freshness FIRST (#945 review). The sidecar gate's git
// evidence is `git log HEAD -- <watchPaths>`, which can only see commits that are
// ancestors of HEAD. On a checkout behind origin/main, a sidecar commit that has
// landed upstream but not locally is INVISIBLE to it: the drift list comes back
// empty and the gate prints "fresh" — a false green in a gate whose entire purpose
// is fail-closed. `deploy:prod` and `deploy:prod:staged` avoid this because their
// npm chains run `check:deploy-freshness` first, which proves HEAD ⊇ origin/main;
// this door skipped it, so the sidecar gate was resting on a precondition nothing
// enforced here. Run it, and the assumption holds on all three doors.
// (Stale checkouts are a proven incident class in this repo — see the
// deploy-freshness.ts docstring. Override: BV_ALLOW_STALE_DEPLOY=1.)
runStep([tsxCliPath, 'scripts/ci/deploy-freshness-check.ts'], 'Deploy freshness gate');

runStep([tsxCliPath, 'scripts/ci/sidecar-deploy-drift-check.ts'], 'Sidecar deploy-drift gate');

runStep(['scripts/inject-private-config.cjs'], 'Private config injection');

runStep(['scripts/brand-audit-schema-preflight.mjs', '--config', generatedConfigPath], 'Brand Audit schema preflight');

const result = spawnSync(process.execPath, [wranglerCliPath, 'deploy', '--config', generatedConfigPath, ...process.argv.slice(2)], {
	stdio: 'inherit',
});

if (result.error) {
	console.error(result.error.message);
	process.exit(1);
}

process.exit(result.status ?? 1);
