// SPDX-License-Identifier: BUSL-1.1
//
// `npm run deploy:prod:promote -- <version-id>` — route 100% of production traffic to an already-uploaded
// Worker version (the step after `npm run deploy:prod:staged`).
//
// The version id is REQUIRED, as an argument or BV_PROMOTE_VERSION_ID, and must be a UUID. There is deliberately
// no "latest" default: promoting whatever was uploaded last would roll traffic to a version nobody smoke-tested
// if another upload landed in between. Without an id this exits non-zero and never starts cf.
//
// `--strategy percentage` is required by the live API but NOT checked by `--dry-run` (SQ-253), so it is always
// passed. `--bypass-deployment-checks` (formerly `--force`) is never passed: cf's guard against rolling back to
// a version whose secrets have changed should stop the promote, not be skipped.
//
// cf has no --config: it evaluates ./cloudflare.config.ts in its cwd, so it is spawned from the config package
// and from that package's own pinned install (the repo root hoists the sidecars' older cf, which cannot type
// the function-form config).
import { spawnSync } from 'node:child_process';
import { realpathSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

/** cloudflare.config.ts PRODUCTION_WORKER_NAME; test/audits/deploy-prod-promote.node.test.ts pins the two together. */
export const PRODUCTION_WORKER_NAME = 'bv-dns-security-mcp';
export const VERSION_ID_ENV = 'BV_PROMOTE_VERSION_ID';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The version id from the first argument, else the environment. Returns null when neither names one. */
export function resolveVersionId(args, env) {
	const fromArg = args.find((arg) => arg.length > 0);
	const id = fromArg ?? env[VERSION_ID_ENV];
	return id === undefined || id === '' ? null : id;
}

/** The cf argv (after the binary) for a 100% promotion. Throws on anything that is not a UUID. */
export function buildPromoteArgv(versionId) {
	if (typeof versionId !== 'string' || !UUID.test(versionId)) {
		throw new Error(`"${String(versionId)}" is not a Worker version id (expected a UUID).`);
	}
	// prettier-ignore
	return [
		'workers', 'deployments', 'create',
		'--worker', PRODUCTION_WORKER_NAME,
		'--strategy', 'percentage',
		'--versions', JSON.stringify([{ version_id: versionId.toLowerCase(), percentage: 100 }]),
	];
}

function main() {
	const versionId = resolveVersionId(process.argv.slice(2), process.env);
	if (versionId === null) {
		console.error(
			`Refusing to promote: no version id. Pass one explicitly: npm run deploy:prod:promote -- <version-id> (or set ${VERSION_ID_ENV}).`,
		);
		console.error('Upload one with `npm run deploy:prod:staged`; it prints the version id. There is no "latest" default.');
		process.exit(1);
	}

	let argv;
	try {
		argv = buildPromoteArgv(versionId);
	} catch (error) {
		console.error(`Refusing to promote: ${error instanceof Error ? error.message : String(error)}`);
		process.exit(1);
	}

	const cfProjectDir = fileURLToPath(new URL('../packages/bv-dns-security-mcp/', import.meta.url));
	const cfCliPath = fileURLToPath(new URL('../packages/bv-dns-security-mcp/node_modules/.bin/cf', import.meta.url));
	const result = spawnSync(process.execPath, [cfCliPath, ...argv], { stdio: 'inherit', cwd: cfProjectDir });
	if (result.error) {
		console.error(`cf failed to start: ${result.error.message}`);
		process.exit(1);
	}
	process.exit(result.status ?? 1);
}

// import.meta.url is the REAL path; argv[1] is as typed. Compare real paths, or a symlinked checkout (macOS /var,
// /tmp) would skip main() and exit 0 having promoted nothing.
if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) main();
