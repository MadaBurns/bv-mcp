// SPDX-License-Identifier: BUSL-1.1

/**
 * bv-ct-index deploy-readiness decision core (US-12, SQ-354).
 *
 * `npm run deploy:ct-index` must run on a CLEAN tree (`check:release-integrity:sidecar` refuses a dirty one), and the Worker's D1
 * database id is an account resource id that must not be committed to this public repo. So the id is injected at deploy time
 * through `BV_CT_INDEX_D1_ID`, read by `packages/bv-ct-index/cloudflare.config.ts` (which `cf deploy` evaluates in Node, with
 * process.env access) and checked up front by `scripts/ci/ct-index-deploy-ready-check.ts`. Both call `resolveCtIndexD1Id`, so the
 * preflight and the deploy cannot disagree about what a usable id is.
 *
 * Deliberately PURE (no `node:*` imports), like `scripts/sidecar-deploy-drift.ts`, so the Workers-pool spec can import it. All file
 * reading lives in the CLI shell. Everything here fails CLOSED: an input that cannot be read is a failure, never a pass.
 */

/** The environment variable that carries the real D1 database id at deploy time. */
export const CT_INDEX_D1_ID_ENV = 'BV_CT_INDEX_D1_ID';

/** The repo-root command that prints the idempotent operator provisioning steps. */
export const CT_INDEX_PROVISION_COMMAND = 'npm run provision:ct-index';

/** The only Worker name this package may deploy: deploy is upsert-by-name on a shared account. */
export const CT_INDEX_WORKER_NAME = 'bv-ct-index';

/**
 * A third party's live app on this account. `cf deploy` upserts by name, so this name appearing in a deploy config would overwrite
 * it. It must never appear in the files `assessCtIndexDeployReady` scans.
 */
export const FORBIDDEN_WORKER_NAME = 'bv-certstream-worker';

/** The tracked placeholder in the test config (`packages/bv-ct-index/wrangler.jsonc`). */
export const CT_INDEX_D1_PLACEHOLDER = 'YOUR_BV_CT_INDEX_CURSORS_D1_DATABASE_ID';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Why a raw value is not a usable D1 id, or null when it is usable. */
function d1IdProblem(raw: string | undefined): string | null {
	const value = raw?.trim() ?? '';
	if (value === '') return `${CT_INDEX_D1_ID_ENV} is unset or empty`;
	if (value === CT_INDEX_D1_PLACEHOLDER || value.startsWith('YOUR_')) return `${CT_INDEX_D1_ID_ENV} is still the placeholder`;
	if (!UUID_RE.test(value)) return `${CT_INDEX_D1_ID_ENV} is not a UUID`;
	return null;
}

function d1IdMessage(problem: string): string {
	return `${problem}. Run \`${CT_INDEX_PROVISION_COMMAND}\` for the steps that create the D1 database, then export ${CT_INDEX_D1_ID_ENV}=<the database_id it prints> before \`npm run deploy:ct-index\`.`;
}

/** The D1 id to deploy with. Throws, naming the variable and the provisioning command, for anything but a UUID. */
export function resolveCtIndexD1Id(raw: string | undefined): string {
	const problem = d1IdProblem(raw);
	if (problem) throw new Error(d1IdMessage(problem));
	return raw!.trim();
}

export interface CtIndexDeployReadyInput {
	/** `process.env.BV_CT_INDEX_D1_ID` (undefined when unset). */
	d1Id: string | undefined;
	/** Source of `packages/bv-ct-index/cloudflare.config.ts`, or null when it could not be read. */
	configSource: string | null;
	/** Source of `packages/bv-ct-index/wrangler.jsonc`, or null when it could not be read. */
	wranglerSource: string | null;
	/** Source of `packages/bv-ct-index/package.json`, or null when it could not be read. */
	packageJsonSource: string | null;
	/** File names in `packages/bv-ct-index/migrations/`, or null when the directory could not be read. */
	migrationFiles: readonly string[] | null;
}

export interface CtIndexDeployReadyVerdict {
	ok: boolean;
	/** One human-readable line per failed condition; empty when ok. */
	failures: string[];
}

/** The Worker `name` the cf config declares: the `name:` that opens the `worker: {` block. */
function cfConfigWorkerName(source: string): string | null {
	return /\bworker:\s*\{\s*(?:\/\/[^\n]*\s*)*name:\s*['"]([^'"]+)['"]/.exec(source)?.[1] ?? null;
}

/** The first `"name"` in the JSONC test config (the top-level Worker name). */
function wranglerWorkerName(source: string): string | null {
	return /"name"\s*:\s*"([^"]+)"/.exec(source)?.[1] ?? null;
}

/**
 * Whether `bv-ct-index` is safe to deploy. Fails closed unless ALL hold: the D1 id resolves to a UUID; the cf config and the test
 * config both name the Worker exactly `bv-ct-index`; the forbidden third-party Worker name appears in none of the config, test
 * config or package manifest; and the migrations directory is non-empty. A file that could not be read is a failure of the
 * condition it was meant to prove.
 */
export function assessCtIndexDeployReady(input: CtIndexDeployReadyInput): CtIndexDeployReadyVerdict {
	const failures: string[] = [];

	const d1Problem = d1IdProblem(input.d1Id);
	if (d1Problem) failures.push(d1IdMessage(d1Problem));

	const checkName = (label: string, source: string | null, extract: (s: string) => string | null) => {
		if (source === null) {
			failures.push(`cannot read ${label}, so the Worker name cannot be verified as ${CT_INDEX_WORKER_NAME}`);
			return;
		}
		const name = extract(source);
		if (name !== CT_INDEX_WORKER_NAME) {
			failures.push(`${label} names the Worker ${name === null ? '(none found)' : JSON.stringify(name)}; it must be exactly ${CT_INDEX_WORKER_NAME}`);
		}
	};
	checkName('packages/bv-ct-index/cloudflare.config.ts', input.configSource, cfConfigWorkerName);
	checkName('packages/bv-ct-index/wrangler.jsonc', input.wranglerSource, wranglerWorkerName);

	const scanned: Array<[string, string | null]> = [
		['packages/bv-ct-index/cloudflare.config.ts', input.configSource],
		['packages/bv-ct-index/wrangler.jsonc', input.wranglerSource],
		['packages/bv-ct-index/package.json', input.packageJsonSource],
	];
	for (const [label, source] of scanned) {
		if (source === null) {
			if (label.endsWith('package.json')) failures.push(`cannot read ${label}, so it cannot be checked for ${FORBIDDEN_WORKER_NAME}`);
		} else if (source.includes(FORBIDDEN_WORKER_NAME)) {
			failures.push(`${label} mentions ${FORBIDDEN_WORKER_NAME}, a third party's live app that a deploy would overwrite`);
		}
	}

	if (input.migrationFiles === null) failures.push('cannot read packages/bv-ct-index/migrations/');
	else if (input.migrationFiles.filter((f) => f.endsWith('.sql')).length === 0) failures.push('packages/bv-ct-index/migrations/ holds no .sql migration');

	return { ok: failures.length === 0, failures };
}
