// SPDX-License-Identifier: BUSL-1.1
//
// `npm run check:live-binding-drift` — read-only check that the LIVE Worker carries exactly the bindings the
// reviewed config says it should (bindings audit 2026-11-13).
//
// `check:cf-binding-parity` compares two config files (cf build vs the injector); nothing compared either of them
// with what is actually serving. This does, for every version in the active deployment:
//   - expected = public wrangler.jsonc + the private overlay, merged exactly as the deploy doors merge them
//     (scripts/lib/overlay-merge.mjs) — so `secrets.required` is the same list the deploy enforces;
//   - live     = `wrangler versions view <id> --json` resources.bindings for each deployed version.
// ERRORS (exit 1): a binding missing live, an unreviewed live binding, a type or target-resource mismatch, a var
// whose value differs, a required secret absent from the version.
// WARNINGS (exit 0): a queue consumer with no dead_letter_queue (a message that exhausts max_retries is dropped).
// INFO: env names the code reads that nothing binds — expected for dark/optional features. A count by default;
//   `--verbose` lists them so a typo shows.
//
// Limits, stated so a clean run is not over-read:
//   - queue CONSUMER settings (batch size, retries, DLQ) are not in version metadata; the DLQ warning reads the
//     merged CONFIG, not live. Verify live consumers with `wrangler queues info <queue>`.
//   - extra live secrets are not errors: fail-soft capability keys are legitimately set without being required.
//   - the code scan is a regex over src/ for `env.NAME` / `env?.NAME`; a name read through a helper by string is
//     missed, and a name in a comment is counted. INFO only, never a failure.
// Never prints var values or resource ids: a changed var shows as "value differs", a changed resource as
// "target differs".
//
// Exit codes: 0 no errors, 1 errors, 2 an input could not be read, or the live deployment had no bindings
// (an empty live set is never reported as clean).
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mergeOverlay, parseJsonc, validateOverlayKeys } from '../lib/overlay-merge.mjs';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/** Config list → [live binding type, field holding the target resource]. */
const CONFIG_KINDS = [
	['kv_namespaces', 'kv_namespace', 'id'],
	['d1_databases', 'd1', 'database_id'],
	['r2_buckets', 'r2_bucket', 'bucket_name'],
	['analytics_engine_datasets', 'analytics_engine', 'dataset'],
	['services', 'service', 'service'],
];

/** Live binding type → field holding the target resource (null: no resource to compare). */
const LIVE_TARGET_FIELD = {
	kv_namespace: 'namespace_id',
	d1: 'id',
	r2_bucket: 'bucket_name',
	analytics_engine: 'dataset',
	service: 'service',
	durable_object_namespace: 'class_name',
	queue: 'queue_name',
	plain_text: 'text',
	secret_text: null,
};

const digest = (value) => (value === undefined || value === null ? null : createHash('sha256').update(String(value)).digest('hex'));

/** Expected bindings from a merged config: Map name → { type, target } (target hashed for vars). */
export function expectedBindings(merged) {
	const out = new Map();
	for (const [key, type, field] of CONFIG_KINDS) {
		for (const entry of merged[key] ?? []) out.set(entry.binding, { type, target: entry[field] ?? null });
	}
	for (const entry of merged.durable_objects?.bindings ?? []) {
		out.set(entry.name, { type: 'durable_object_namespace', target: entry.class_name ?? null });
	}
	for (const entry of merged.queues?.producers ?? []) out.set(entry.binding, { type: 'queue', target: entry.queue ?? null });
	for (const [name, value] of Object.entries(merged.vars ?? {})) out.set(name, { type: 'plain_text', target: digest(value) });
	for (const name of merged.secrets?.required ?? []) out.set(name, { type: 'secret_text', target: null });
	return out;
}

/** Live bindings from one `versions view` payload: Map name → { type, target }. */
export function liveBindings(version) {
	const out = new Map();
	for (const binding of version?.resources?.bindings ?? []) {
		const field = LIVE_TARGET_FIELD[binding.type];
		const raw = field ? binding[field] : null;
		out.set(binding.name, { type: binding.type, target: binding.type === 'plain_text' ? digest(raw) : (raw ?? null) });
	}
	return out;
}

function compareOne(name, want, got) {
	if (!got)
		return want.type === 'secret_text'
			? `required secret ${name} is not set on the deployed version`
			: `${name} (${want.type}) is missing live`;
	if (got.type !== want.type) return `${name}: type differs (config ${want.type}, live ${got.type})`;
	if (want.target !== null && got.target !== want.target) {
		return want.type === 'plain_text' ? `var ${name}: value differs` : `${name} (${want.type}): target differs`;
	}
	return null;
}

/**
 * Pure comparison. Returns { errors, warnings, info } as printable lines.
 * @param {{ expected: Map<string, {type: string, target: unknown}>, live: Map<string, {type: string, target: unknown}>,
 *           consumers?: Array<Record<string, unknown>>, codeNames?: Iterable<string> }} input
 */
export function compareLiveBindings({ expected, live, consumers = [], codeNames = [] }) {
	const errors = [];
	for (const [name, want] of expected) {
		const problem = compareOne(name, want, live.get(name));
		if (problem) errors.push(problem);
	}
	for (const [name, got] of live) {
		if (!expected.has(name) && got.type !== 'secret_text')
			errors.push(`${name} (${got.type}) is bound live but not in the reviewed config`);
	}
	const warnings = consumers
		.filter((consumer) => !consumer.dead_letter_queue)
		.map((consumer) => `queue consumer ${consumer.queue} has no dead_letter_queue (config; exhausted messages are dropped)`);
	const known = new Set([...expected.keys(), ...live.keys()]);
	const info = [...new Set(codeNames)]
		.filter((name) => !known.has(name) && !name.startsWith('TENANT_DB_'))
		.sort()
		.map((name) => `code reads env.${name}, which nothing binds (optional/dark, or a typo)`);
	return { errors, warnings, info };
}

/** Env names read in src/ as `env.NAME` or `env?.NAME` (see the limits in the header). */
export function scanCodeEnvNames(srcDir) {
	const names = new Set();
	const files = readdirSync(srcDir, { recursive: true }).filter((file) => String(file).endsWith('.ts'));
	for (const file of files) {
		for (const match of readFileSync(join(srcDir, String(file)), 'utf8').matchAll(/\benv\??\.([A-Z][A-Z0-9_]{2,})\b/g)) names.add(match[1]);
	}
	return names;
}

function parseArgs(argv) {
	const args = {
		overlay: join(repoRoot, '.dev/wrangler.deploy.jsonc'),
		publicConfig: join(repoRoot, 'wrangler.jsonc'),
		liveJson: null,
		verbose: false,
	};
	const valued = { '--overlay': 'overlay', '--public': 'publicConfig', '--live-json': 'liveJson' };
	for (let i = 0; i < argv.length; i += 1) {
		if (argv[i] === '--verbose') {
			args.verbose = true;
			continue;
		}
		const key = valued[argv[i]];
		if (!key || argv[i + 1] === undefined) throw new Error(`unknown or incomplete argument ${argv[i]}`);
		args[key] = argv[(i += 1)];
	}
	return args;
}

function wranglerJson(args) {
	return JSON.parse(
		execFileSync('npx', ['wrangler', ...args, '--json'], { cwd: repoRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }),
	);
}

/** Every version serving traffic in the active deployment, as `versions view` payloads. */
function fetchLiveVersions(worker) {
	const status = wranglerJson(['deployments', 'status', '--name', worker]);
	return (status.versions ?? []).map((v) => wranglerJson(['versions', 'view', v.version_id, '--name', worker]));
}

function loadInputs(args) {
	const publicConfig = parseJsonc(readFileSync(args.publicConfig, 'utf8'));
	const overlay = parseJsonc(readFileSync(args.overlay, 'utf8'));
	validateOverlayKeys(overlay, publicConfig);
	const merged = mergeOverlay(publicConfig, overlay);
	const versions = args.liveJson ? JSON.parse(readFileSync(args.liveJson, 'utf8')) : fetchLiveVersions(merged.name);
	return { merged, versions, verbose: args.verbose };
}

function report(label, lines, print) {
	for (const line of lines) print(`  ${label} ${line}`);
}

export function main(argv, { out = console.log, err = console.error, srcDir = join(repoRoot, 'src') } = {}) {
	let inputs;
	try {
		inputs = loadInputs(parseArgs(argv));
	} catch (error) {
		err(`live-binding-drift: cannot read inputs — ${error.message.split('\n')[0]}`);
		return 2;
	}
	const { merged, versions, verbose } = inputs;
	if (!Array.isArray(versions) || versions.length === 0 || versions.some((v) => !v?.resources?.bindings?.length)) {
		err('live-binding-drift: the live deployment returned no versions or a version with no bindings — refusing to report clean.');
		return 2;
	}
	const expected = expectedBindings(merged);
	const codeNames = scanCodeEnvNames(srcDir);
	let failed = false;
	for (const version of versions) {
		const result = compareLiveBindings({ expected, live: liveBindings(version), consumers: merged.queues?.consumers ?? [], codeNames });
		const status = result.errors.length > 0 ? 'FAIL' : 'OK';
		failed ||= result.errors.length > 0;
		out(
			`live-binding-drift: ${status} — version ${version.id}: ${version.resources.bindings.length} live bindings, ${expected.size} expected`,
		);
		report('ERROR', result.errors, err);
		report('WARN ', result.warnings, out);
		if (verbose) report('INFO ', result.info, out);
		else if (result.info.length > 0)
			out(`  INFO  ${result.info.length} env names read by src/ are unbound (optional/dark); --verbose lists them`);
	}
	return failed ? 1 : 0;
}

const invokedDirectly = process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
if (invokedDirectly) process.exit(main(process.argv.slice(2)));
