// SPDX-License-Identifier: BUSL-1.1
//
// `npm run check:cf-binding-parity` — the operator's pre-deploy parity check for the wrangler -> cf cutover (US-8).
//
// It compares what `cf build --mode production` WILL deploy (packages/bv-dns-security-mcp/.cloudflare/output/v0/
// workers/default/worker.config.json) against what the injector wrote for the legacy door (wrangler.production.jsonc),
// after normalising both to the same shape:
//   - bindings: a sorted list of { binding, type, resourceId, options }. cf keys `env` by BINDING NAME and wrangler
//     scatters bindings across kv_namespaces / d1_databases / services / ...; the ad-hoc jq this replaces read cf's
//     `.name` (a RESOURCE name) and so reported a diff on identical configs (SQ-257 seam 9).
//   - triggers: every cron and every queue consumer with all of its settings (DLQ, retries, batch size/timeout,
//     concurrency, retry delay), plus name / compatibility date+flags / cpu limit / observability / tail consumers.
//   - Durable Object classes: wrangler `migrations` vs cf `exports` (the ONE representation difference that is
//     expected). The migrations are folded to a final {class: storage} map and compared with cf's exports.
// Any other difference — and any top-level key either side carries that this script does not understand — exits 1,
// so a new field can never be waved through as "not compared".
//
// Exit codes: 0 identical, 1 differences, 2 an input could not be read or parsed.
// Text var VALUES are never printed (a var can hold an alert-webhook URL); a changed value shows as a short sha256.
import { createHash } from 'node:crypto';
import { readFileSync, realpathSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseJsonc } from '../lib/overlay-merge.mjs';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const DEFAULT_CF_CONFIG = join(repoRoot, 'packages/bv-dns-security-mcp/.cloudflare/output/v0/workers/default/worker.config.json');
export const DEFAULT_WRANGLER_CONFIG = join(repoRoot, 'wrangler.production.jsonc');

/** Wrangler top-level keys that carry no binding/trigger/setting this script compares (deploy plumbing only). */
const WRANGLER_IGNORED_KEYS = new Set(['$schema', 'main', 'upload_source_maps']);
/** cf top-level keys that carry no binding/trigger/setting this script compares (the bundle manifest). */
const CF_IGNORED_KEYS = new Set(['manifest']);

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const camel = (key) => key.replace(/_([a-z0-9])/g, (_, c) => c.toUpperCase());

/** Recursively camelCase object KEYS (never values), so wrangler's snake_case lines up with cf's camelCase. */
function camelKeys(value) {
	if (Array.isArray(value)) return value.map(camelKeys);
	if (!isObject(value)) return value;
	return Object.fromEntries(Object.entries(value).map(([k, v]) => [camel(k), camelKeys(v)]));
}

/** Deterministic JSON: object keys sorted at every depth. */
export function canon(value) {
	if (Array.isArray(value)) return `[${value.map(canon).join(',')}]`;
	if (isObject(value)) {
		return `{${Object.keys(value)
			.sort()
			.map((k) => `${JSON.stringify(k)}:${canon(value[k])}`)
			.join(',')}}`;
	}
	return JSON.stringify(value) ?? 'null';
}

/** Drop undefined/null options so "absent" and "explicitly unset" compare equal. */
function options(raw) {
	const out = Object.fromEntries(Object.entries(raw).filter(([, v]) => v !== undefined && v !== null));
	return Object.keys(out).length === 0 ? undefined : out;
}

function binding(name, type, resourceId, opts = {}) {
	const entry = { binding: name, type, resourceId: resourceId ?? null };
	const extra = options(opts);
	if (extra) entry.options = extra;
	return entry;
}

const sortBindings = (list) =>
	[...list].sort((a, b) => (a.binding === b.binding ? canon(a).localeCompare(canon(b)) : a.binding.localeCompare(b.binding)));

/** Fold wrangler `migrations` to the final { className: 'sqlite' | 'kv' } set that cf expresses as `exports`. */
function foldMigrations(migrations, unmapped) {
	const classes = new Map();
	for (const step of migrations ?? []) {
		for (const key of Object.keys(step)) {
			if (!['tag', 'new_classes', 'new_sqlite_classes', 'renamed_classes', 'deleted_classes'].includes(key)) {
				unmapped.push(`migrations[${step.tag}].${key}`);
			}
		}
		for (const name of step.new_classes ?? []) classes.set(name, 'kv');
		for (const name of step.new_sqlite_classes ?? []) classes.set(name, 'sqlite');
		for (const { from, to } of step.renamed_classes ?? []) {
			classes.set(to, classes.get(from) ?? 'unknown');
			classes.delete(from);
		}
		for (const name of step.deleted_classes ?? []) classes.delete(name);
	}
	return Object.fromEntries([...classes.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

/** Record every key of `value` that is not in `known` as unmapped; returns `value` (or {}). */
function knownKeys(value, known, where, unmapped) {
	for (const key of Object.keys(value ?? {})) {
		if (!known.includes(key)) unmapped.push(`${where}.${key}`);
	}
	return value ?? {};
}

/** Normalise a parsed wrangler.production.jsonc. */
export function normalizeWrangler(config) {
	const unmapped = [];
	const bindings = [];
	const triggers = [];
	const handled = new Set([
		'name',
		'compatibility_date',
		'compatibility_flags',
		'limits',
		'observability',
		'tail_consumers',
		'vars',
		'services',
		'kv_namespaces',
		'd1_databases',
		'r2_buckets',
		'analytics_engine_datasets',
		'queues',
		'secrets',
		'durable_objects',
		'migrations',
		'triggers',
	]);
	for (const key of Object.keys(config)) {
		if (!handled.has(key) && !WRANGLER_IGNORED_KEYS.has(key)) unmapped.push(key);
	}

	const settings = {
		name: config.name ?? null,
		compatibilityDate: config.compatibility_date ?? null,
		compatibilityFlags: [...(config.compatibility_flags ?? [])].sort(),
		limits: camelKeys(config.limits ?? {}),
		observability: camelKeys(config.observability ?? {}),
		tailConsumers: (config.tail_consumers ?? []).map((t) => t.service).sort(),
	};

	for (const [name, value] of Object.entries(config.vars ?? {})) {
		bindings.push(typeof value === 'string' ? binding(name, 'text', value) : binding(name, 'json', canon(value)));
	}
	for (const s of config.services ?? []) {
		bindings.push(
			binding(s.binding, 'worker', s.service, { entrypoint: s.entrypoint, props: s.props === undefined ? undefined : canon(s.props) }),
		);
	}
	for (const kv of config.kv_namespaces ?? []) bindings.push(binding(kv.binding, 'kv', kv.id));
	for (const d1 of config.d1_databases ?? []) bindings.push(binding(d1.binding, 'd1', d1.database_id, { name: d1.database_name }));
	for (const r2 of config.r2_buckets ?? []) bindings.push(binding(r2.binding, 'r2', r2.bucket_name, { jurisdiction: r2.jurisdiction }));
	for (const ae of config.analytics_engine_datasets ?? []) bindings.push(binding(ae.binding, 'analytics-engine-dataset', ae.dataset));
	const queues = knownKeys(config.queues, ['producers', 'consumers'], 'queues', unmapped);
	for (const p of queues.producers ?? []) bindings.push(binding(p.binding, 'queue', p.queue, { deliveryDelay: p.delivery_delay }));
	const secrets = knownKeys(config.secrets, ['required'], 'secrets', unmapped);
	for (const name of secrets.required ?? []) bindings.push(binding(name, 'secret', null));
	const dos = knownKeys(config.durable_objects, ['bindings'], 'durable_objects', unmapped);
	for (const d of dos.bindings ?? []) {
		bindings.push(binding(d.name, 'durable-object', d.class_name, { worker: d.script_name ?? config.name }));
	}

	const trig = knownKeys(config.triggers, ['crons'], 'triggers', unmapped);
	for (const schedule of trig.crons ?? []) triggers.push({ kind: 'cron', schedule });
	for (const c of queues.consumers ?? []) {
		const { queue, ...rest } = camelKeys(c);
		triggers.push({ kind: 'queue', queue, ...rest });
	}
	triggers.sort((a, b) => canon(a).localeCompare(canon(b)));

	return {
		bindings: sortBindings(bindings),
		triggers,
		settings,
		durableObjectClasses: foldMigrations(config.migrations, unmapped),
		unmapped,
	};
}

/** The resourceId + options for one cf `env` entry, by type. */
function cfBinding(name, entry) {
	const { type, ...rest } = entry;
	switch (type) {
		case 'text':
			return binding(name, 'text', rest.value);
		case 'json':
			return binding(name, 'json', canon(rest.value));
		case 'secret':
			return binding(name, 'secret', null);
		case 'worker':
			return binding(name, 'worker', rest.worker, {
				entrypoint: rest.exportName,
				props: rest.props === undefined ? undefined : canon(rest.props),
			});
		case 'durable-object':
			return binding(name, 'durable-object', rest.exportName, { worker: rest.worker });
		case 'kv':
			return binding(name, 'kv', rest.id);
		case 'd1':
			return binding(name, 'd1', rest.id, { name: rest.name });
		case 'r2':
			return binding(name, 'r2', rest.name, { jurisdiction: rest.jurisdiction });
		case 'queue':
			return binding(name, 'queue', rest.name, { deliveryDelay: rest.deliveryDelay });
		case 'analytics-engine-dataset':
			return binding(name, 'analytics-engine-dataset', rest.name);
		default:
			// A binding type this script does not know still gets compared — by its whole body — never skipped.
			return binding(name, String(type), canon(rest));
	}
}

/** Normalise a parsed cf worker.config.json. */
export function normalizeCf(config) {
	const unmapped = [];
	const handled = new Set([
		'name',
		'compatibilityDate',
		'compatibilityFlags',
		'limits',
		'observability',
		'tailConsumers',
		'triggers',
		'env',
		'exports',
	]);
	for (const key of Object.keys(config)) {
		if (!handled.has(key) && !CF_IGNORED_KEYS.has(key)) unmapped.push(key);
	}

	const settings = {
		name: config.name ?? null,
		compatibilityDate: config.compatibilityDate ?? null,
		compatibilityFlags: [...(config.compatibilityFlags ?? [])].sort(),
		limits: config.limits ?? {},
		observability: config.observability ?? {},
		tailConsumers: (config.tailConsumers ?? []).map((t) => t.worker).sort(),
	};
	const bindings = Object.entries(config.env ?? {}).map(([name, entry]) => cfBinding(name, entry));

	const triggers = [];
	for (const t of config.triggers ?? []) {
		if (t.type === 'scheduled') triggers.push({ kind: 'cron', schedule: t.schedule });
		else if (t.type === 'queue') {
			const { type: _type, name, ...rest } = t;
			triggers.push({ kind: 'queue', queue: name, ...rest });
		} else unmapped.push(`triggers[type=${t.type}]`);
	}
	triggers.sort((a, b) => canon(a).localeCompare(canon(b)));

	const durableObjectClasses = {};
	for (const [name, entry] of Object.entries(config.exports ?? {})) {
		if (entry.type === 'durable-object') durableObjectClasses[name] = entry.storage === 'sqlite' ? 'sqlite' : 'kv';
		else unmapped.push(`exports.${name}[type=${entry.type}]`);
	}

	return { bindings: sortBindings(bindings), triggers, settings, durableObjectClasses, unmapped };
}

/** Flatten a normalised config to key -> [values]; repeated keys are kept (a duplicate binding name is a diff). */
function flatten(side, normalized) {
	const rows = [];
	for (const b of normalized.bindings) rows.push([`binding ${b.binding}`, b]);
	for (const t of normalized.triggers)
		rows.push([t.kind === 'cron' ? `trigger cron ${t.schedule}` : `trigger queue consumer ${t.queue}`, t]);
	for (const [k, v] of Object.entries(normalized.settings)) rows.push([`setting ${k}`, v]);
	for (const [cls, storage] of Object.entries(normalized.durableObjectClasses)) rows.push([`durable object class ${cls}`, storage]);
	for (const u of normalized.unmapped) rows.push([`unmapped ${side} key ${u}`, 'present']);
	const grouped = new Map();
	for (const [key, value] of rows) {
		if (!grouped.has(key)) grouped.set(key, []);
		grouped.get(key).push(value);
	}
	return grouped;
}

/** Display form: text var values are replaced by a short hash so webhook-style values never reach a log. */
function show(value) {
	const redact = (v) => {
		if (Array.isArray(v)) return v.map(redact);
		if (!isObject(v)) return v;
		if (v.type === 'text' && typeof v.resourceId === 'string') {
			return { ...v, resourceId: `sha256:${createHash('sha256').update(v.resourceId).digest('hex').slice(0, 12)}` };
		}
		return v;
	};
	return canon(redact(value));
}

/** Differences between two normalised configs as human-readable lines; empty means parity. */
export function diffNormalized(wrangler, cf) {
	const a = flatten('wrangler', wrangler);
	const b = flatten('cf', cf);
	const lines = [];
	for (const key of [...new Set([...a.keys(), ...b.keys()])].sort()) {
		const left = a.get(key);
		const right = b.get(key);
		if (!right) lines.push(`only in wrangler.production.jsonc: ${key} = ${show(left)}`);
		else if (!left) lines.push(`only in cf worker.config.json:  ${key} = ${show(right)}`);
		else if (canon(left) !== canon(right)) lines.push(`differs: ${key}\n    wrangler: ${show(left)}\n    cf:       ${show(right)}`);
	}
	return lines;
}

/** Compare two parsed configs. */
export function compareConfigs(wranglerConfig, cfConfig) {
	return diffNormalized(normalizeWrangler(wranglerConfig), normalizeCf(cfConfig));
}

function readConfig(path, label, parse) {
	try {
		return { value: parse(readFileSync(path, 'utf8')) };
	} catch (error) {
		return { error: `Cannot read ${label} at ${path}: ${error instanceof Error ? error.message : String(error)}` };
	}
}

/** CLI entry. Returns the process exit code; `out`/`err` receive the lines. */
export function main(argv, out = console.log, err = console.error) {
	let cfPath = DEFAULT_CF_CONFIG;
	let wranglerPath = DEFAULT_WRANGLER_CONFIG;
	for (let i = 0; i < argv.length; i += 1) {
		if (argv[i] === '--cf' && argv[i + 1]) cfPath = argv[++i];
		else if (argv[i] === '--wrangler' && argv[i + 1]) wranglerPath = argv[++i];
		else {
			err(`Unknown argument "${argv[i]}". Usage: cf-binding-diff.mjs [--cf <worker.config.json>] [--wrangler <wrangler.production.jsonc>]`);
			return 2;
		}
	}
	const cf = readConfig(
		cfPath,
		'the cf worker.config.json (run `cf build --mode production` from packages/bv-dns-security-mcp first)',
		JSON.parse,
	);
	const wrangler = readConfig(wranglerPath, 'wrangler.production.jsonc (run `node scripts/inject-private-config.cjs` first)', parseJsonc);
	const failed = [cf, wrangler].filter((r) => r.error);
	if (failed.length > 0) {
		for (const f of failed) err(f.error);
		return 2;
	}
	const lines = compareConfigs(wrangler.value, cf.value);
	if (lines.length === 0) {
		const normalized = normalizeCf(cf.value);
		out(
			`cf-binding-parity: OK — ${normalized.bindings.length} bindings, ${normalized.triggers.length} triggers, ` +
				`${Object.keys(normalized.durableObjectClasses).length} Durable Object classes identical.`,
		);
		return 0;
	}
	err(
		`cf-binding-parity: FAIL — ${lines.length} difference${lines.length === 1 ? '' : 's'} between wrangler.production.jsonc and the cf build:`,
	);
	for (const line of lines) err(`  ${line}`);
	return 1;
}

const invokedDirectly = process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
if (invokedDirectly) process.exit(main(process.argv.slice(2)));
