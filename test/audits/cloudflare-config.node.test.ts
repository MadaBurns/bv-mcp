// Audit test for packages/bv-dns-security-mcp/cloudflare.config.ts (US-8 Phase 5.2, SQ-255): the cf deploy config
// for bv-dns-security-mcp. Successor of wrangler-public-no-private-bindings.audit.test.ts for the cf door.
//
// The expected output is never a hand list: it is rendered from the SAME inputs the Wrangler-door
// injector uses — mergeOverlay(wrangler.jsonc, overlay) from scripts/lib/overlay-merge.mjs — through
// the codemod's wrangler→cf rendering (spike ledger L34). So this pins cf-door/injector parity.
// Node pool: reads wrangler.jsonc and overlay fixtures with real node:fs.

import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import config, {
	NON_PRODUCTION_WORKER_NAME,
	PRODUCTION_OVERLAY_PATH,
	PRODUCTION_WORKER_NAME,
	buildCloudflareConfig,
} from '../../packages/bv-dns-security-mcp/cloudflare.config';
import { mergeOverlay, parseJsonc } from '../../scripts/lib/overlay-merge.mjs';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- loosely-typed wrangler/cf config objects
type Json = Record<string, any>;

const root = process.cwd();
const PACKAGE_DIR = 'packages/bv-dns-security-mcp';
const examplePath = join(root, 'wrangler.private.example.jsonc');
const loadPublic = (): Json => parseJsonc(readFileSync(join(root, 'wrangler.jsonc'), 'utf8'));
const loadExample = (): Json => parseJsonc(readFileSync(examplePath, 'utf8'));

const scratch = mkdtempSync(join(tmpdir(), 'cf-config-audit-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
let fixtureCount = 0;
function writeOverlay(overlay: Json): string {
	const path = join(scratch, `overlay-${fixtureCount++}.jsonc`);
	writeFileSync(path, JSON.stringify(overlay));
	return path;
}

const worker = (mode: string | undefined, overlayPath?: string): Json => (buildCloudflareConfig({ mode, overlayPath }) as Json).worker;
const production = (overlayPath = examplePath): Json => worker('production', overlayPath);

/** Drop undefined-valued keys so an absent optional field compares equal to an omitted one. */
const compact = (value: Json): Json => Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined));

/**
 * The codemod's wrangler→cf rendering (cf migrate, spike ledger L34), applied to a wrangler-shaped
 * config. `workerName` replaces self-references (the DO host Worker and the self tail consumer), so
 * the public shape renders under the -dev name exactly as wrangler.jsonc renders under its own.
 */
function renderEnv(cfg: Json, workerName: string): Json {
	const self = (name: string | undefined) => (name === undefined || name === cfg.name ? workerName : name);
	const env: Json = {};
	for (const [name, value] of Object.entries(cfg.vars ?? {})) env[name] = { type: 'text', value };
	for (const s of cfg.services ?? []) env[s.binding] = compact({ type: 'worker', worker: s.service, exportName: s.entrypoint });
	for (const d of cfg.durable_objects?.bindings ?? [])
		env[d.name] = { type: 'durable-object', worker: self(d.script_name), exportName: d.class_name };
	for (const k of cfg.kv_namespaces ?? []) env[k.binding] = { type: 'kv', id: k.id };
	for (const d of cfg.d1_databases ?? []) env[d.binding] = { type: 'd1', name: d.database_name, id: d.database_id };
	for (const r of cfg.r2_buckets ?? []) env[r.binding] = compact({ type: 'r2', name: r.bucket_name, jurisdiction: r.jurisdiction });
	for (const a of cfg.analytics_engine_datasets ?? []) env[a.binding] = { type: 'analytics-engine-dataset', name: a.dataset };
	for (const p of cfg.queues?.producers ?? []) env[p.binding] = compact({ type: 'queue', name: p.queue, deliveryDelay: p.delivery_delay });
	for (const name of cfg.secrets?.required ?? []) env[name] = { type: 'secret' };
	return env;
}

function renderTriggers(cfg: Json): Json[] {
	const crons = (cfg.triggers?.crons ?? []).map((schedule: string) => ({ type: 'scheduled', schedule }));
	const consumers = (cfg.queues?.consumers ?? []).map((c: Json) =>
		compact({
			type: 'queue',
			name: c.queue,
			maxBatchSize: c.max_batch_size,
			maxBatchTimeout: c.max_batch_timeout,
			maxRetries: c.max_retries,
			deadLetterQueue: c.dead_letter_queue,
			maxConcurrency: c.max_concurrency,
			retryDelay: c.retry_delay,
		}),
	);
	return [...crons, ...consumers];
}

/** Everything a wrangler-shaped config pins beyond bindings and triggers. */
function renderWorkerShape(cfg: Json, workerName: string): Json {
	const self = (name: string) => (name === cfg.name ? workerName : name);
	return {
		name: workerName,
		compatibilityDate: cfg.compatibility_date,
		compatibilityFlags: cfg.compatibility_flags,
		// The config lives two levels down; the entry stays in the root tree.
		entrypoint: `../../${cfg.main}`,
		limits: { cpuMs: cfg.limits.cpu_ms },
		observability: {
			enabled: cfg.observability.enabled,
			logs: { headSamplingRate: cfg.observability.logs.head_sampling_rate, invocationLogs: cfg.observability.logs.invocation_logs },
			traces: { enabled: cfg.observability.traces.enabled, headSamplingRate: cfg.observability.traces.head_sampling_rate },
		},
		tailConsumers: (cfg.tail_consumers ?? []).map((t: Json) => ({ worker: self(t.service) })),
	};
}

const pickShape = (w: Json): Json => ({
	name: w.name,
	compatibilityDate: w.compatibilityDate,
	compatibilityFlags: w.compatibilityFlags,
	entrypoint: w.entrypoint,
	limits: w.limits,
	observability: w.observability,
	tailConsumers: w.tailConsumers,
});

/** Binding names the BSL public shape must never carry (mirrors wrangler-public-no-private-bindings). */
const FORBIDDEN_PUBLIC_BINDINGS = [
	'BV_INFRA_GRAPH',
	'BV_INTEL_GATEWAY',
	'BV_ENTERPRISE',
	'BV_RECON',
	'BV_RECON_KEY',
	'BV_TLS_PROBE',
	'BV_TLS_PROBE_KEY',
];
const PRIVATE_RESOURCE_TYPES = ['kv', 'd1', 'r2', 'analytics-engine-dataset', 'queue', 'secret'];
const NON_PRODUCTION_MODES = [undefined, 'development', 'staging', 'Production', ''];

describe('(a) non-production mode is the public shape only', () => {
	it.each(NON_PRODUCTION_MODES)('mode %j: no KV/D1/R2/AE/queue/secret bindings, no private services, no queue consumers', (mode) => {
		const w = worker(mode);
		const types = Object.values(w.env).map((binding) => (binding as Json).type);
		expect(types.filter((type) => PRIVATE_RESOURCE_TYPES.includes(type))).toEqual([]);
		expect(Object.keys(w.env).filter((name) => FORBIDDEN_PUBLIC_BINDINGS.includes(name))).toEqual([]);

		const publicServices = (loadPublic().services as Json[]).map((s) => s.binding).sort();
		const services = Object.entries(w.env)
			.filter(([, binding]) => (binding as Json).type === 'worker')
			.map(([name]) => name)
			.sort();
		expect(services).toEqual(publicServices);
		expect(w.triggers.filter((t: Json) => t.type !== 'scheduled')).toEqual([]);
	});

	it('renders exactly what the public wrangler.jsonc declares', () => {
		const pub = loadPublic();
		const w = worker(undefined);
		expect(w.env).toEqual(renderEnv(pub, NON_PRODUCTION_WORKER_NAME));
		expect(w.triggers).toEqual(renderTriggers(pub));
		expect(pickShape(w)).toEqual(renderWorkerShape(pub, NON_PRODUCTION_WORKER_NAME));
	});

	it('never reads the overlay outside production', () => {
		expect(() => worker(undefined, join(scratch, 'does-not-exist.jsonc'))).not.toThrow();
	});

	it('the default export passes mode through to the same builder', async () => {
		const factory = config as unknown as (ctx: { mode: string | undefined; isPreview: boolean }) => unknown;
		expect(await factory({ mode: undefined, isPreview: false })).toEqual(buildCloudflareConfig({ mode: undefined }));
		expect(await factory({ mode: 'development', isPreview: false })).toEqual(buildCloudflareConfig({ mode: 'development' }));
	});
});

describe('(b) production mode fails closed', () => {
	it('throws when the overlay file is missing', () => {
		const missing = join(scratch, 'no-such-dir', 'wrangler.deploy.jsonc');
		expect(() => production(missing)).toThrow(/wrangler\.deploy\.jsonc/);
	});

	it('throws on an overlay key the merge does not handle (validateOverlayKeys)', () => {
		const path = writeOverlay({ ...loadExample(), hyperdrive: [{ binding: 'HD', id: 'x' }] });
		expect(() => production(path)).toThrow(/"hyperdrive"/);
	});

	it('throws when the overlay overrides a fatal-on-drift public key', () => {
		const path = writeOverlay({ ...loadExample(), name: 'some-other-worker' });
		expect(() => production(path)).toThrow(/"name"/);
	});

	it('throws when a required production var is missing or wrong', () => {
		const missing = loadExample();
		delete missing.vars.REQUIRE_PRODUCTION_BINDINGS;
		expect(() => production(writeOverlay(missing))).toThrow(/REQUIRE_PRODUCTION_BINDINGS/);
		const wrong = loadExample();
		wrong.vars.OAUTH_ISSUER = 'https://evil.example';
		expect(() => production(writeOverlay(wrong))).toThrow(/OAUTH_ISSUER/);
	});

	it('throws on an overlay binding cloudflare.config.ts does not declare, instead of dropping it', () => {
		const overlay = loadExample();
		overlay.kv_namespaces.push({ binding: 'UNDECLARED_KV', id: 'undeclared-id' });
		expect(() => production(writeOverlay(overlay))).toThrow(/UNDECLARED_KV/);
	});

	it('throws on a binding field the cf rendering would silently drop', () => {
		const overlay = loadExample();
		overlay.queues.producers[0].unexpected_field = 1;
		expect(() => production(writeOverlay(overlay))).toThrow(/unexpected_field/);
	});
});

describe('(c) production mode matches the injector (mergeOverlay) binding for binding', () => {
	it('example overlay: same binding names, types and IDs, same crons and queue consumers', () => {
		const merged = mergeOverlay(loadPublic(), loadExample());
		const w = production();
		expect(w.env).toEqual(renderEnv(merged, PRODUCTION_WORKER_NAME));
		expect(w.triggers).toEqual(renderTriggers(merged));
		expect(pickShape(w)).toEqual(renderWorkerShape(merged, PRODUCTION_WORKER_NAME));
	});

	it('takes every private ID from the overlay, none from the config source', () => {
		const overlay = loadExample();
		overlay.kv_namespaces[0].id = 'id-from-overlay-only';
		const w = production(writeOverlay(overlay));
		expect(w.env[overlay.kv_namespaces[0].binding]).toEqual({ type: 'kv', id: 'id-from-overlay-only' });
		expect(readFileSync(join(root, PACKAGE_DIR, 'cloudflare.config.ts'), 'utf8')).not.toContain('YOUR_RATE_LIMIT_KV_NAMESPACE_ID');
	});

	it('overlay with every supported binding kind, overrides and per-tenant D1s: still exact parity', () => {
		const overlay = loadExample();
		overlay.services = [
			{ binding: 'BV_WEB', service: 'bv-web-override', entrypoint: 'InternalApi' },
			{ binding: 'BV_RECON', service: 'recon-target' },
		];
		overlay.d1_databases = [
			{ binding: 'TENANT_REGISTRY_DB', database_name: 'registry', database_id: 'reg-id', migrations_dir: 'migrations/registry' },
			{ binding: 'TENANT_DB_ACME', database_name: 'tenant-acme', database_id: 'acme-id' },
		];
		overlay.r2_buckets = [{ binding: 'BRAND_REPORTS', bucket_name: 'reports', jurisdiction: 'eu' }];
		overlay.queues.producers.push({ binding: 'BRAND_AUDIT_QUEUE', queue: 'brand-audit', delivery_delay: 5 });
		overlay.queues.consumers.push({ queue: 'brand-audit', max_batch_size: 1, max_batch_timeout: 30, max_concurrency: 2, retry_delay: 10 });
		overlay.vars.OVERLAY_ONLY_VAR = 'overlay-value';
		const merged = mergeOverlay(loadPublic(), overlay);
		const w = production(writeOverlay(overlay));
		expect(w.env).toEqual(renderEnv(merged, PRODUCTION_WORKER_NAME));
		expect(w.triggers).toEqual(renderTriggers(merged));
	});
});

describe('(d) Durable Object exports replace wrangler migrations', () => {
	it.each([undefined, 'production'])('mode %j: exactly QuotaCoordinator and ProfileAccumulator, both SQLite', (mode) => {
		const w = mode === 'production' ? production() : worker(mode);
		expect(w.exports).toEqual({
			QuotaCoordinator: { type: 'durable-object', storage: 'sqlite' },
			ProfileAccumulator: { type: 'durable-object', storage: 'sqlite' },
		});
	});

	it('matches the SQLite classes created by the wrangler.jsonc migrations', () => {
		const sqliteClasses = (loadPublic().migrations as Json[]).flatMap((m) => m.new_sqlite_classes ?? []).sort();
		expect(Object.keys(worker(undefined).exports).sort()).toEqual(sqliteClasses);
	});
});

describe('(e) worker-name split (US-8 Decision 6)', () => {
	it('production deploys as bv-dns-security-mcp; every other mode as bv-dns-security-mcp-dev', () => {
		expect(PRODUCTION_WORKER_NAME).toBe('bv-dns-security-mcp');
		expect(NON_PRODUCTION_WORKER_NAME).toBe('bv-dns-security-mcp-dev');
		expect(production().name).toBe(PRODUCTION_WORKER_NAME);
		for (const mode of NON_PRODUCTION_MODES) expect(worker(mode).name).toBe(NON_PRODUCTION_WORKER_NAME);
	});

	it('the -dev shape never binds to or tails into the production Worker', () => {
		expect(JSON.stringify(worker(undefined))).not.toContain(`"${PRODUCTION_WORKER_NAME}"`);
	});
});

// cf refuses to build at the root of an npm workspace ("The Cloudflare application detection logic has been run in
// the root of a workspace…", cf 1.0.0-beta.9 and beta.10), so the config lives in a config-only workspace package.
describe('(f) config-only workspace package', () => {
	const pkg = JSON.parse(readFileSync(join(root, PACKAGE_DIR, 'package.json'), 'utf8'));
	const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));

	it('leaves no cf config at the repo root, where cf build is refused', () => {
		expect(existsSync(join(root, 'cloudflare.config.ts'))).toBe(false);
		expect(existsSync(join(root, 'wrangler.config.ts'))).toBe(false);
	});

	it('pins cf exactly to the version measured for function-form configs (beta.5 types them as an empty Env)', () => {
		expect(pkg.private).toBe(true);
		expect(pkg.devDependencies.cf).toBe('1.0.0-beta.9');
	});

	// cf finds wrangler ONLY at <package>/node_modules/wrangler (measured on beta.9: with just the root-hoisted copy,
	// `cf build` fails "wrangler is declared in …/package.json but is not installed"). npm hoists a wrangler matching
	// the root's to the root, so the package pins an exact version the root does not resolve to.
	it('keeps a nested wrangler install so cf can discover it', () => {
		const nested = lock.packages[`${PACKAGE_DIR}/node_modules/wrangler`];
		expect(nested?.version).toBe(pkg.devDependencies.wrangler);
		expect(nested.version).not.toBe(lock.packages['node_modules/wrangler'].version);
	});

	it('reads every file from the repo root, whatever the cwd', () => {
		expect(PRODUCTION_OVERLAY_PATH).toBe(join(root, '.dev', 'wrangler.deploy.jsonc'));
		const cwd = process.cwd();
		process.chdir(scratch);
		try {
			expect(worker(undefined).env.BV_WEB).toEqual({ type: 'worker', worker: 'bv-web-prod' });
		} finally {
			process.chdir(cwd);
		}
	});
});
