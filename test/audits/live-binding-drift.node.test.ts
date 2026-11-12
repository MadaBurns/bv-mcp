// SPDX-License-Identifier: BUSL-1.1
//
// Contract for scripts/ci/live-binding-drift.mjs (`npm run check:live-binding-drift`, bindings audit 2026-11-13).
// A live payload mirroring the merged config must compare clean; each single mutation must surface as exactly the
// error/warning it is, without printing var values or resource ids; an empty live set must never read as clean.
// Node pool: reads real config files and spawns nothing (live data comes from --live-json fixtures).

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { compareLiveBindings, expectedBindings, liveBindings, main, scanCodeEnvNames } from '../../scripts/ci/live-binding-drift.mjs';
import { mergeOverlay, parseJsonc } from '../../scripts/lib/overlay-merge.mjs';
import { readFileSync } from 'node:fs';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- fixture objects are mutated through arbitrary nested paths
type Json = Record<string, any>;

const root = process.cwd();
const publicPath = join(root, 'wrangler.jsonc');
const examplePath = join(root, 'wrangler.private.example.jsonc');
const merged = (): Json => mergeOverlay(parseJsonc(readFileSync(publicPath, 'utf8')), parseJsonc(readFileSync(examplePath, 'utf8')));
const SECRET_VALUE = 'https://hooks.example.test/very-secret-token';

/** A `versions view` payload that matches a merged config exactly. */
function liveFor(config: Json, id = 'v-1'): Json {
	const b: Json[] = [];
	for (const e of config.kv_namespaces ?? []) b.push({ name: e.binding, type: 'kv_namespace', namespace_id: e.id });
	for (const e of config.d1_databases ?? []) b.push({ name: e.binding, type: 'd1', id: e.database_id, database_id: e.database_id });
	for (const e of config.r2_buckets ?? []) b.push({ name: e.binding, type: 'r2_bucket', bucket_name: e.bucket_name });
	for (const e of config.analytics_engine_datasets ?? []) b.push({ name: e.binding, type: 'analytics_engine', dataset: e.dataset });
	for (const e of config.services ?? []) b.push({ name: e.binding, type: 'service', service: e.service, environment: 'production' });
	for (const e of config.durable_objects?.bindings ?? [])
		b.push({ name: e.name, type: 'durable_object_namespace', class_name: e.class_name });
	for (const e of config.queues?.producers ?? []) b.push({ name: e.binding, type: 'queue', queue_name: e.queue });
	for (const [name, text] of Object.entries(config.vars ?? {})) b.push({ name, type: 'plain_text', text });
	for (const name of config.secrets?.required ?? []) b.push({ name, type: 'secret_text' });
	return { id, resources: { bindings: b } };
}

const compare = (config: Json, live: Json, codeNames: string[] = []) =>
	compareLiveBindings({
		expected: expectedBindings(config),
		live: liveBindings(live),
		consumers: config.queues?.consumers ?? [],
		codeNames,
	});

describe('compareLiveBindings', () => {
	it('positive control: live mirroring the merged config has no errors', () => {
		const config = merged();
		const result = compare(config, liveFor(config));
		expect(result.errors).toEqual([]);
		expect(expectedBindings(config).size).toBeGreaterThan(20);
	});

	it('reports a binding missing live', () => {
		const config = merged();
		const live = liveFor(config);
		live.resources.bindings = live.resources.bindings.filter((b: Json) => b.name !== 'BRAND_AUDIT_DB');
		expect(compare(config, live).errors).toEqual(['BRAND_AUDIT_DB (d1) is missing live']);
	});

	it('reports a live binding nobody reviewed', () => {
		const config = merged();
		const live = liveFor(config);
		live.resources.bindings.push({ name: 'ROGUE_KV', type: 'kv_namespace', namespace_id: 'x' });
		expect(compare(config, live).errors).toEqual(['ROGUE_KV (kv_namespace) is bound live but not in the reviewed config']);
	});

	it('reports a changed target without printing either resource id', () => {
		const config = merged();
		const live = liveFor(config);
		live.resources.bindings.find((b: Json) => b.name === 'INTELLIGENCE_DB').id = 'live-only-database-id';
		const { errors } = compare(config, live);
		expect(errors).toEqual(['INTELLIGENCE_DB (d1): target differs']);
		expect(errors.join('\n')).not.toContain('live-only-database-id');
	});

	it('reports a changed var value without printing either value', () => {
		const config = merged();
		config.vars.WEBHOOKISH = SECRET_VALUE;
		const live = liveFor(config);
		live.resources.bindings.find((b: Json) => b.name === 'WEBHOOKISH').text = `${SECRET_VALUE}-changed`;
		const { errors } = compare(config, live);
		expect(errors).toEqual(['var WEBHOOKISH: value differs']);
		expect(errors.join('\n')).not.toContain('very-secret-token');
	});

	it('reports a required secret missing from the version, but not an extra fail-soft secret', () => {
		const config = merged();
		const live = liveFor(config);
		live.resources.bindings = live.resources.bindings.filter((b: Json) => b.name !== 'KV_ENVELOPE_KEY');
		live.resources.bindings.push({ name: 'CERTSPOTTER_TOKEN', type: 'secret_text' });
		expect(compare(config, live).errors).toEqual(['required secret KV_ENVELOPE_KEY is not set on the deployed version']);
	});

	it('warns on a queue consumer without a dead_letter_queue', () => {
		const config = merged();
		expect(compare(config, liveFor(config)).warnings).toEqual([]);
		delete config.queues.consumers[1].dead_letter_queue;
		expect(compare(config, liveFor(config)).warnings).toEqual([
			`queue consumer ${config.queues.consumers[1].queue} has no dead_letter_queue (config; exhausted messages are dropped)`,
		]);
	});

	it('lists unbound code-read names as info, skipping known names and TENANT_DB_ prefixes', () => {
		const config = merged();
		const { info, errors } = compare(config, liveFor(config), ['SCAN_CACHE', 'TENANT_DB_ACME', 'DARK_FEATURE_DB']);
		expect(errors).toEqual([]);
		expect(info).toEqual(['code reads env.DARK_FEATURE_DB, which nothing binds (optional/dark, or a typo)']);
	});
});

describe('scanCodeEnvNames', () => {
	it('finds names the real src reads (positive control)', () => {
		const names = scanCodeEnvNames(join(root, 'src'));
		expect(names.has('SCAN_CACHE')).toBe(true);
		expect(names.has('BV_SCANNER_SLOW_QUEUE')).toBe(true);
	});
});

describe('main (CLI exit codes, --live-json fixtures)', () => {
	const dir = mkdtempSync(join(tmpdir(), 'live-binding-drift-'));
	afterAll(() => rmSync(dir, { recursive: true, force: true }));
	const src = join(dir, 'src');
	mkdirSync(src);
	writeFileSync(join(src, 'x.ts'), 'export const f = (env: { SCAN_CACHE: unknown }) => env.SCAN_CACHE;\n');
	const run = (versions: unknown) => {
		const live = join(dir, `live-${Math.random()}.json`);
		writeFileSync(live, JSON.stringify(versions));
		const lines: string[] = [];
		const code = main(['--overlay', examplePath, '--public', publicPath, '--live-json', live], {
			out: (l: string) => lines.push(l),
			err: (l: string) => lines.push(l),
			srcDir: src,
		});
		return { code, lines };
	};

	it('exits 0 when every deployed version matches', () => {
		const { code, lines } = run([liveFor(merged())]);
		expect(code).toBe(0);
		expect(lines[0]).toMatch(/^live-binding-drift: OK — version v-1:/);
	});

	it('exits 1 on drift in any one deployed version (gradual rollout)', () => {
		const drifted = liveFor(merged(), 'v-2');
		drifted.resources.bindings = drifted.resources.bindings.filter((b: Json) => b.name !== 'RATE_LIMIT');
		const { code, lines } = run([liveFor(merged()), drifted]);
		expect(code).toBe(1);
		expect(lines).toContain('  ERROR RATE_LIMIT (kv_namespace) is missing live');
	});

	it('exits 2, never 0, when live returns no versions or no bindings', () => {
		expect(run([]).code).toBe(2);
		expect(run([{ id: 'v-1', resources: { bindings: [] } }]).code).toBe(2);
	});

	it('summarises unbound code-read names as one line unless --verbose', () => {
		const withDark = join(src, 'dark.ts');
		writeFileSync(withDark, 'export const g = (env: { DARK_ONE?: string }) => env.DARK_ONE;\n');
		const { lines } = run([liveFor(merged())]);
		expect(lines).toContain('  INFO  1 env names read by src/ are unbound (optional/dark); --verbose lists them');
		rmSync(withDark);
	});

	it('exits 2 when an input file cannot be read', () => {
		const lines: string[] = [];
		const code = main(['--overlay', join(dir, 'missing.jsonc'), '--public', publicPath, '--live-json', join(dir, 'x.json')], {
			out: (l: string) => lines.push(l),
			err: (l: string) => lines.push(l),
			srcDir: src,
		});
		expect(code).toBe(2);
		expect(lines[0]).toMatch(/^live-binding-drift: cannot read inputs/);
	});
});
