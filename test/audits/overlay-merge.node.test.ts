// Unit tests for the pure overlay-merge core (scripts/lib/overlay-merge.mjs), extracted from
// scripts/inject-private-config.cjs in SQ-254 (Phase 5.1). The injector's end-to-end behaviour is
// pinned by private-config-injection.node.test.ts; these pin the module's own contract, against
// the real wrangler.private.example.jsonc template so a template/merge-rule drift fails here.
// Node pool: reads the template with real node:fs (the Workers pool has no filesystem).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
	OVERLAY_FATAL_ON_DRIFT,
	OVERLAY_MERGED_KEYS,
	OVERLAY_PATH_RELATIVE_KEYS,
	OVERLAY_PUBLIC_OWNED_KEYS,
	OverlayValidationError,
	PRODUCTION_REQUIRED_SECRETS,
	REQUIRED_PRODUCTION_VARS,
	mergeOverlay,
	parseJsonc,
	validateOverlayKeys,
} from '../../scripts/lib/overlay-merge.mjs';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- loosely-typed wrangler config fixtures
type Json = Record<string, any>;

const root = process.cwd();
const examplePath = join(root, 'wrangler.private.example.jsonc');
const loadExample = (): Json => parseJsonc(readFileSync(examplePath, 'utf8'));
const loadPublic = (): Json => parseJsonc(readFileSync(join(root, 'wrangler.jsonc'), 'utf8'));

describe('parseJsonc', () => {
	it('parses the commented example overlay', () => {
		const overlay = loadExample();
		expect(overlay.kv_namespaces.map((entry: Json) => entry.binding)).toContain('RATE_LIMIT');
		expect(overlay.vars.OAUTH_ISSUER).toBe('https://dns-mcp.blackveilsecurity.com');
	});

	it('keeps comment-looking text inside string literals', () => {
		expect(parseJsonc('{ "url": "https://x.test/a//b", /* c */ "n": 1 // tail\n }')).toEqual({ url: 'https://x.test/a//b', n: 1 });
	});
});

describe('mergeOverlay', () => {
	const publicBase = (): Json => ({
		name: 'bv-mcp-test',
		compatibility_date: '2026-01-01',
		services: [
			{ binding: 'BV_WEB', service: 'blackveil-web' },
			{ binding: 'BV_WHOIS', service: 'bv-whois' },
		],
		vars: { KEEP: 'public', SHARED: 'public' },
		kv_namespaces: [{ binding: 'PUBLIC_KV', id: 'public-id' }],
	});

	it('merges services by binding name: overlay wins, public-only entries survive, overlay-only entries are added', () => {
		const merged = mergeOverlay(publicBase(), {
			services: [
				{ binding: 'BV_WEB', service: 'blackveil-web-prod' },
				{ binding: 'BV_CERTSTREAM', service: 'bv-certstream-worker' },
			],
		});
		expect(merged.services).toEqual([
			{ binding: 'BV_WEB', service: 'blackveil-web-prod' },
			{ binding: 'BV_WHOIS', service: 'bv-whois' },
			{ binding: 'BV_CERTSTREAM', service: 'bv-certstream-worker' },
		]);
	});

	it('merges vars shallowly with the overlay winning', () => {
		const merged = mergeOverlay(publicBase(), { vars: { SHARED: 'overlay', ADDED: 'overlay' } });
		expect(merged.vars).toEqual({ KEEP: 'public', SHARED: 'overlay', ADDED: 'overlay' });
	});

	it('replaces queues, kv_namespaces, d1_databases, analytics_engine_datasets and r2_buckets wholesale', () => {
		const overlay: Json = {
			queues: { producers: [{ binding: 'Q', queue: 'q' }], consumers: [{ queue: 'q', dead_letter_queue: 'q-dlq' }] },
			kv_namespaces: [{ binding: 'PRIVATE_KV', id: 'private-id' }],
			d1_databases: [{ binding: 'DB', database_name: 'db', database_id: 'abc' }],
			analytics_engine_datasets: [{ binding: 'AE', dataset: 'ds' }],
			r2_buckets: [{ binding: 'R2', bucket_name: 'b' }],
		};
		const merged = mergeOverlay(publicBase(), overlay);
		for (const key of ['queues', 'kv_namespaces', 'd1_databases', 'analytics_engine_datasets', 'r2_buckets']) {
			expect(merged[key], key).toEqual(overlay[key]);
		}
		// Wholesale, not per-entry: the public kv entry is gone, and unknown consumer fields pass through.
		expect(merged.kv_namespaces).toEqual([{ binding: 'PRIVATE_KV', id: 'private-id' }]);
		expect(merged.queues.consumers[0].dead_letter_queue).toBe('q-dlq');
	});

	it('keeps public values for keys the overlay does not provide', () => {
		const merged = mergeOverlay(publicBase(), {});
		expect(merged.kv_namespaces).toEqual([{ binding: 'PUBLIC_KV', id: 'public-id' }]);
		expect(merged.name).toBe('bv-mcp-test');
		expect(merged.compatibility_date).toBe('2026-01-01');
	});

	it('injects secrets.required and never takes public-owned keys from the overlay', () => {
		const merged = mergeOverlay(publicBase(), { name: 'overlay-name', compatibility_date: '2020-01-01' });
		expect(merged.secrets).toEqual({ required: [...PRODUCTION_REQUIRED_SECRETS] });
		expect(merged.secrets.required).not.toBe(PRODUCTION_REQUIRED_SECRETS);
		expect(merged.name).toBe('bv-mcp-test');
		expect(merged.compatibility_date).toBe('2026-01-01');
	});

	it('is pure: neither input is mutated', () => {
		const base = publicBase();
		const overlay: Json = { vars: { A: '1' }, services: [{ binding: 'X', service: 'x' }], kv_namespaces: [{ binding: 'K', id: 'k' }] };
		const baseBefore = JSON.stringify(base);
		const overlayBefore = JSON.stringify(overlay);
		mergeOverlay(base, overlay);
		expect(JSON.stringify(base)).toBe(baseBefore);
		expect(JSON.stringify(overlay)).toBe(overlayBefore);
	});

	it('merges the real example overlay onto the real public wrangler.jsonc', () => {
		const publicConfig = loadPublic();
		const overlay = loadExample();
		const merged = mergeOverlay(publicConfig, overlay);

		expect(merged.name).toBe(publicConfig.name);
		expect(merged.durable_objects).toEqual(publicConfig.durable_objects);
		expect(merged.kv_namespaces).toEqual(overlay.kv_namespaces);
		expect(merged.analytics_engine_datasets).toEqual(overlay.analytics_engine_datasets);
		expect(merged.queues).toEqual(overlay.queues);
		expect(merged.vars).toMatchObject(overlay.vars);
		for (const [name, value] of Object.entries(REQUIRED_PRODUCTION_VARS)) {
			expect(merged.vars[name], name).toBe(value);
		}
		expect(merged.secrets.required).toContain('BV_API_KEY');
	});
});

describe('validateOverlayKeys', () => {
	it('accepts the example overlay against the public wrangler.jsonc with no warnings', () => {
		expect(validateOverlayKeys(loadExample(), loadPublic())).toEqual({ warnings: [] });
	});

	it('rejects an unknown overlay key, naming it', () => {
		expect(() => validateOverlayKeys({ vars: {}, hyperdrive: [{ binding: 'H' }] }, {})).toThrow(OverlayValidationError);
		expect(() => validateOverlayKeys({ hyperdrive: [] }, {})).toThrow(/declares "hyperdrive", which this script does not merge/);
		// The unknown-key check does not depend on a public base.
		expect(() => validateOverlayKeys({ workflows: [] })).toThrow(/"workflows"/);
	});

	it.each(OVERLAY_FATAL_ON_DRIFT)('rejects a drifted %s as fatal', (key) => {
		const publicConfig: Json = { name: 'a', durable_objects: { bindings: [{ name: 'DO', class_name: 'D' }] }, migrations: [{ tag: 'v1' }] };
		const overlay: Json = { [key]: 'DRIFTED' };
		expect(() => validateOverlayKeys(overlay, publicConfig)).toThrow(
			new RegExp(`overrides "${key}", but the public wrangler.jsonc owns those keys`),
		);
	});

	it('accepts an identical copy of a fatal-on-drift key', () => {
		const publicConfig: Json = { name: 'a', durable_objects: { bindings: [] } };
		expect(validateOverlayKeys({ name: 'a', durable_objects: { bindings: [] } }, publicConfig)).toEqual({ warnings: [] });
	});

	it('warns (does not throw) on non-fatal drift and discards path-relative keys silently', () => {
		const result = validateOverlayKeys({ compatibility_date: '2020-01-01', main: 'x.ts', $schema: 'y' }, { compatibility_date: '2026-01-01' });
		expect(result.warnings).toHaveLength(1);
		expect(result.warnings[0]).toMatch(/^WARNING: overlay compatibility_date differs from wrangler\.jsonc and is being ignored/);
	});

	it('carries earlier drift warnings on the fatal error so the caller can still print them', () => {
		try {
			validateOverlayKeys({ compatibility_date: '2020-01-01', name: 'other' }, { compatibility_date: '2026-01-01', name: 'a' });
			expect.unreachable('expected a fatal OverlayValidationError');
		} catch (error) {
			expect(error).toBeInstanceOf(OverlayValidationError);
			expect((error as OverlayValidationError).warnings).toHaveLength(1);
			expect((error as OverlayValidationError).message).toMatch(/overrides "name"/);
		}
	});
});

describe('exported constant lists', () => {
	it('keep fatal-drift keys inside the public-owned set and merged keys disjoint from the discarded ones', () => {
		for (const key of OVERLAY_FATAL_ON_DRIFT) expect(OVERLAY_PUBLIC_OWNED_KEYS).toContain(key);
		const discarded = new Set([...OVERLAY_PUBLIC_OWNED_KEYS, ...OVERLAY_PATH_RELATIVE_KEYS]);
		for (const key of OVERLAY_MERGED_KEYS) expect(discarded.has(key), key).toBe(false);
	});

	it('pins the three fail-closed production vars', () => {
		expect(REQUIRED_PRODUCTION_VARS).toEqual({
			OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
			REJECT_QUERY_API_KEY: 'true',
			REQUIRE_PRODUCTION_BINDINGS: 'true',
		});
	});
});
