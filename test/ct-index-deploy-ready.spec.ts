// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for the bv-ct-index deploy-readiness core (SQ-354).
 *
 * Imports ONLY `scripts/ct-index-deploy-ready.ts`, which is pure by design (the CLI shell that reads the filesystem is
 * `scripts/ci/ct-index-deploy-ready-check.ts`). The gate fails CLOSED, so the cases that matter are the ones that must NOT pass:
 * a deploy that proceeds with a placeholder D1 id, or under the name of another Worker on the shared account, is the failure.
 */

import { describe, expect, it } from 'vitest';
import ctIndexCfConfigSource from '../packages/bv-ct-index/cloudflare.config.ts?raw';
import ctIndexPackageJsonSource from '../packages/bv-ct-index/package.json?raw';
import ctIndexWranglerSource from '../packages/bv-ct-index/wrangler.jsonc?raw';
import {
	assessCtIndexDeployReady,
	CT_INDEX_D1_ID_ENV,
	CT_INDEX_D1_PLACEHOLDER,
	CT_INDEX_PROVISION_COMMAND,
	FORBIDDEN_WORKER_NAME,
	resolveCtIndexD1Id,
	type CtIndexDeployReadyInput,
} from '../scripts/ct-index-deploy-ready';

const FAKE_UUID = '12345678-1234-4234-8234-123456789abc';

// The real migrations on disk, so the "non-empty" condition is exercised against the actual directory.
const migrationFiles = Object.keys(import.meta.glob('../packages/bv-ct-index/migrations/*.sql', { query: '?raw' })).map((p) => p.split('/').pop()!);

const goodInput = (): CtIndexDeployReadyInput => ({
	d1Id: FAKE_UUID,
	configSource: ctIndexCfConfigSource,
	wranglerSource: ctIndexWranglerSource,
	packageJsonSource: ctIndexPackageJsonSource,
	migrationFiles,
});

describe('resolveCtIndexD1Id', () => {
	it('accepts a UUID and trims surrounding whitespace', () => {
		expect(resolveCtIndexD1Id(FAKE_UUID)).toBe(FAKE_UUID);
		expect(resolveCtIndexD1Id(`  ${FAKE_UUID.toUpperCase()}\n`)).toBe(FAKE_UUID.toUpperCase());
	});

	it.each([
		['undefined', undefined, /unset or empty/],
		['empty', '', /unset or empty/],
		['whitespace', '   ', /unset or empty/],
		['the tracked placeholder', CT_INDEX_D1_PLACEHOLDER, /placeholder/],
		['any YOUR_ placeholder', 'YOUR_OTHER_ID', /placeholder/],
		['a non-UUID', 'not-a-uuid', /not a UUID/],
		['a UUID with a trailing character', `${FAKE_UUID}x`, /not a UUID/],
	])('throws for %s, naming the variable and the provisioning command', (_label, raw, reason) => {
		expect(() => resolveCtIndexD1Id(raw)).toThrow(reason);
		expect(() => resolveCtIndexD1Id(raw)).toThrow(CT_INDEX_D1_ID_ENV);
		expect(() => resolveCtIndexD1Id(raw)).toThrow(CT_INDEX_PROVISION_COMMAND);
	});
});

describe('assessCtIndexDeployReady', () => {
	it('passes on the repo files with a valid D1 id (the real config, test config, manifest and migrations)', () => {
		expect(migrationFiles.length).toBeGreaterThan(0);
		expect(assessCtIndexDeployReady(goodInput())).toEqual({ ok: true, failures: [] });
	});

	it('fails when the D1 id is unset, a placeholder or not a UUID', () => {
		for (const d1Id of [undefined, '', CT_INDEX_D1_PLACEHOLDER, 'abc']) {
			const verdict = assessCtIndexDeployReady({ ...goodInput(), d1Id });
			expect(verdict.ok, String(d1Id)).toBe(false);
			expect(verdict.failures.join('\n')).toContain(CT_INDEX_D1_ID_ENV);
		}
	});

	it('fails when the cf config names any Worker other than bv-ct-index', () => {
		const configSource = ctIndexCfConfigSource.replace("name: 'bv-ct-index',", "name: 'bv2-ct-index',");
		expect(configSource).not.toBe(ctIndexCfConfigSource);
		const verdict = assessCtIndexDeployReady({ ...goodInput(), configSource });
		expect(verdict.ok).toBe(false);
		expect(verdict.failures.join('\n')).toContain('bv2-ct-index');
	});

	it('fails when the test config names a different Worker, or no Worker at all', () => {
		expect(assessCtIndexDeployReady({ ...goodInput(), wranglerSource: '{ "name": "other" }' }).ok).toBe(false);
		expect(assessCtIndexDeployReady({ ...goodInput(), wranglerSource: '{}' }).ok).toBe(false);
		expect(assessCtIndexDeployReady({ ...goodInput(), configSource: 'export default {};' }).ok).toBe(false);
	});

	it.each(['configSource', 'wranglerSource', 'packageJsonSource'] as const)(
		'fails when %s mentions the third-party Worker name',
		(field) => {
			const base = goodInput();
			const verdict = assessCtIndexDeployReady({ ...base, [field]: `${base[field]}\n// ${FORBIDDEN_WORKER_NAME}` });
			expect(verdict.ok).toBe(false);
			expect(verdict.failures.join('\n')).toContain(FORBIDDEN_WORKER_NAME);
		},
	);

	it('fails when the migrations directory is empty or holds no .sql file', () => {
		expect(assessCtIndexDeployReady({ ...goodInput(), migrationFiles: [] }).ok).toBe(false);
		expect(assessCtIndexDeployReady({ ...goodInput(), migrationFiles: ['README.md'] }).ok).toBe(false);
	});

	it('fails closed when an input could not be read', () => {
		for (const field of ['configSource', 'wranglerSource', 'packageJsonSource', 'migrationFiles'] as const) {
			const verdict = assessCtIndexDeployReady({ ...goodInput(), [field]: null });
			expect(verdict.ok, field).toBe(false);
			expect(verdict.failures.length, field).toBeGreaterThan(0);
		}
	});

	it('reports every failed condition, not just the first', () => {
		const verdict = assessCtIndexDeployReady({ ...goodInput(), d1Id: undefined, migrationFiles: [] });
		expect(verdict.failures).toHaveLength(2);
	});
});

describe('the committed deploy files', () => {
	it('keep the YOUR_ placeholder out of the cf config and in the test config', () => {
		expect(ctIndexCfConfigSource).not.toContain(CT_INDEX_D1_PLACEHOLDER);
		expect(ctIndexWranglerSource).toContain(CT_INDEX_D1_PLACEHOLDER);
	});
});
