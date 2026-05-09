// SPDX-License-Identifier: BUSL-1.1

/**
 * Unit tests for `scripts/tenants/provision-tenant.mjs`.
 *
 * The script never statically imports `node:*` (so it is safe to import inside
 * `@cloudflare/vitest-pool-workers` which has no Node built-ins). All side
 * effects funnel through an injected `deps` object — tests pass a fake to
 * exercise every branch without touching real wrangler / fs / crypto.
 *
 * Layer: Unit. Each spec asserts a single observable behaviour of
 * `provisionTenant()` plus the public helpers (parseArgs, validateSubTenantId,
 * buildSubTenantInsertSql, etc.). The eight cases mirror the spec's case list:
 *
 *   1. happy path — all 7 steps run in order, exit 0
 *   2. duplicate sub_tenant pre-check — exit 1, 'Invalid' prefix
 *   3. migration failure — D1 delete invoked as cleanup, exit 1
 *   4. dry-run — no real runCmd calls, every command printed
 *   5. invalid sub-tenant regex — exit 1 immediately
 *   6. super-tenant lookup fails — exit 1
 *   7. API key generation — exactly 64 hex chars to stdout, no log file
 *   8. lock contention — second concurrent run exits 1, 'Resource not found' prefix
 */

import { describe, it, expect } from 'vitest';
import {
	parseArgs,
	provisionTenant,
	tenantBindingName,
	tenantDbName,
	buildBindingStanza,
	buildSubTenantInsertSql,
	validateSubTenantId,
	parseWranglerJsonOutput,
	extractWranglerRows,
	listMigrationFiles,
} from '../../scripts/tenants/provision-tenant.mjs';

// ---- fakes -------------------------------------------------------------------

type ExecCall = { file: string; args: string[] };

interface FakeFsState {
	locks: Set<string>;
	migrationFiles: string[];
}

function makeDeps(overrides: Partial<{
	runCmdImpl: (file: string, args: string[], opts: unknown) => string;
	migrationFiles: string[];
	homeDir: string;
	migrationsDir: string;
	now: number;
	randomHex: string;
	failLockOpen: 'eexist' | 'other' | null;
}> = {}) {
	const stdout: string[] = [];
	const stderr: string[] = [];
	const cmds: ExecCall[] = [];
	const fsState: FakeFsState = {
		locks: new Set(),
		migrationFiles: overrides.migrationFiles ?? [
			'/repo/src/tenants/db/migrations/tenant/0000_clear_clea.sql',
		],
	};
	const homeDir = overrides.homeDir ?? '/home/op';
	const migrationsDir = overrides.migrationsDir ?? '/repo/src/tenants/db/migrations/tenant';

	const defaultRun: (file: string, args: string[], opts: unknown) => string = (file, args) => {
		const joined = `${file} ${args.join(' ')}`;
		// `wrangler d1 create <name> --json` → return UUID
		if (file === 'wrangler' && args[0] === 'd1' && args[1] === 'create') {
			return JSON.stringify({ uuid: 'fake-d1-uuid', name: args[2] });
		}
		// `wrangler d1 execute <bind> --remote --command=<sql> --json`
		if (file === 'wrangler' && args[0] === 'd1' && args[1] === 'execute') {
			const cmdArg = args.find((a) => a.startsWith('--command='));
			const sql = cmdArg ? cmdArg.slice('--command='.length) : '';
			if (/SELECT id FROM super_tenants/i.test(sql)) {
				return JSON.stringify([{ results: [{ id: 'super-tenant-1' }] }]);
			}
			if (/SELECT id FROM sub_tenants/i.test(sql)) {
				return JSON.stringify([{ results: [] }]);
			}
			// inserts/file-applies → empty results array
			return JSON.stringify([{ results: [], success: true }]);
		}
		// `wrangler d1 delete <name> --skip-confirmation`
		if (file === 'wrangler' && args[0] === 'd1' && args[1] === 'delete') {
			return '';
		}
		throw new Error(`unmocked: ${joined}`);
	};

	const runCmdImpl = overrides.runCmdImpl ?? defaultRun;

	const deps = {
		runCmd(file: string, args: string[], opts: unknown) {
			cmds.push({ file, args });
			return runCmdImpl(file, args, opts);
		},
		fs: {
			openSync(path: string, flags: string) {
				if (overrides.failLockOpen === 'eexist') {
					const e = new Error('EEXIST: file already exists') as Error & { code?: string };
					e.code = 'EEXIST';
					throw e;
				}
				if (overrides.failLockOpen === 'other') {
					throw new Error('disk full');
				}
				if (flags === 'wx' && fsState.locks.has(path)) {
					const e = new Error(`EEXIST: ${path}`) as Error & { code?: string };
					e.code = 'EEXIST';
					throw e;
				}
				fsState.locks.add(path);
				return 42;
			},
			closeSync(_fd: number) { /* no-op */ },
			unlinkSync(path: string) { fsState.locks.delete(path); },
			readdirSync(_dir: string) {
				return fsState.migrationFiles.map((p) => p.split('/').pop() ?? p);
			},
			statSync(_p: string) {
				return { isFile: () => true };
			},
		},
		randomBytes(_n: number) {
			const hex = overrides.randomHex ?? 'a'.repeat(64);
			return { toString: (_enc: string) => hex };
		},
		sha256(text: string) {
			// Deterministic placeholder — tests assert _the_ key hashing happens, not the digest.
			return `sha256(${text.slice(0, 8)}...)`;
		},
		now: () => overrides.now ?? 1_700_000_000_000,
		stdout: (s: string) => { stdout.push(s); },
		stderr: (s: string) => { stderr.push(s); },
		migrationsDir,
		homeDir,
	};

	return { deps, stdout, stderr, cmds, fsState };
}

const baseOpts = {
	'super-tenant': 'super-tenant-1',
	'sub-tenant': 'tenant-1',
	'display-name': 'Acme Corp',
};

// ---- pure helpers ------------------------------------------------------------

describe('pure helpers', () => {
	it('parseArgs splits --name=value pairs and treats bare flags as true', () => {
		const out = parseArgs([
			'--super-tenant=super-tenant-1',
			'--sub-tenant=tenant-1',
			'--display-name=Acme Corp',
			'--dry-run',
		]);
		expect(out['super-tenant']).toBe('super-tenant-1');
		expect(out['sub-tenant']).toBe('tenant-1');
		expect(out['display-name']).toBe('Acme Corp');
		expect(out['dry-run']).toBe(true);
	});

	it('tenantBindingName replaces hyphens with underscores and uppercases', () => {
		expect(tenantBindingName('tenant-1')).toBe('TENANT_DB_TENANT_1');
	});

	it('tenantDbName prepends tenant-db- prefix', () => {
		expect(tenantDbName('tenant-1')).toBe('tenant-db-tenant-1');
	});

	it('buildBindingStanza emits a JSONC-friendly stanza', () => {
		const s = buildBindingStanza('tenant-1', 'uuid-123');
		expect(s).toContain('"binding": "TENANT_DB_TENANT_1"');
		expect(s).toContain('"database_name": "tenant-db-tenant-1"');
		expect(s).toContain('"database_id": "uuid-123"');
	});

	it("buildSubTenantInsertSql escapes single quotes in display name", () => {
		const sql = buildSubTenantInsertSql({
			id: 'tenant-1',
			super_tenant_id: 'super-tenant-1',
			name: "O'Reilly Inc",
			d1_db_id: 'u',
			active: true,
			created_at: 1_700_000_000,
		});
		expect(sql).toContain("'O''Reilly Inc'");
	});

	it('validateSubTenantId returns null for valid ids and an Invalid-prefixed error otherwise', () => {
		expect(validateSubTenantId('tenant-1')).toBeNull();
		expect(validateSubTenantId('Tenant-1')).toMatch(/^Invalid /);
		expect(validateSubTenantId('1leading-digit')).toMatch(/^Invalid /);
	});

	it('parseWranglerJsonOutput tolerates banner-prefixed JSON', () => {
		const text = '⛅️ wrangler 4.88.0\n[{"results":[{"id":"x"}]}]';
		const parsed = parseWranglerJsonOutput(text);
		expect(Array.isArray(parsed) && (parsed as unknown[])[0]).toBeTruthy();
	});

	it('extractWranglerRows pulls nested results arrays', () => {
		expect(extractWranglerRows('[{"results":[{"id":1}]}]')).toEqual([{ id: 1 }]);
		expect(extractWranglerRows('{"results":[{"id":2}]}')).toEqual([{ id: 2 }]);
		expect(extractWranglerRows('not-json')).toEqual([]);
	});

	it('listMigrationFiles filters non-.sql entries', () => {
		const fakeFs = {
			readdirSync: () => ['0000_clear_clea.sql', 'meta', '0001_other.sql'],
			statSync: (p: string) => ({ isFile: () => p.endsWith('.sql') }),
		} as unknown as { readdirSync: (d: string) => string[]; statSync: (p: string) => { isFile: () => boolean } };
		const files = listMigrationFiles({
			fs: fakeFs,
			migrationsDir: '/m',
		} as unknown as Parameters<typeof listMigrationFiles>[0]);
		expect(files).toEqual(['/m/0000_clear_clea.sql', '/m/0001_other.sql']);
	});
});

// ---- provisionTenant orchestration ------------------------------------------

describe('provisionTenant', () => {
	it('happy path runs every step in order and exits 0', async () => {
		const { deps, stdout, cmds } = makeDeps();
		const code = await provisionTenant(baseOpts, deps);
		expect(code).toBe(0);
		// Order: super-tenant lookup, sub-tenant lookup, d1 create, migrations, sub_tenants insert, tenant_keys insert
		const wranglerCalls = cmds.filter((c) => c.file === 'wrangler');
		const sequence = wranglerCalls.map((c) => `${c.args[0]} ${c.args[1]} ${c.args[2] ?? ''}`.trim());
		expect(sequence[0]).toContain('d1 execute');
		expect(sequence[1]).toContain('d1 execute');
		expect(sequence[2]).toBe('d1 create tenant-db-tenant-1');
		expect(sequence[3]).toContain('d1 execute');
		// Two final inserts: sub_tenants + tenant_keys
		const allOutput = stdout.join('');
		expect(allOutput).toContain('TENANT_DB_TENANT_1');
		expect(allOutput).toContain('tenant-db-tenant-1');
		// API key — 64 lowercase hex on its own line (or as a token in a line)
		expect(allOutput).toMatch(/[0-9a-f]{64}/);
	});

	it('exits 1 when the sub-tenant already exists in the registry', async () => {
		const { deps, stderr } = makeDeps({
			runCmdImpl: (file, args) => {
				if (file === 'wrangler' && args[0] === 'd1' && args[1] === 'execute') {
					const cmd = args.find((a) => a.startsWith('--command=')) ?? '';
					if (/super_tenants/i.test(cmd)) return JSON.stringify([{ results: [{ id: 'super-tenant-1' }] }]);
					if (/sub_tenants/i.test(cmd)) return JSON.stringify([{ results: [{ id: 'tenant-1' }] }]);
				}
				return '';
			},
		});
		const code = await provisionTenant(baseOpts, deps);
		expect(code).toBe(1);
		const err = stderr.join('');
		expect(err).toMatch(/^Invalid /);
		expect(err).toContain('tenant-1');
	});

	it('rolls back the freshly-created D1 when migrations fail', async () => {
		const { deps, cmds } = makeDeps({
			runCmdImpl: (file, args) => {
				if (file === 'wrangler' && args[0] === 'd1' && args[1] === 'execute') {
					const cmd = args.find((a) => a.startsWith('--command=')) ?? '';
					if (/super_tenants/i.test(cmd)) return JSON.stringify([{ results: [{ id: 'super-tenant-1' }] }]);
					if (/sub_tenants/i.test(cmd)) return JSON.stringify([{ results: [] }]);
					// Any --file= invocation → migration apply, simulate failure
					if (args.some((a) => a.startsWith('--file='))) throw new Error('SQLITE_BUSY');
					return '';
				}
				if (file === 'wrangler' && args[0] === 'd1' && args[1] === 'create') {
					return JSON.stringify({ uuid: 'rollback-uuid', name: args[2] });
				}
				if (file === 'wrangler' && args[0] === 'd1' && args[1] === 'delete') return '';
				throw new Error(`unmocked: ${file} ${args.join(' ')}`);
			},
		});
		const code = await provisionTenant(baseOpts, deps);
		expect(code).toBe(1);
		// Rollback delete must have been invoked
		const deleteCall = cmds.find(
			(c) => c.file === 'wrangler' && c.args[0] === 'd1' && c.args[1] === 'delete',
		);
		expect(deleteCall).toBeTruthy();
		expect(deleteCall?.args).toContain('tenant-db-tenant-1');
	});

	it('--dry-run prints commands and never invokes runCmd', async () => {
		const { deps, stdout, cmds } = makeDeps();
		const code = await provisionTenant({ ...baseOpts, 'dry-run': true }, deps);
		expect(code).toBe(0);
		expect(cmds.length).toBe(0);
		const allOutput = stdout.join('');
		expect(allOutput).toContain('[dry-run] would query');
		expect(allOutput).toContain('[dry-run] would run: wrangler d1 create');
		expect(allOutput).toContain('[dry-run] would run on');
		// Real raw key must NOT appear in dry-run output
		expect(allOutput).not.toMatch(/\b[0-9a-f]{64}\b/);
	});

	it('rejects an invalid sub-tenant id with an Invalid-prefixed message', async () => {
		const { deps, stderr } = makeDeps();
		const code = await provisionTenant({ ...baseOpts, 'sub-tenant': 'Bad-ID' }, deps);
		expect(code).toBe(1);
		expect(stderr.join('')).toMatch(/^Invalid /);
	});

	it('exits 1 when the super-tenant lookup returns no rows', async () => {
		const { deps, stderr } = makeDeps({
			runCmdImpl: (file, args) => {
				if (file === 'wrangler' && args[0] === 'd1' && args[1] === 'execute') {
					return JSON.stringify([{ results: [] }]); // empty for every query
				}
				throw new Error(`unmocked: ${file} ${args.join(' ')}`);
			},
		});
		const code = await provisionTenant(baseOpts, deps);
		expect(code).toBe(1);
		const err = stderr.join('');
		expect(err).toMatch(/^Invalid /);
		expect(err).toContain('super-tenant-1');
	});

	it('mints exactly 64 hex chars to stdout and never writes a log file', async () => {
		const { deps, stdout, cmds } = makeDeps({ randomHex: 'b'.repeat(64) });
		const code = await provisionTenant(baseOpts, deps);
		expect(code).toBe(0);
		const all = stdout.join('');
		// Find the sole 64-hex token and confirm exact length
		const matches = all.match(/[0-9a-f]{64}/g) ?? [];
		expect(matches).toContain('b'.repeat(64));
		// No fs.writeFileSync calls — fake fs has no writeFileSync, importer would have failed.
		// Also assert no unexpected commands ran.
		const dangerous = cmds.filter((c) => c.file !== 'wrangler');
		expect(dangerous).toEqual([]);
	});

	it('exits 1 when another run holds the lock file', async () => {
		const { deps, stderr } = makeDeps({ failLockOpen: 'eexist' });
		const code = await provisionTenant(baseOpts, deps);
		expect(code).toBe(1);
		expect(stderr.join('')).toMatch(/^Resource not found:/);
	});
});
