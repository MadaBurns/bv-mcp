#!/usr/bin/env node
// SPDX-License-Identifier: BUSL-1.1

/**
 * scripts/tenants/provision-tenant.mjs
 *
 * CLI to provision a new tenant sub-tenant. Phase 1 of the tenant scalable architecture
 * roll-out — see `tenant-Scalable-Architecture-Design.md` §2.4 (tenant routing) and
 * §3.1 (registry schema).
 *
 * What it does:
 *   1. Validates inputs (super-tenant exists, sub-tenant id matches TENANT_ID_REGEX,
 *      sub-tenant doesn't already exist).
 *   2. Creates a per-tenant D1 database via `wrangler d1 create tenant-db-<id>`.
 *   3. Applies every `.sql` migration under `src/tenants/db/migrations/tenant/` in
 *      lexicographic order.
 *   4. INSERTs a row into `sub_tenants` in the registry D1.
 *   5. Mints a tenant-scoped API key (64 hex chars), stores SHA-256(key) in the
 *      `tenant_keys` table, and prints the *raw* key to stdout exactly once.
 *   6. Prints the wrangler binding stanza the operator must paste into
 *      `.dev/wrangler.deploy.jsonc` — this script never edits config files.
 *
 * Rollback: if applying migrations fails (step 3), the freshly-created D1 is
 * deleted (`wrangler d1 delete`) before the script exits non-zero. Registry
 * INSERT failures (step 4) trigger the same cleanup.
 *
 * Concurrency: a lock file at `~/.bv-tenant-provisioning.lock` (created with
 * `O_EXCL | O_CREAT`) prevents two operators from racing the registry. The
 * lock is released on every exit path, including failure.
 *
 * Safety rails: the script never edits wrangler.jsonc / .dev/wrangler.deploy.jsonc;
 * the operator pastes the printed binding stanza manually. The minted API key is
 * printed to stdout once with a "save now — never shown again" warning, never
 * persisted to a log file.
 *
 * Command execution uses `execFileSync(file, args)` — no shell is involved, so
 * argv values like display names with quotes can't be re-interpreted. The
 * registry SQL we build (super/sub lookup + INSERT) does single-quote-escape the
 * tenant id and display name; while these are also pre-validated by
 * `validateSubTenantId`/`buildSubTenantInsertSql`, the escape is defense in depth.
 *
 * Usage:
 *   node scripts/tenants/provision-tenant.mjs \
 *     --super-tenant=super-tenant-1 \
 *     --sub-tenant=tenant-1 \
 *     --display-name="Acme Corp" \
 *     [--dry-run] \
 *     [--registry-db=<binding-name-or-uuid>]
 *
 * Exit codes:
 *   0 — success (or --help)
 *   1 — validation/runtime failure (message on stderr)
 *
 * Test surface: every side-effecting operation funnels through `deps.runCmd`,
 * `deps.fs`, `deps.randomBytes`, `deps.sha256`, `deps.now`, `deps.stdout`,
 * `deps.stderr`. The test imports `provisionTenant` and helper pure functions
 * and passes a fake `deps` object — no real wrangler calls, no real fs writes.
 * We avoid static `import`s from `node:*` because tests execute under
 * `@cloudflare/vitest-pool-workers`, which has no Node built-ins; the CLI
 * bootstrap at the bottom of this file dynamic-imports them only when run
 * directly.
 */

// -- pure helpers --------------------------------------------------------------

/** Same regex as `TENANT_ID_REGEX` in src/schemas/tenant-internal.ts. */
export const TENANT_ID_REGEX = /^[a-z][a-z0-9_-]{0,63}$/;

/** Cloudflare binding name convention: `TENANT_DB_<UPPER_UNDERSCORED>`. */
export function tenantBindingName(subTenantId) {
	return `TENANT_DB_${subTenantId.replaceAll('-', '_').toUpperCase()}`;
}

/** D1 database name convention: `tenant-db-<sub-tenant>`. */
export function tenantDbName(subTenantId) {
	return `tenant-db-${subTenantId}`;
}

/**
 * Parse `--name=value` style argv into a flat object. Boolean flags (no `=`)
 * land as `true`. Unknown args are kept so callers can decide whether to
 * reject them.
 */
export function parseArgs(argv) {
	const out = {};
	for (const a of argv) {
		if (!a.startsWith('--')) continue;
		const body = a.slice(2);
		const eq = body.indexOf('=');
		if (eq === -1) {
			out[body] = true;
		} else {
			out[body.slice(0, eq)] = body.slice(eq + 1);
		}
	}
	return out;
}

/** Validate a sub-tenant id against TENANT_ID_REGEX. Returns null on success. */
export function validateSubTenantId(id) {
	if (typeof id !== 'string' || !TENANT_ID_REGEX.test(id)) {
		return `Invalid sub-tenant id: must match ${TENANT_ID_REGEX.source}`;
	}
	return null;
}

/**
 * Build the wrangler binding stanza for the operator to paste into
 * `.dev/wrangler.deploy.jsonc`. Note we emit JSONC (with trailing comma) so it
 * drops cleanly inside the existing `d1_databases` array.
 */
export function buildBindingStanza(subTenantId, databaseId) {
	const binding = tenantBindingName(subTenantId);
	const databaseName = tenantDbName(subTenantId);
	return `\t\t{ "binding": "${binding}", "database_name": "${databaseName}", "database_id": "${databaseId}" },`;
}

/**
 * Build the SQL string to INSERT a sub_tenant row. Values are passed positionally
 * — the script wraps them in `wrangler d1 execute --command`, so we single-quote
 * and escape any single quotes in the display name. `created_at` is a unix-seconds
 * integer so the schema's `integer('created_at')` stays in range.
 */
export function buildSubTenantInsertSql(row) {
	const escape = (s) => String(s).replaceAll("'", "''");
	const active = row.active ? 1 : 0;
	return (
		`INSERT INTO sub_tenants (id, super_tenant_id, name, d1_db_id, active, created_at) VALUES ` +
		`('${escape(row.id)}', '${escape(row.super_tenant_id)}', '${escape(row.name)}', ` +
		`'${escape(row.d1_db_id)}', ${active}, ${Math.floor(row.created_at)});`
	);
}

/** Build the SQL to insert a tenant_keys row (key_hash + scope only). */
export function buildTenantKeyInsertSql(row) {
	const escape = (s) => String(s).replaceAll("'", "''");
	return (
		`INSERT INTO tenant_keys (key_hash, super_tenant_id, sub_tenant_id, scope) VALUES ` +
		`('${escape(row.key_hash)}', '${escape(row.super_tenant_id)}', '${escape(row.sub_tenant_id)}', '${escape(row.scope)}');`
	);
}

/** Render the usage banner. */
export function usageText() {
	return [
		'Usage: node scripts/tenants/provision-tenant.mjs --super-tenant=<id> --sub-tenant=<id> --display-name="<name>" [--dry-run] [--registry-db=<binding>]',
		'',
		'Required:',
		'  --super-tenant=<id>     existing super-tenant in the registry',
		'  --sub-tenant=<id>       new sub-tenant id (^[a-z][a-z0-9_-]{0,63}$)',
		'  --display-name="<name>" human-readable display name',
		'',
		'Optional:',
		'  --dry-run               print every command + INSERT, execute none',
		'  --registry-db=<name>    registry D1 binding (default: TENANT_REGISTRY_DB)',
		'',
		'Exit 0 on success, 1 on any failure (message on stderr).',
	].join('\n');
}

// -- exec helpers --------------------------------------------------------------

/**
 * Run `wrangler d1 create <name>` and parse its JSON output for the new database id.
 * Wrangler emits both human-readable text and a JSON block; we ask for `--json`
 * so the entire stdout is parseable JSON.
 *
 * Throws on non-zero exit. Returns `{ id, name }`.
 */
export function createTenantD1(deps, dbName) {
	const out = deps.runCmd('wrangler', ['d1', 'create', dbName], { stdio: 'pipe' });
	const text = typeof out === 'string' ? out : out?.toString?.('utf8') ?? '';
	const parsed = parseWranglerJsonOutput(text);
	if (!parsed?.uuid && !parsed?.id) {
		throw new Error(`wrangler d1 create returned no id: ${text.slice(0, 500)}`);
	}
	return { id: parsed.uuid ?? parsed.id, name: parsed.name ?? dbName };
}

/**
 * Best-effort cleanup: delete a freshly-provisioned D1 database. Failures are
 * swallowed and reported on stderr — the caller is already in a failure path
 * and the operator can clean up by hand if this also fails.
 */
export function deleteTenantD1(deps, dbName) {
	try {
		deps.runCmd('wrangler', ['d1', 'delete', dbName, '--skip-confirmation'], { stdio: 'pipe' });
		return true;
	} catch (err) {
		deps.stderr(`warning: rollback of ${dbName} failed: ${err?.message ?? err}\n`);
		return false;
	}
}

/** Apply a single SQL file to a D1 database via `wrangler d1 execute --remote --file`. */
export function applyMigrationFile(deps, dbName, sqlFilePath) {
	deps.runCmd('wrangler', ['d1', 'execute', dbName, '--remote', `--file=${sqlFilePath}`], {
		stdio: 'pipe',
	});
}

/** Run a one-off SQL command against a D1 database, returning stdout text. */
export function executeRegistrySql(deps, registryBinding, sql) {
	const out = deps.runCmd(
		'wrangler',
		['d1', 'execute', registryBinding, '--remote', `--command=${sql}`, '--json'],
		{ stdio: 'pipe' },
	);
	return typeof out === 'string' ? out : out?.toString?.('utf8') ?? '';
}

/**
 * Parse `wrangler d1 execute --json` output. Wrangler emits an array of result
 * objects (one per statement); each has `results: any[]`, `success: boolean`,
 * and friends. We walk the structure defensively.
 */
export function parseWranglerJsonOutput(text) {
	if (!text) return null;
	try {
		const parsed = JSON.parse(text);
		if (parsed.d1_databases?.[0]) return parsed.d1_databases[0];
		return parsed;
	} catch {
		// Some wrangler versions wrap JSON in non-JSON banner lines. Find the
		// first `{` or `[` and try to parse from there.
		const i = text.search(/[\[{]/);
		if (i === -1) return null;
		try {
			// Try parsing the slice, but wrangler might append text after the JSON.
			// We try to find the balancing closing brace/bracket.
			let end = text.length;
			const stack = [];
			for (let j = i; j < text.length; j++) {
				if (text[j] === '{' || text[j] === '[') stack.push(text[j]);
				if (text[j] === '}' || text[j] === ']') {
					const top = stack.pop();
					if (stack.length === 0) {
						end = j + 1;
						break;
					}
				}
			}
			const snippet = text.slice(i, end);
			const parsed = JSON.parse(snippet);
			if (parsed.d1_databases?.[0]) {
				const d = parsed.d1_databases[0];
				return { ...d, id: d.database_id ?? d.id, name: d.database_name ?? d.name };
			}
			return parsed;
		} catch {
			return null;
		}
	}
}

/** Extract the `results` rows from a wrangler `--json` execute output. */
export function extractWranglerRows(text) {
	const parsed = parseWranglerJsonOutput(text);
	if (!parsed) return [];
	if (Array.isArray(parsed)) {
		// `[ { results: [...] }, ... ]`
		const first = parsed[0];
		if (first && Array.isArray(first.results)) return first.results;
	}
	if (parsed && Array.isArray(parsed.results)) return parsed.results;
	return [];
}

// -- core orchestration --------------------------------------------------------

/**
 * Run the full provisioning flow. All side effects funnel through `deps`.
 *
 * Returns the process exit code (0 on success, 1 on any failure).
 *
 * `deps` shape:
 *   runCmd(file, args, opts) -> stdout string | Buffer (throws on non-zero exit)
 *   fs.openSync(path, flags) -> fd (used to acquire the lock with `wx`)
 *   fs.closeSync(fd)
 *   fs.unlinkSync(path)
 *   fs.readdirSync(dir) -> string[]
 *   fs.statSync(path) -> { isFile() }
 *   randomBytes(n) -> Buffer-like with .toString('hex')
 *   sha256(text) -> hex string
 *   now() -> ms epoch (number)
 *   stdout(s), stderr(s) -> void
 *   migrationsDir -> absolute path string
 *   homeDir -> absolute path string for the lock file
 */
export async function provisionTenant(opts, deps) {
	const {
		'super-tenant': superTenantId,
		'sub-tenant': subTenantId,
		'display-name': displayName,
		'dry-run': dryRunFlag,
		'registry-db': registryBindingArg,
	} = opts;
	const dryRun = dryRunFlag === true || dryRunFlag === 'true';
	const registryBinding = typeof registryBindingArg === 'string' && registryBindingArg.length > 0
		? registryBindingArg
		: 'TENANT_REGISTRY_DB';

	if (typeof superTenantId !== 'string' || superTenantId.length === 0) {
		deps.stderr('Invalid input: --super-tenant is required\n');
		return 1;
	}
	const subErr = validateSubTenantId(subTenantId);
	if (subErr) {
		deps.stderr(`${subErr}\n`);
		return 1;
	}
	if (typeof displayName !== 'string' || displayName.length === 0) {
		deps.stderr('Invalid input: --display-name is required\n');
		return 1;
	}

	// Acquire the cross-process lock first — registry mutations must serialize.
	const lockPath = `${deps.homeDir}/.bv-tenant-provisioning.lock`;
	let lockFd = null;
	try {
		lockFd = deps.fs.openSync(lockPath, 'wx');
	} catch (err) {
		if (err && (err.code === 'EEXIST' || /EEXIST/.test(String(err.message)))) {
			deps.stderr(
				`Resource not found: another provisioning run holds ${lockPath}. ` +
					`Wait for it to finish, or remove the lock file manually if you're sure no run is active.\n`,
			);
			return 1;
		}
		deps.stderr(`Failed to acquire lock at ${lockPath}: ${err?.message ?? err}\n`);
		return 1;
	}

	const releaseLock = () => {
		if (lockFd !== null) {
			try { deps.fs.closeSync(lockFd); } catch { /* ignore */ }
			try { deps.fs.unlinkSync(lockPath); } catch { /* ignore */ }
			lockFd = null;
		}
	};

	try {
		// Step 1a: super-tenant must exist.
		const superLookupSql = `SELECT id FROM super_tenants WHERE id='${superTenantId.replaceAll("'", "''")}' LIMIT 1;`;
		if (dryRun) {
			deps.stdout(`[dry-run] would query: ${superLookupSql}\n`);
		} else {
			let rows;
			try {
				const text = executeRegistrySql(deps, registryBinding, superLookupSql);
				rows = extractWranglerRows(text);
			} catch (err) {
				deps.stderr(`Invalid input: super-tenant lookup failed: ${err?.message ?? err}\n`);
				return 1;
			}
			if (rows.length === 0) {
				deps.stderr(`Invalid input: super-tenant '${superTenantId}' not found in registry\n`);
				return 1;
			}
		}

		// Step 1b: sub-tenant must NOT already exist.
		const subLookupSql = `SELECT id FROM sub_tenants WHERE id='${subTenantId.replaceAll("'", "''")}' LIMIT 1;`;
		if (dryRun) {
			deps.stdout(`[dry-run] would query: ${subLookupSql}\n`);
		} else {
			let rows;
			try {
				const text = executeRegistrySql(deps, registryBinding, subLookupSql);
				rows = extractWranglerRows(text);
			} catch (err) {
				deps.stderr(`Invalid input: sub-tenant lookup failed: ${err?.message ?? err}\n`);
				return 1;
			}
			if (rows.length > 0) {
				deps.stderr(`Invalid input: sub-tenant '${subTenantId}' already exists in registry\n`);
				return 1;
			}
		}

		// Step 2: create the per-tenant D1.
		const dbName = tenantDbName(subTenantId);
		let databaseId = null;
		if (dryRun) {
			deps.stdout(`[dry-run] would run: wrangler d1 create ${dbName} --json\n`);
			databaseId = '<dry-run-d1-uuid>';
		} else {
			try {
				const created = createTenantD1(deps, dbName);
				databaseId = created.id;
				deps.stdout(`created D1 database ${dbName} (id=${databaseId})\n`);
			} catch (err) {
				deps.stderr(`Failed to create D1 ${dbName}: ${err?.message ?? err}\n`);
				return 1;
			}
		}

		// Step 3: apply migrations. On failure, roll back the D1.
		let migrationFiles;
		try {
			migrationFiles = listMigrationFiles(deps);
		} catch (err) {
			deps.stderr(`Failed to enumerate migrations: ${err?.message ?? err}\n`);
			if (!dryRun) deleteTenantD1(deps, dbName);
			return 1;
		}
		if (migrationFiles.length === 0) {
			deps.stderr(`Failed: no .sql files found under ${deps.migrationsDir}\n`);
			if (!dryRun) deleteTenantD1(deps, dbName);
			return 1;
		}

		for (const file of migrationFiles) {
			if (dryRun) {
				deps.stdout(`[dry-run] would run: wrangler d1 execute ${dbName} --remote --file=${file}\n`);
				continue;
			}
			try {
				applyMigrationFile(deps, dbName, file);
				deps.stdout(`applied ${file}\n`);
			} catch (err) {
				deps.stderr(`Failed to apply migration ${file}: ${err?.message ?? err}\n`);
				deleteTenantD1(deps, dbName);
				return 1;
			}
		}

		// Step 4: register the sub-tenant.
		const insertSubSql = buildSubTenantInsertSql({
			id: subTenantId,
			super_tenant_id: superTenantId,
			name: displayName,
			d1_db_id: databaseId,
			active: true,
			// schema column is `integer('created_at')` storing seconds-since-epoch
			created_at: Math.floor(deps.now() / 1000),
		});
		if (dryRun) {
			deps.stdout(`[dry-run] would run on ${registryBinding}: ${insertSubSql}\n`);
		} else {
			try {
				executeRegistrySql(deps, registryBinding, insertSubSql);
				deps.stdout(`registered sub-tenant ${subTenantId}\n`);
			} catch (err) {
				deps.stderr(`Failed to register sub-tenant: ${err?.message ?? err}\n`);
				deleteTenantD1(deps, dbName);
				return 1;
			}
		}

		// Step 5: print the binding stanza.
		const stanza = buildBindingStanza(subTenantId, databaseId);
		deps.stdout(
			`\nAdd this stanza to .dev/wrangler.deploy.jsonc under "d1_databases":\n${stanza}\n\n`,
		);

		// Step 6: mint and store an API key.
		const rawKey = deps.randomBytes(32).toString('hex');
		// Defense-in-depth: assert the generated key is exactly 64 lowercase hex chars.
		if (!/^[0-9a-f]{64}$/.test(rawKey)) {
			deps.stderr(`Failed to generate API key: unexpected shape\n`);
			if (!dryRun) deleteTenantD1(deps, dbName);
			return 1;
		}
		const keyHash = deps.sha256(rawKey);
		const insertKeySql = buildTenantKeyInsertSql({
			key_hash: keyHash,
			super_tenant_id: superTenantId,
			sub_tenant_id: subTenantId,
			scope: 'tenant',
		});
		if (dryRun) {
			deps.stdout(`[dry-run] would run on ${registryBinding}: ${insertKeySql}\n`);
			deps.stdout(`[dry-run] would mint API key: <not generated in dry-run>\n`);
		} else {
			try {
				executeRegistrySql(deps, registryBinding, insertKeySql);
			} catch (err) {
				deps.stderr(`Failed to insert tenant key: ${err?.message ?? err}\n`);
				deleteTenantD1(deps, dbName);
				return 1;
			}
			deps.stderr(
				`!! save now — never shown again !!\n` +
					`Tenant API key for ${subTenantId} (scope=tenant):\n`,
			);
			deps.stdout(`${rawKey}\n`);
		}

		return 0;
	} finally {
		releaseLock();
	}
}

/**
 * List every `.sql` file under `deps.migrationsDir` in lexicographic order.
 * Non-files (e.g. drizzle's `meta/` dir) are skipped.
 */
export function listMigrationFiles(deps) {
	const entries = deps.fs.readdirSync(deps.migrationsDir);
	const files = [];
	for (const name of entries) {
		if (!name.endsWith('.sql')) continue;
		const full = `${deps.migrationsDir}/${name}`;
		try {
			const st = deps.fs.statSync(full);
			if (typeof st.isFile === 'function' ? st.isFile() : true) {
				files.push(full);
			}
		} catch {
			// inject-friendly: tests that don't stub statSync will still see all .sql entries
			files.push(full);
		}
	}
	files.sort();
	return files;
}

// -- CLI bootstrap -------------------------------------------------------------

// Only run the CLI when invoked directly (node scripts/tenants/provision-tenant.mjs ...).
// When imported by a test, the `node:*` modules are NOT loaded — keeping the
// module compatible with the @cloudflare/vitest-pool-workers runtime.
const isDirectInvocation = (() => {
	try {
		if (typeof process === 'undefined' || !process?.argv?.[1]) return false;
		const entry = process.argv[1];
		// import.meta.url is `file:///abs/path` on Node
		return import.meta.url === `file://${entry}`;
	} catch {
		return false;
	}
})();

if (isDirectInvocation) {
	const [{ execFileSync }, fsMod, cryptoMod, osMod, pathMod, urlMod] = await Promise.all([
		import('node:child_process'),
		import('node:fs'),
		import('node:crypto'),
		import('node:os'),
		import('node:path'),
		import('node:url'),
	]);

	const __filename = urlMod.fileURLToPath(import.meta.url);
	const __dirname = pathMod.dirname(__filename);
	const repoRoot = pathMod.resolve(__dirname, '..', '..');
	const migrationsDir = pathMod.join(repoRoot, 'src', 'tenants', 'db', 'migrations', 'tenant');

	const argv = process.argv.slice(2);
	if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
		process.stdout.write(usageText() + '\n');
		process.exit(0);
	}
	const opts = parseArgs(argv);

	const deps = {
		runCmd: (file, args, options) => execFileSync(file, args, options),
		fs: {
			openSync: (p, flags) => fsMod.openSync(p, flags),
			closeSync: (fd) => fsMod.closeSync(fd),
			unlinkSync: (p) => fsMod.unlinkSync(p),
			readdirSync: (p) => fsMod.readdirSync(p),
			statSync: (p) => fsMod.statSync(p),
		},
		randomBytes: (n) => cryptoMod.randomBytes(n),
		sha256: (text) => cryptoMod.createHash('sha256').update(text, 'utf8').digest('hex'),
		now: () => Date.now(),
		stdout: (s) => process.stdout.write(s),
		stderr: (s) => process.stderr.write(s),
		migrationsDir,
		homeDir: osMod.homedir(),
	};

	const code = await provisionTenant(opts, deps);
	process.exit(code);
}
