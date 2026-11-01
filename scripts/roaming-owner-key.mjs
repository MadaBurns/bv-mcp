// SPDX-License-Identifier: BUSL-1.1
// Provision one temporary, independently revocable owner credential without exposing its value.
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, relative, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const WORKER_NAME = 'bv-dns-security-mcp';
export const SECRET_NAMES = ['BV_ROAMING_OWNER_KEY', 'BV_ROAMING_OWNER_EXPIRES_AT'];
const repoRoot = fileURLToPath(new URL('../', import.meta.url));

export function validateCredentialOutput(output) {
	if (typeof output !== 'string' || !isAbsolute(output)) throw new Error('An absolute private output path is required.');
	const suffix = [];
	let ancestor = resolve(output);
	while (!existsSync(ancestor)) {
		suffix.unshift(basename(ancestor));
		ancestor = dirname(ancestor);
	}
	const canonical = resolve(realpathSync(ancestor), ...suffix);
	for (let directory = realpathSync(ancestor); ; directory = dirname(directory)) {
		const found = spawnSync('git', ['-C', directory, 'rev-parse', '--show-toplevel'], { encoding: 'utf8' });
		if (found.error) throw new Error('Cannot verify private credential output location.');
		if (found.status === 0) {
			const root = found.stdout.trim();
			const path = relative(root, canonical);
			if (path !== '..' && !path.startsWith('../') && !isAbsolute(path)) {
				const ignored = spawnSync('git', ['-C', root, 'check-ignore', '--quiet', '--', canonical]);
				if (ignored.status !== 0) throw new Error('Credential output inside a Git working tree must be ignored.');
			}
		}
		if (dirname(directory) === directory) break;
	}
	return canonical;
}

export function expiryForDays(days = 7, now = Date.now()) {
	if (!Number.isInteger(days) || days < 1 || days > 30 || !Number.isFinite(now)) {
		throw new Error('Expiry must be an integer between 1 and 30 days.');
	}
	return new Date(now + days * 86_400_000).toISOString();
}

export function newCredential(days = 7, now = Date.now()) {
	return {
		kind: 'roaming-owner',
		worker: WORKER_NAME,
		key: `bvroam_${randomBytes(32).toString('base64url')}`,
		expiresAt: expiryForDays(days, now),
		status: 'pending',
	};
}

export function provisionCredential(record, output, { run = spawnSync, wranglerPath, configPath } = {}) {
	output = validateCredentialOutput(output);
	if (record.kind !== 'roaming-owner' || record.worker !== WORKER_NAME || typeof record.key !== 'string' || record.key.length < 32) {
		throw new Error('Invalid roaming-owner credential record.');
	}
	const expiry = Date.parse(record.expiresAt);
	if (!Number.isFinite(expiry) || new Date(expiry).toISOString() !== record.expiresAt || expiry <= Date.now()) {
		throw new Error('Credential expiry must be canonical UTC and in the future.');
	}
	if (existsSync(output)) throw new Error('Credential file already exists; refusing to overwrite it.');
	const require = createRequire(import.meta.url);
	const cli = wranglerPath ?? require.resolve('wrangler/bin/wrangler.js');
	const config = configPath ?? resolve(repoRoot, 'wrangler.production.jsonc');
	const common = ['--name', WORKER_NAME, '--config', config];
	// Wrangler otherwise permits inherited debug settings to persist request bodies on disk.
	const env = { ...process.env, WRANGLER_LOG_SANITIZE: 'true', WRANGLER_WRITE_LOGS: 'false' };
	const listed = run(process.execPath, [cli, 'secret', 'list', '--format', 'json', ...common], {
		cwd: repoRoot,
		env,
		encoding: 'utf8',
		timeout: 60_000,
	});
	if (listed.status !== 0) throw new Error('Cannot verify production secret inventory; no credential provisioned.');
	let names;
	try {
		names = JSON.parse(listed.stdout);
	} catch {
		throw new Error('Invalid production secret inventory; no credential provisioned.');
	}
	if (!Array.isArray(names) || !names.some((entry) => entry.name === 'BV_API_KEY')) {
		throw new Error('Expected production Worker secret inventory was not found.');
	}
	if (names.some((entry) => SECRET_NAMES.includes(entry.name))) {
		throw new Error('Roaming credential configuration already exists; explicit revocation is required before replacement.');
	}
	mkdirSync(dirname(output), { recursive: true, mode: 0o700 });
	writeFileSync(output, JSON.stringify(record, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
	const payload = { BV_ROAMING_OWNER_KEY: record.key, BV_ROAMING_OWNER_EXPIRES_AT: record.expiresAt };
	const result = run(process.execPath, [cli, 'secret', 'bulk', ...common], {
		cwd: repoRoot,
		env,
		input: JSON.stringify(payload),
		encoding: 'utf8',
		timeout: 120_000,
	});
	if (result.status !== 0) {
		// A transport failure can follow a successful remote write. Keep the private recovery record,
		// never print subprocess output, and never auto-retry a possibly completed mutation.
		record.status = 'remote-state-unverified';
		writeFileSync(output, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
		throw new Error('Provisioning did not confirm success. Private recovery record retained; inspect remote state before retrying.');
	}
	record.status = 'provisioned';
	writeFileSync(output, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
	chmodSync(output, 0o600);
	return { worker: WORKER_NAME, expiresAt: record.expiresAt, credentialFile: output, status: record.status, secretNames: SECRET_NAMES };
}

async function main() {
	const args = process.argv.slice(2);
	if (args[0] !== 'create') throw new Error('Usage: roaming-owner-key.mjs create --output <absolute-private-file> [--days 1..30] [--dry-run]');
	let output;
	let days = 7;
	let dryRun = false;
	for (let i = 1; i < args.length; i++) {
		if (args[i] === '--output') output = args[++i];
		else if (args[i] === '--days') days = Number(args[++i]);
		else if (args[i] === '--dry-run') dryRun = true;
		else throw new Error('Unknown provisioning option.');
	}
	output = validateCredentialOutput(output);
	const expiresAt = expiryForDays(days);
	if (dryRun) {
		console.log(JSON.stringify({ worker: WORKER_NAME, secretNames: SECRET_NAMES, expiresAt, credentialFile: output, dryRun: true }));
		return;
	}
	const result = provisionCredential(newCredential(days), output);
	console.log(JSON.stringify(result));
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
	main().catch(() => {
		console.error('Roaming-owner provisioning failed; no credential values were printed. Inspect private recovery state before retrying.');
		process.exitCode = 1;
	});
}
