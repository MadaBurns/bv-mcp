// SPDX-License-Identifier: BUSL-1.1
import { mkdtempSync, readFileSync, realpathSync, rmSync, statSync, existsSync, writeFileSync, symlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { expiryForDays, newCredential, provisionCredential, resolveWranglerPath, validateCredentialOutput, WORKER_NAME } from '../../scripts/roaming-owner-key.mjs';

const dirs: string[] = [];
function output() {
	const dir = mkdtempSync(join(tmpdir(), 'roaming-owner-test-'));
	dirs.push(dir);
	return join(dir, 'credential.json');
}
function runner(second = { status: 0, stdout: '' }) {
	return vi
		.fn()
		.mockReturnValueOnce({ status: 0, stdout: JSON.stringify([{ name: 'BV_API_KEY', type: 'secret_text' }]) })
		.mockReturnValueOnce(second);
}
const options = (run: ReturnType<typeof vi.fn>) => ({
	// This test double supplies only the UTF-8 signature and result fields consumed by provisioning.
	// It is never used as the other Buffer/command-only overloads of Node's spawnSync.
	run: run as unknown as typeof spawnSync,
	wranglerPath: '/synthetic/wrangler.js',
	configPath: '/synthetic/production.jsonc',
});

afterEach(() => {
	for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
	vi.restoreAllMocks();
});

describe('roaming owner credential provisioning', () => {
	it('resolves the installed Wrangler entrypoint without relying on a private package export', () => {
		const cli = resolveWranglerPath();
		expect(existsSync(cli)).toBe(true);
		const run = runner();
		const defaultPathOptions = { run: options(run).run, configPath: '/synthetic/production.jsonc' };
		provisionCredential(newCredential(), output(), defaultPathOptions);
		expect(run.mock.calls[0][1][0]).toBe(cli);
	});
	it('overrides inherited unsafe Wrangler logging settings for every subprocess', () => {
		vi.stubEnv('WRANGLER_LOG_SANITIZE', 'false');
		vi.stubEnv('WRANGLER_WRITE_LOGS', 'true');
		const run = runner();
		try {
			provisionCredential(newCredential(), output(), options(run));
			for (const [, , spawnOptions] of run.mock.calls) {
				expect(spawnOptions.env.WRANGLER_LOG_SANITIZE).toBe('true');
				expect(spawnOptions.env.WRANGLER_WRITE_LOGS).toBe('false');
			}
		} finally {
			vi.unstubAllEnvs();
		}
	});
	it('allows only ignored Git output paths, including after resolving symlinked parents', () => {
		const root = realpathSync(mkdtempSync(join(tmpdir(), 'roaming-owner-git-')));
		dirs.push(root);
		expect(spawnSync('git', ['init', root]).status).toBe(0);
		writeFileSync(join(root, '.gitignore'), 'private/\ntracked.json\n');
		writeFileSync(join(root, 'tracked.json'), 'synthetic fixture');
		expect(spawnSync('git', ['-C', root, 'add', '-f', 'tracked.json']).status).toBe(0);
		for (const file of ['untracked.json', 'tracked.json', '.git/credential.json']) {
			const run = runner();
			expect(() => provisionCredential(newCredential(), join(root, file), options(run))).toThrow('must be ignored');
			expect(run).not.toHaveBeenCalled();
		}
		expect(validateCredentialOutput(join(root, 'private', 'credential.json'))).toBe(join(root, 'private', 'credential.json'));
		const outside = mkdtempSync(join(tmpdir(), 'roaming-owner-link-'));
		dirs.push(outside);
		symlinkSync(root, join(outside, 'repo'));
		expect(() => validateCredentialOutput(join(outside, 'repo', 'untracked.json'))).toThrow('must be ignored');
		expect(validateCredentialOutput(join(outside, 'repo', 'private', 'credential.json'))).toBe(join(root, 'private', 'credential.json'));
	});
	it('defaults to a bounded seven-day UTC expiry and generates distinct 256-bit credentials', () => {
		const now = Date.UTC(2026, 0, 1);
		expect(expiryForDays(undefined, now)).toBe('2026-01-08T00:00:00.000Z');
		const a = newCredential(7, now), b = newCredential(7, now);
		expect(a.key).toMatch(/^bvroam_[A-Za-z0-9_-]{43}$/);
		expect(a.key).not.toBe(b.key);
	});
	it.each([0, -1, 31, 1.5, NaN, Infinity])('rejects unsafe expiry duration %s', (days) => {
		expect(() => expiryForDays(days)).toThrow('between 1 and 30');
	});
	it('sends authority only through stdin, preserves unrelated secrets, and saves a private record', () => {
		const record = newCredential(), file = output(), run = runner();
		const result = provisionCredential(record, file, options(run));
		const [, argv, spawnOptions] = run.mock.calls[1];
		expect(argv).toContain(WORKER_NAME);
		expect(argv).not.toContain(record.key);
		expect(JSON.stringify(argv)).not.toContain(record.key);
		expect(JSON.parse(spawnOptions.input)).toEqual({ BV_ROAMING_OWNER_KEY: record.key, BV_ROAMING_OWNER_EXPIRES_AT: record.expiresAt });
		expect(Object.keys(JSON.parse(spawnOptions.input))).toHaveLength(2);
		expect(JSON.stringify(result)).not.toContain(record.key);
		expect(statSync(file).mode & 0o777).toBe(0o600);
		expect(JSON.parse(readFileSync(file, 'utf8')).status).toBe('provisioned');
	});
	it('refuses to overwrite a remotely configured roaming credential', () => {
		const file = output();
		const run = vi.fn().mockReturnValue({ status: 0, stdout: JSON.stringify([{ name: 'BV_API_KEY' }, { name: 'BV_ROAMING_OWNER_KEY' }]) });
		expect(() => provisionCredential(newCredential(), file, options(run))).toThrow('already exists');
		expect(run).toHaveBeenCalledTimes(1);
		expect(existsSync(file)).toBe(false);
	});
	it('fails closed on missing or malformed production inventory', () => {
		for (const response of [{ status: 1, stdout: '' }, { status: 0, stdout: 'not JSON' }, { status: 0, stdout: '[]' }]) {
			const run = vi.fn().mockReturnValue(response), file = output();
			expect(() => provisionCredential(newCredential(), file, options(run))).toThrow();
			expect(run).toHaveBeenCalledTimes(1);
			expect(existsSync(file)).toBe(false);
		}
	});
	it('retains private recovery data after an ambiguous remote failure without leaking subprocess output or retrying', () => {
		const record = newCredential(), file = output();
		const run = runner({ status: 1, stdout: record.key });
		let message = '';
		try { provisionCredential(record, file, options(run)); } catch (error) { message = (error as Error).message; }
		expect(message).toContain('inspect remote state');
		expect(message).not.toContain(record.key);
		expect(run).toHaveBeenCalledTimes(2);
		expect(JSON.parse(readFileSync(file, 'utf8')).status).toBe('remote-state-unverified');
		expect(statSync(file).mode & 0o777).toBe(0o600);
	});
	it('refuses expired records before any cloud command', () => {
		const record = { ...newCredential(), expiresAt: '2000-01-01T00:00:00.000Z' }, run = vi.fn();
		expect(() => provisionCredential(record, output(), options(run))).toThrow('future');
		expect(run).not.toHaveBeenCalled();
	});
});
