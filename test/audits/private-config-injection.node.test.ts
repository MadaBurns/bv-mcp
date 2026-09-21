// SPDX-License-Identifier: BUSL-1.1

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';

const require = createRequire(import.meta.url);

const injectScript = require('../../scripts/inject-private-config.cjs') as {
	assessAlertWebhookSecretGate: (
		vars: Record<string, unknown>,
		listSecretNames: () => string[],
		allowMissing: boolean,
	) => { ok: boolean; message: string | null };
	listProductionSecretNames: (workerName: string, spawnSyncFn: (...args: unknown[]) => unknown) => string[];
	ALERT_WEBHOOK_SECRET_NAME: string;
	ALERT_WEBHOOK_OVERRIDE_ENV: string;
	WRANGLER_SECRET_LIST_ARGV: string[];
};

// The real ALERT_WEBHOOK_URL secret gate shells out to `wrangler secret list`
// (scripts/inject-private-config.cjs). Every fixture below that is not
// specifically exercising that gate opts out of the live lister with the
// same one-shot override an operator uses for a transition deploy — the
// override is checked BEFORE any spawn, so these subprocess runs never touch
// the network or Cloudflare. Tests for the gate itself, further down,
// `require()` the module directly and inject a fake lister instead.
const ALLOW_MISSING_ALERT_SECRET_ENV = { ...process.env, BV_ALLOW_MISSING_ALERT_SECRET: '1' };

describe('private Wrangler config injection', () => {
	it('preserves public service bindings that are not overridden by the private overlay', () => {
		const cwd = mkdtempSync(join(tmpdir(), 'bv-mcp-inject-'));
		mkdirSync(join(cwd, 'scripts'));
		mkdirSync(join(cwd, '.dev'));
		copyFileSync(join(process.cwd(), 'scripts/inject-private-config.cjs'), join(cwd, 'scripts/inject-private-config.cjs'));

		writeFileSync(
			join(cwd, 'wrangler.jsonc'),
			JSON.stringify({
				name: 'bv-mcp-test',
				main: 'src/index.ts',
				services: [
					{ binding: 'BV_WEB', service: 'blackveil-web' },
					{ binding: 'BV_WHOIS', service: 'bv-whois' },
				],
			}),
		);
		writePrivateOverlay(cwd, {
			vars: productionVars(),
			services: [
				{ binding: 'BV_WEB', service: 'blackveil-web-prod' },
				{ binding: 'BV_CERTSTREAM', service: 'bv-certstream-worker' },
			],
		});

		execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe', env: ALLOW_MISSING_ALERT_SECRET_ENV });
		const injected = JSON.parse(readFileSync(join(cwd, 'wrangler.production.jsonc'), 'utf8')) as {
			services?: Array<{ binding?: string; service?: string }>;
		};

		expect(injected.services).toEqual([
			{ binding: 'BV_WEB', service: 'blackveil-web-prod' },
			{ binding: 'BV_WHOIS', service: 'bv-whois' },
			{ binding: 'BV_CERTSTREAM', service: 'bv-certstream-worker' },
		]);
	});

	it('fails closed when required production security vars are missing or unsafe', () => {
		const cwd = mkdtempSync(join(tmpdir(), 'bv-mcp-inject-'));
		mkdirSync(join(cwd, 'scripts'));
		mkdirSync(join(cwd, '.dev'));
		copyFileSync(join(process.cwd(), 'scripts/inject-private-config.cjs'), join(cwd, 'scripts/inject-private-config.cjs'));
		writeFileSync(join(cwd, 'wrangler.jsonc'), JSON.stringify({ name: 'bv-mcp-test', main: 'src/index.ts' }));
		writePrivateOverlay(cwd, {
			vars: {
				OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
				REQUIRE_PRODUCTION_BINDINGS: 'true',
				REJECT_QUERY_API_KEY: 'false',
			},
		});

		expect(() =>
			execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe', env: ALLOW_MISSING_ALERT_SECRET_ENV }),
		).toThrow(/REJECT_QUERY_API_KEY/);
	});

	it('fails closed when ALERT_WEBHOOK_URL is present in vars — the re-disclosure / secret-collision state (#1073)', () => {
		// A binding name cannot be both a var and a secret (wrangler rejects
		// `secret put` with [code: 10053] while it is), and `wrangler types`
		// renders every plaintext var inline on every deploy — the exact
		// disclosure #1073 reports. This must fail even when the value is a
		// real-looking URL, and even under the transition override: the
		// override exists for "not yet provisioned", not "still a plaintext var".
		const cwd = mkdtempSync(join(tmpdir(), 'bv-mcp-inject-'));
		mkdirSync(join(cwd, 'scripts'));
		mkdirSync(join(cwd, '.dev'));
		copyFileSync(join(process.cwd(), 'scripts/inject-private-config.cjs'), join(cwd, 'scripts/inject-private-config.cjs'));
		writeFileSync(join(cwd, 'wrangler.jsonc'), JSON.stringify({ name: 'bv-mcp-test', main: 'src/index.ts' }));
		writePrivateOverlay(cwd, {
			vars: {
				...productionVars(),
				ALERT_WEBHOOK_URL: 'https://alerts.example.test/webhook',
			},
		});

		expect(() =>
			execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe', env: ALLOW_MISSING_ALERT_SECRET_ENV }),
		).toThrow(/ALERT_WEBHOOK_URL is still present in vars/);
	});

	it('fails closed when the overlay declares a binding kind the merge does not handle', () => {
		// The merge is an allowlist, so an unhandled key is dropped in silence. A new
		// binding kind added only to the private overlay must stop the deploy, not vanish.
		const cwd = setupInjectFixture();
		writePrivateOverlay(cwd, {
			vars: productionVars(),
			hyperdrive: [{ binding: 'DB', id: 'not-a-real-id' }],
		});

		expect(() => runInject(cwd)).toThrow(/hyperdrive/);
	});

	it('fails closed when the overlay contradicts a public key whose value would be discarded', () => {
		const cwd = setupInjectFixture();
		writePrivateOverlay(cwd, {
			vars: productionVars(),
			durable_objects: { bindings: [{ name: 'QUOTA_COORDINATOR', class_name: 'SomethingElse' }] },
		});

		expect(() => runInject(cwd)).toThrow(/durable_objects/);
	});

	it('keeps the public compatibility_date when the overlay carries a stale copy', () => {
		// Merging the overlay's copy would silently regress the production runtime, so the
		// public value ships and the operator is warned about the dead configuration.
		const cwd = setupInjectFixture({ compatibility_date: '2026-07-29' });
		writePrivateOverlay(cwd, { vars: productionVars(), compatibility_date: '2026-04-22' });

		runInject(cwd);
		const injected = JSON.parse(readFileSync(join(cwd, 'wrangler.production.jsonc'), 'utf8')) as {
			compatibility_date?: string;
		};

		expect(injected.compatibility_date).toBe('2026-07-29');
	});

	it('declares required secrets so wrangler refuses to deploy without them', () => {
		const cwd = setupInjectFixture();
		writePrivateOverlay(cwd, { vars: productionVars() });

		runInject(cwd);
		const injected = JSON.parse(readFileSync(join(cwd, 'wrangler.production.jsonc'), 'utf8')) as {
			secrets?: { required?: string[] };
		};

		expect(injected.secrets?.required, 'the generated production config must declare its required secrets').toContain(
			'BV_API_KEY',
		);
		expect(injected.secrets?.required).toContain('OAUTH_SIGNING_SECRET');

		// Fail-soft capabilities must stay out: check_ssl, the recon tools and Cert Spotter
		// are all designed to degrade when unset, so requiring them would block a deploy
		// over a supported configuration.
		for (const optional of ['BV_RECON_KEY', 'BV_TLS_PROBE_KEY', 'CERTSPOTTER_TOKEN']) {
			expect(injected.secrets?.required, `${optional} is fail-soft and must not gate the deploy`).not.toContain(optional);
		}

		// ALERT_WEBHOOK_URL is a Worker secret now, but it is NOT added here — see
		// PRODUCTION_REQUIRED_SECRETS's own docstring: an entry here with the secret
		// not yet provisioned turns wrangler's own built-in check into a deploy
		// outage with no override, which would break exactly the transition deploy
		// this ticket's override exists to support.
		expect(injected.secrets?.required).not.toContain('ALERT_WEBHOOK_URL');
	});

	// wrangler.private.example.jsonc is the template operators copy to .dev/, and
	// scripts/deploy-private.mjs deploys the result. It previously carried its own
	// `durable_objects` copy that had gone stale, so a fresh overlay was missing
	// PROFILE_ACCUMULATOR entirely. Inject the real template against the real public
	// config so that class of drift fails here instead of in production.
	it('injects the shipped example overlay into a complete production config', () => {
		const cwd = mkdtempSync(join(tmpdir(), 'bv-mcp-inject-'));
		mkdirSync(join(cwd, 'scripts'));
		mkdirSync(join(cwd, '.dev'));
		copyFileSync(join(process.cwd(), 'scripts/inject-private-config.cjs'), join(cwd, 'scripts/inject-private-config.cjs'));
		copyFileSync(join(process.cwd(), 'wrangler.jsonc'), join(cwd, 'wrangler.jsonc'));
		copyFileSync(join(process.cwd(), 'wrangler.private.example.jsonc'), join(cwd, '.dev/wrangler.deploy.jsonc'));

		execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe', env: ALLOW_MISSING_ALERT_SECRET_ENV });
		const injected = JSON.parse(readFileSync(join(cwd, 'wrangler.production.jsonc'), 'utf8')) as {
			durable_objects?: { bindings?: Array<{ name?: string }> };
			migrations?: Array<{ tag?: string }>;
			triggers?: { crons?: string[] };
			vars?: Record<string, unknown>;
		};

		expect(
			injected.durable_objects?.bindings?.map((binding) => binding.name),
			'the example overlay must not shadow the public Durable Object bindings',
		).toEqual(['QUOTA_COORDINATOR', 'PROFILE_ACCUMULATOR']);
		expect(injected.migrations?.map((migration) => migration.tag)).toEqual(['v1', 'v2', 'v3']);
		expect(injected.triggers?.crons, 'cron triggers come from the public config, not the overlay').toHaveLength(3);
		// The shipped public config and example overlay must not reintroduce
		// ALERT_WEBHOOK_URL as a var (#1073) — that is the exact disclosure this
		// ticket removes, and the injector fails closed if either does.
		expect(injected.vars, 'ALERT_WEBHOOK_URL must not ship as a var').not.toHaveProperty('ALERT_WEBHOOK_URL');
	});
});

function setupInjectFixture(publicExtras: Record<string, unknown> = {}): string {
	const cwd = mkdtempSync(join(tmpdir(), 'bv-mcp-inject-'));
	mkdirSync(join(cwd, 'scripts'));
	mkdirSync(join(cwd, '.dev'));
	copyFileSync(join(process.cwd(), 'scripts/inject-private-config.cjs'), join(cwd, 'scripts/inject-private-config.cjs'));
	writeFileSync(join(cwd, 'wrangler.jsonc'), JSON.stringify({ name: 'bv-mcp-test', main: 'src/index.ts', ...publicExtras }));
	return cwd;
}

function runInject(cwd: string, env: NodeJS.ProcessEnv = ALLOW_MISSING_ALERT_SECRET_ENV): Buffer {
	return execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe', env });
}

function productionVars(): Record<string, string> {
	return {
		OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
		REQUIRE_PRODUCTION_BINDINGS: 'true',
		REJECT_QUERY_API_KEY: 'true',
	};
}

function writePrivateOverlay(cwd: string, config: Record<string, unknown>): void {
	writeFileSync(join(cwd, '.dev/wrangler.deploy.jsonc'), JSON.stringify(config));
}

/**
 * The ALERT_WEBHOOK_URL secret gate (#1073) — behavioral assertions on
 * `assessAlertWebhookSecretGate`'s returned verdict, requiring
 * scripts/inject-private-config.cjs directly so no subprocess, network, or
 * real wrangler call is involved. Mirrors the injection style
 * `scripts/ci/sidecar-deploy-drift-check.ts`'s tests use for
 * `assessSidecarDrift` (`test/audits/sidecar-deploy-drift-check.node.test.ts`).
 */
describe('ALERT_WEBHOOK_URL secret gate — assessAlertWebhookSecretGate', () => {
	const { assessAlertWebhookSecretGate, ALERT_WEBHOOK_SECRET_NAME, ALERT_WEBHOOK_OVERRIDE_ENV } = injectScript;

	it('is the ALERT_WEBHOOK_URL name and BV_ALLOW_MISSING_ALERT_SECRET override, matching the runbook', () => {
		expect(ALERT_WEBHOOK_SECRET_NAME).toBe('ALERT_WEBHOOK_URL');
		expect(ALERT_WEBHOOK_OVERRIDE_ENV).toBe('BV_ALLOW_MISSING_ALERT_SECRET');
	});

	it('PASSES when the secret is listed and the var is absent', () => {
		const listSecretNames = vi.fn(() => ['BV_API_KEY', 'ALERT_WEBHOOK_URL']);
		const verdict = assessAlertWebhookSecretGate({}, listSecretNames, false);
		expect(verdict.ok).toBe(true);
		expect(listSecretNames).toHaveBeenCalledTimes(1);
	});

	it('FAILS when ALERT_WEBHOOK_URL is present in vars, even though it is also a listed secret', () => {
		const listSecretNames = vi.fn(() => ['ALERT_WEBHOOK_URL']);
		const verdict = assessAlertWebhookSecretGate({ ALERT_WEBHOOK_URL: 'https://x.test/hook' }, listSecretNames, false);
		expect(verdict.ok).toBe(false);
		expect(verdict.message).toMatch(/still present in vars/);
		expect(verdict.message).toMatch(/10053/);
		// The re-disclosure state is checked before ever consulting the lister.
		expect(listSecretNames).not.toHaveBeenCalled();
	});

	it('FAILS when neither the var nor the secret is present', () => {
		const listSecretNames = vi.fn(() => ['BV_API_KEY', 'OAUTH_SIGNING_SECRET']);
		const verdict = assessAlertWebhookSecretGate({}, listSecretNames, false);
		expect(verdict.ok).toBe(false);
		expect(verdict.message).toMatch(/not set as a Worker secret/);
	});

	it('FAILS closed when the secret lister throws (network/auth failure or a timeout)', () => {
		const timeoutError = new Error('`wrangler secret list` timed out after 30000ms');
		const listSecretNames = vi.fn(() => {
			throw timeoutError;
		});
		const verdict = assessAlertWebhookSecretGate({}, listSecretNames, false);
		expect(verdict.ok).toBe(false);
		expect(verdict.message).toMatch(/could not verify/);
		expect(verdict.message).toMatch(/timed out after 30000ms/);
	});

	it('PASSES with a loud warning under the override, WITHOUT calling the lister', () => {
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
		try {
			const listSecretNames = vi.fn(() => ['ALERT_WEBHOOK_URL']);
			const verdict = assessAlertWebhookSecretGate({}, listSecretNames, true);
			expect(verdict.ok).toBe(true);
			expect(listSecretNames).not.toHaveBeenCalled();
			expect(warnSpy).toHaveBeenCalledTimes(1);
			expect(warnSpy.mock.calls[0]?.[0]).toMatch(/BV_ALLOW_MISSING_ALERT_SECRET=1/);
			expect(warnSpy.mock.calls[0]?.[0]).toMatch(/UNVERIFIED/);
		} finally {
			warnSpy.mockRestore();
		}
	});

	it('the override does NOT rescue a var still present in vars', () => {
		const listSecretNames = vi.fn(() => ['ALERT_WEBHOOK_URL']);
		const verdict = assessAlertWebhookSecretGate({ ALERT_WEBHOOK_URL: 'https://x.test/hook' }, listSecretNames, true);
		expect(verdict.ok).toBe(false);
		expect(verdict.message).toMatch(/still present in vars/);
	});
});

/**
 * `listProductionSecretNames` — the impure half that shells out to
 * `wrangler secret list`. Injected `spawnSync` so these tests never launch a
 * real process (mirrors `scripts/ci/sidecar-deploy-drift-check.ts`'s
 * `SpawnSyncLike` tests).
 */
describe('ALERT_WEBHOOK_URL secret gate — listProductionSecretNames', () => {
	const { listProductionSecretNames, WRANGLER_SECRET_LIST_ARGV } = injectScript;

	it('issues a read-only `wrangler secret list --format json --name <worker>` and nothing else', () => {
		const spawnSyncFn = vi.fn((_command: string, _args: string[]) => ({ status: 0, stdout: '[]', stderr: '' }));
		listProductionSecretNames('bv-dns-security-mcp', spawnSyncFn);

		expect(spawnSyncFn).toHaveBeenCalledTimes(1);
		const [command, args] = spawnSyncFn.mock.calls[0] as [string, string[]];
		expect(command).toBe('npx');
		expect(args).toEqual([...WRANGLER_SECRET_LIST_ARGV, 'bv-dns-security-mcp']);
		expect(args).not.toContain('put');
		expect(args).not.toContain('delete');
		expect(args).not.toContain('--config');
	});

	it('returns the secret names from a well-formed JSON array', () => {
		const spawnSyncFn = vi.fn(() => ({
			status: 0,
			stdout: JSON.stringify([{ name: 'BV_API_KEY', type: 'secret_text' }, { name: 'ALERT_WEBHOOK_URL', type: 'secret_text' }]),
			stderr: '',
		}));
		expect(listProductionSecretNames('bv-dns-security-mcp', spawnSyncFn)).toEqual(['BV_API_KEY', 'ALERT_WEBHOOK_URL']);
	});

	it('throws (never returns "no secrets") on a timed-out spawn', () => {
		const timeoutError = Object.assign(new Error('spawnSync npx ETIMEDOUT'), { code: 'ETIMEDOUT' });
		const spawnSyncFn = vi.fn(() => ({ status: null, stdout: '', stderr: '', error: timeoutError }));
		expect(() => listProductionSecretNames('bv-dns-security-mcp', spawnSyncFn)).toThrow(/timed out after 30000ms/);
	});

	it('throws on a SIGTERM-killed spawn even with no ETIMEDOUT error object', () => {
		const spawnSyncFn = vi.fn(() => ({ status: null, stdout: '', stderr: '', signal: 'SIGTERM' }));
		expect(() => listProductionSecretNames('bv-dns-security-mcp', spawnSyncFn)).toThrow(/timed out after 30000ms/);
	});

	it('throws on a non-zero exit without parsing stdout (an auth banner is not JSON)', () => {
		const spawnSyncFn = vi.fn(() => ({
			status: 1,
			stdout: '📎 It looks like you are authenticating Wrangler via a custom API token.',
			stderr: 'Authentication error [code: 10000]',
		}));
		expect(() => listProductionSecretNames('bv-dns-security-mcp', spawnSyncFn)).toThrow(/exited 1/);
	});

	it('throws on unparseable stdout', () => {
		const spawnSyncFn = vi.fn(() => ({ status: 0, stdout: 'not json', stderr: '' }));
		expect(() => listProductionSecretNames('bv-dns-security-mcp', spawnSyncFn)).toThrow(/did not return JSON/);
	});

	it('throws when the parsed result is not an array', () => {
		const spawnSyncFn = vi.fn(() => ({ status: 0, stdout: JSON.stringify({ oops: true }), stderr: '' }));
		expect(() => listProductionSecretNames('bv-dns-security-mcp', spawnSyncFn)).toThrow(/expected an array/);
	});
});
