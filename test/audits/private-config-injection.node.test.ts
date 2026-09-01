// SPDX-License-Identifier: BUSL-1.1

import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

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
			vars: {
				ALERT_WEBHOOK_URL: 'https://alerts.example.test/webhook',
				OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
				REQUIRE_PRODUCTION_BINDINGS: 'true',
				REJECT_QUERY_API_KEY: 'true',
			},
			services: [
				{ binding: 'BV_WEB', service: 'blackveil-web-prod' },
				{ binding: 'BV_CERTSTREAM', service: 'bv-certstream-worker' },
			],
		});

		execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe' });
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
				ALERT_WEBHOOK_URL: 'https://alerts.example.test/webhook',
				OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
				REQUIRE_PRODUCTION_BINDINGS: 'true',
				REJECT_QUERY_API_KEY: 'false',
			},
		});

		expect(() => execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe' })).toThrow(
			/REJECT_QUERY_API_KEY/,
		);
	});

	it('fails closed when production alert delivery is not configured', () => {
		const cwd = mkdtempSync(join(tmpdir(), 'bv-mcp-inject-'));
		mkdirSync(join(cwd, 'scripts'));
		mkdirSync(join(cwd, '.dev'));
		copyFileSync(join(process.cwd(), 'scripts/inject-private-config.cjs'), join(cwd, 'scripts/inject-private-config.cjs'));
		writeFileSync(join(cwd, 'wrangler.jsonc'), JSON.stringify({ name: 'bv-mcp-test', main: 'src/index.ts' }));
		writePrivateOverlay(cwd, {
			vars: {
				ALERT_WEBHOOK_URL: '',
				OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
				REQUIRE_PRODUCTION_BINDINGS: 'true',
				REJECT_QUERY_API_KEY: 'true',
			},
		});

		expect(() => execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe' })).toThrow(
			/ALERT_WEBHOOK_URL/,
		);
	});

	it('fails closed when the overlay declares a binding kind the merge does not handle', () => {
		// The merge is an allowlist, so an unhandled key is dropped in silence. A new
		// binding kind added only to the private overlay must stop the deploy, not vanish.
		const cwd = setupInjectFixture();
		writePrivateOverlay(cwd, {
			vars: productionVars(),
			hyperdrive: [{ binding: 'DB', id: 'not-a-real-id' }],
		});

		expect(() => execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe' })).toThrow(
			/hyperdrive/,
		);
	});

	it('fails closed when the overlay contradicts a public key whose value would be discarded', () => {
		const cwd = setupInjectFixture();
		writePrivateOverlay(cwd, {
			vars: productionVars(),
			durable_objects: { bindings: [{ name: 'QUOTA_COORDINATOR', class_name: 'SomethingElse' }] },
		});

		expect(() => execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe' })).toThrow(
			/durable_objects/,
		);
	});

	it('keeps the public compatibility_date when the overlay carries a stale copy', () => {
		// Merging the overlay's copy would silently regress the production runtime, so the
		// public value ships and the operator is warned about the dead configuration.
		const cwd = setupInjectFixture({ compatibility_date: '2026-07-29' });
		writePrivateOverlay(cwd, { vars: productionVars(), compatibility_date: '2026-04-22' });

		execFileSync(process.execPath, ['scripts/inject-private-config.cjs'], { cwd, stdio: 'pipe' });
		const injected = JSON.parse(readFileSync(join(cwd, 'wrangler.production.jsonc'), 'utf8')) as {
			compatibility_date?: string;
		};

		expect(injected.compatibility_date).toBe('2026-07-29');
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

function productionVars(): Record<string, string> {
	return {
		ALERT_WEBHOOK_URL: 'https://alerts.example.test/webhook',
		OAUTH_ISSUER: 'https://dns-mcp.blackveilsecurity.com',
		REQUIRE_PRODUCTION_BINDINGS: 'true',
		REJECT_QUERY_API_KEY: 'true',
	};
}

function writePrivateOverlay(cwd: string, config: Record<string, unknown>): void {
	writeFileSync(join(cwd, '.dev/wrangler.deploy.jsonc'), JSON.stringify(config));
}
