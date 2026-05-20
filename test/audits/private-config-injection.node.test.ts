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
		writeFileSync(
			join(cwd, '.dev/wrangler.deploy.jsonc'),
			JSON.stringify({
				services: [
					{ binding: 'BV_WEB', service: 'blackveil-web-prod' },
					{ binding: 'BV_CERTSTREAM', service: 'bv-certstream-worker' },
				],
			}),
		);

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
});
