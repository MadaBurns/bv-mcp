// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import packageJsonSource from '../../package.json?raw';
import injectScriptSource from '../../scripts/inject-private-config.cjs?raw';

interface PackageJson {
	scripts?: Record<string, string>;
}

const pkg = JSON.parse(packageJsonSource) as PackageJson;

describe('deploy:prod pipeline integrity', () => {
	const deployScript = pkg.scripts?.['deploy:prod'] ?? '';

	it('exposes a deploy:prod script', () => {
		expect(deployScript, 'package.json must define a deploy:prod script').not.toBe('');
	});

	// F2: deploy:prod must rebuild @blackveil/dns-checks before deploying so wrangler
	// never bundles a stale dist/ (previously caused a real prod ReferenceError).
	it('rebuilds @blackveil/dns-checks as part of deploy:prod', () => {
		expect(deployScript, 'deploy:prod must build the dns-checks package before deploying').toContain(
			'npm -w packages/dns-checks run build',
		);
	});

	it('builds dns-checks BEFORE running wrangler deploy', () => {
		const buildIndex = deployScript.indexOf('npm -w packages/dns-checks run build');
		const deployIndex = deployScript.indexOf('wrangler deploy');
		expect(buildIndex, 'deploy:prod must contain the dns-checks build step').toBeGreaterThan(-1);
		expect(deployIndex, 'deploy:prod must contain a wrangler deploy step').toBeGreaterThan(-1);
		expect(buildIndex, 'the dns-checks build must run before wrangler deploy').toBeLessThan(deployIndex);
	});
});

describe('inject-private-config fail-closed on missing overlay', () => {
	// F3: a genuinely-absent private overlay must hard-fail the deploy (process.exit(1))
	// rather than `return` 0, which would let the `&&` chain proceed to wrangler against
	// a stale/wrong generated config (the silent-misconfigured-deploy class).
	// The missing-overlay branch is gated on !fs.existsSync(privateConfigPath) and
	// runs before the script reads/parses the overlay (parseJsonc(fs.readFileSync(privateConfigPath...)).
	function missingOverlayBranch(): string {
		const start = injectScriptSource.indexOf('existsSync(privateConfigPath)');
		const end = injectScriptSource.indexOf('parseJsonc(fs.readFileSync(privateConfigPath');
		expect(start, 'inject script must guard on existsSync(privateConfigPath)').toBeGreaterThan(-1);
		expect(end, 'inject script must parse the overlay after the guard').toBeGreaterThan(start);
		return injectScriptSource.slice(start, end);
	}

	it('hard-fails (process.exit(1)) when the private overlay is absent', () => {
		expect(missingOverlayBranch(), 'the missing-overlay branch must hard-fail rather than return 0').toContain(
			'process.exit(1)',
		);
	});

	it('does not silently `return` from the missing-overlay branch', () => {
		expect(missingOverlayBranch(), 'a bare return would let the deploy proceed against a stale config').not.toMatch(
			/\breturn\b/,
		);
	});
});
