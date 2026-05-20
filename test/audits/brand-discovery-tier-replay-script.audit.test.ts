// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';
import source from '../../scripts/brand-discovery-tier-replay.mjs?raw';

/**
 * T11 — n=14 benchmark replay script safety audit.
 *
 * Pins:
 *   - Output dir is .reports/brand-discovery-tier-replay/ (gitignored).
 *   - Domain list parsed from argv with a default of the 14 documented brands.
 *   - Both `tiered` and `baseline` modes are explicitly invoked per brand.
 *   - Output filenames are deterministic (no timestamp in filename) → idempotent
 *     re-runs overwrite cleanly.
 */
describe('brand-discovery tier replay script safety', () => {
	it('writes replay output only under .reports/brand-discovery-tier-replay/', () => {
		expect(source).toContain('.reports/brand-discovery-tier-replay');
		// No other top-level write paths.
		expect(source).not.toMatch(/writeFileSync\(\s*['"](?!\.reports\/)/);
	});

	it('reads the domain list from argv', () => {
		expect(source).toContain('process.argv.slice(2)');
	});

	it('defaults to the 14 documented production brands when argv is empty', () => {
		// The 14-brand cohort documented in the design doc (Task 11 / line 723).
		const expectedDefaults = [
			'google.com',
			'microsoft.com',
			'apple.com',
			'amazon.com',
			'github.com',
			'paypal.com',
			'brand-gamma.com',
			'brand-zeta.com',
			'brand-theta.com',
			'brand-kappa.com',
			'brand-alpha.com',
			'blackveilsecurity.com',
			'brand-eta.com',
			'stripe.com',
		];
		for (const brand of expectedDefaults) {
			expect(source).toContain(brand);
		}
	});

	it('explicitly invokes both tiered and baseline modes per brand', () => {
		expect(source).toContain("'tiered'");
		expect(source).toContain("'baseline'");
		// Threaded as the discovery_mode env var (classic = baseline downstream).
		expect(source).toContain('BV_REPORT_DISCOVERY_MODE');
	});

	it('uses deterministic per-brand filenames so re-runs overwrite cleanly', () => {
		// No Date.now()-based filenames (would defeat idempotency).
		expect(source).not.toMatch(/\$\{[^}]*Date\.now\(\)[^}]*\}\.json/);
		// File stem references the brand domain.
		expect(source).toMatch(/\$\{[^}]*(domain|brand|stem)[^}]*\}[^`'"]*\.json/i);
	});

	it('safely renames brand domains before using them in file paths', () => {
		// Path-traversal / shell-metachar guard — same hygiene as the planner benchmark.
		expect(source).toMatch(/replace\(\s*\/\[\^a-z0-9\.-\]/i);
	});

	it('extracts owned portfolio and tier metrics from the tiered sidecar shape', () => {
		expect(source).toContain('sidecar.ownedPortfolio?.total');
		expect(source).toContain('sidecar.performance?.tiers');
	});
});
