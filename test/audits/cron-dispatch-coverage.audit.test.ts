// SPDX-License-Identifier: BUSL-1.1
//
// Audit test: every cron trigger declared in the deployed `wrangler.jsonc`
// `triggers.crons[]` must route to a DEDICATED dispatch branch in the
// `scheduled()` handler — not the catch-all 15-min sweep — unless it is an
// explicitly-recognized periodic fallback.
//
// Background (F1): the dispatcher uses `if / else if / else`, where the `else`
// is a catch-all. The original bug did NOT leave Sunday unhandled — it routed
// the deployed named-DOW trigger `0 2 * * SUN` to the WRONG handler (the 15-min
// fallback) because the dispatcher string-compared against the numeric form
// `0 2 * * 0`. A naive "is each cron handled?" check would pass trivially
// (the catch-all "handles" everything) and would have passed against the buggy
// code too. So this audit asserts each non-fallback cron routes to its OWN
// route via the shared `routeCron()` SSOT, comparing the NORMALIZED form so the
// named/numeric DOW variants are equivalent.
//
// Pre-fix, `routeCron('0 2 * * SUN')` returned `'periodic'` (string-equality
// miss) → this audit fails. Post-fix it returns `'weekly-tenant-rescan'` →
// passes. It also trips if a future cron is added to wrangler.jsonc without a
// dedicated dispatch branch.
//
// Per testing-methodology.md principle 4 — audit tests replace review checklists.

import { describe, it, expect } from 'vitest';
import wranglerSource from '../../wrangler.jsonc?raw';
import { routeCron, normalizeCron } from '../../src';

interface WranglerConfig {
	triggers?: { crons?: string[] };
}

const config = JSON.parse(wranglerSource) as WranglerConfig;
const declaredCrons = config.triggers?.crons ?? [];

// Crons that are INTENTIONALLY served by the catch-all periodic ('else') branch.
// Normalized so a future named-DOW form would still match the right entry.
const KNOWN_PERIODIC_FALLBACK = new Set(['*/15 * * * *'].map(normalizeCron));

describe('cron dispatch coverage audit', () => {
	it('wrangler.jsonc declares at least one cron trigger', () => {
		expect(declaredCrons.length).toBeGreaterThan(0);
	});

	it('every declared cron routes to a dedicated branch (or the explicit periodic fallback)', () => {
		const misrouted = declaredCrons.filter((cron) => {
			if (KNOWN_PERIODIC_FALLBACK.has(normalizeCron(cron))) return false;
			// A non-fallback cron MUST resolve to a dedicated route, never the
			// catch-all 'periodic'. This is what fails pre-fix for '0 2 * * SUN'.
			return routeCron(cron) === 'periodic';
		});
		expect(
			misrouted,
			`These declared cron triggers fall through to the catch-all 'periodic' (15-min) branch ` +
				`instead of a dedicated handler — either wire a dispatch branch in scheduled()/routeCron() ` +
				`or add the cron to KNOWN_PERIODIC_FALLBACK if that is intentional: ${misrouted.join(', ')}`,
		).toEqual([]);
	});

	it('the deployed named-DOW weekly trigger routes to the tenant weekly rescan (premise-independent)', () => {
		// Guards both forms regardless of how Cloudflare passes event.cron back.
		expect(routeCron('0 2 * * SUN')).toBe('weekly-tenant-rescan');
		expect(routeCron('0 2 * * 0')).toBe('weekly-tenant-rescan');
	});
});
