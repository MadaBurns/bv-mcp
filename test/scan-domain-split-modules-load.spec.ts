// SPDX-License-Identifier: BUSL-1.1

/**
 * Load-order guard for the scan-domain.ts split (SQ-537).
 *
 * The orchestrator's helpers moved into five leaf modules under src/tools/scan/.
 * A cycle between them (or back to the scan-domain barrel) can throw a TDZ
 * ReferenceError at Worker start-up that `tsc` does not see. Each module is
 * imported ON ITS OWN in a fresh module registry, and one known export of each
 * is asserted defined. The adaptive-weight cache is module-level mutable state:
 * it must be MOVED, so the barrel's re-export has to be the very same Map.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
	vi.resetModules();
});

describe('scan-domain split modules load standalone', () => {
	it('check-dispatch loads on its own', async () => {
		vi.resetModules();
		const mod = await import('../src/tools/scan/check-dispatch');
		expect(mod.CHECK_DISPATCH).toBeDefined();
		expect(mod.SCAN_CATEGORIES.length).toBeGreaterThan(0);
		expect(mod.CHECKS_WITHOUT_DNS_POOL.has('ssl')).toBe(true);
	});

	it('scan-types loads on its own (type-only module, empty at runtime)', async () => {
		vi.resetModules();
		const mod = await import('../src/tools/scan/scan-types');
		expect(mod).toBeDefined();
	});

	it('early-results loads on its own', async () => {
		vi.resetModules();
		const mod = await import('../src/tools/scan/early-results');
		expect(typeof mod.buildUnscoredResult).toBe('function');
		expect(typeof mod.buildNonResolvingResult).toBe('function');
		expect(typeof mod.buildDnsBrokenResult).toBe('function');
	});

	it('check-retry loads on its own', async () => {
		vi.resetModules();
		const mod = await import('../src/tools/scan/check-retry');
		expect(typeof mod.runCheckRetry).toBe('function');
		expect(typeof mod.safeCheck).toBe('function');
		expect(typeof mod.shouldRetry).toBe('function');
	});

	it('adaptive-weights loads on its own', async () => {
		vi.resetModules();
		const mod = await import('../src/tools/scan/adaptive-weights');
		expect(typeof mod.fetchAdaptiveWeights).toBe('function');
		expect(typeof mod.evictAdaptiveWeightCache).toBe('function');
		expect(mod._adaptiveWeightCacheForTest).toBeInstanceOf(Map);
	});

	it('the scan-domain barrel still exports every previous name', async () => {
		vi.resetModules();
		const barrel = await import('../src/tools/scan-domain');
		expect(typeof barrel.scanDomain).toBe('function');
		expect(barrel.CHECK_DISPATCH).toBeDefined();
		expect(barrel.SCAN_CATEGORIES.length).toBeGreaterThan(0);
		expect(barrel.CHECKS_WITHOUT_DNS_POOL).toBeInstanceOf(Set);
		expect(typeof barrel.runCheckRetry).toBe('function');
		expect(typeof barrel.evictAdaptiveWeightCache).toBe('function');
		expect(barrel._adaptiveWeightCacheForTest).toBeInstanceOf(Map);
		expect(typeof barrel.formatScanReport).toBe('function');
		expect(typeof barrel.buildStructuredScanResult).toBe('function');
	});

	it('old-path and new-path share one moved binding, not a copy', async () => {
		vi.resetModules();
		const oldPath = await import('../src/tools/scan-domain');
		const newPath = await import('../src/tools/scan/adaptive-weights');
		const dispatch = await import('../src/tools/scan/check-dispatch');
		const retry = await import('../src/tools/scan/check-retry');
		// Review Focus 3: the cache is the same object, so test reset helpers clear what production reads.
		expect(oldPath._adaptiveWeightCacheForTest).toBe(newPath._adaptiveWeightCacheForTest);
		expect(oldPath.evictAdaptiveWeightCache).toBe(newPath.evictAdaptiveWeightCache);
		expect(oldPath.CHECK_DISPATCH).toBe(dispatch.CHECK_DISPATCH);
		expect(oldPath.SCAN_CATEGORIES).toBe(dispatch.SCAN_CATEGORIES);
		expect(oldPath.CHECKS_WITHOUT_DNS_POOL).toBe(dispatch.CHECKS_WITHOUT_DNS_POOL);
		expect(oldPath.runCheckRetry).toBe(retry.runCheckRetry);
	});
});
