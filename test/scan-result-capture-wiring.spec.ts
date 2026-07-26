// SPDX-License-Identifier: BUSL-1.1

/**
 * Pins which capture hook each tool path on `handleToolsCall` actually invokes.
 *
 * `resultCapture` is the single-`CheckResult` hook and fires only on the
 * `TOOL_REGISTRY` path. `scan_domain` is an orchestrator returning a
 * `ScanDomainResult` and fires `scanResultCapture` instead. The tenant scan
 * paths originally subscribed to `resultCapture` for `scan_domain`, so their
 * `captured` was null on every scan and every persisted row carried null
 * score/grade/result_json — while their tests passed, because those tests
 * mocked `handleToolsCall` and invoked `resultCapture` themselves.
 *
 * These tests call the REAL `handleToolsCall` (DNS mocked) and assert which
 * hook fires and which does not, so the same divergence cannot recur silently.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, txtResponse } from './helpers/dns-mock';
import { IN_MEMORY_CACHE } from '../src/lib/cache';
import { parseTenantScanSnapshot, toTenantScanSnapshot } from '../src/tenants/scan-snapshot';
import type { ScanDomainResult } from '../src/tools/scan-domain';
import type { CheckResult } from '../src/lib/scoring';

const { restore } = setupFetchMock();
afterEach(() => restore());

/** Catch-all DoH mock: every check resolves to a benign TXT answer. */
function mockDns(domain: string) {
	globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(txtResponse(domain, ['v=spf1 -all'])));
}

describe('handleToolsCall capture-hook wiring', () => {
	it('fires scanResultCapture (not resultCapture) for scan_domain', async () => {
		IN_MEMORY_CACHE.clear();
		mockDns('capture-wiring.example.com');

		let scanCaptured: ScanDomainResult | null = null;
		let checkCaptured: CheckResult | null = null;

		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'scan_domain', arguments: { domain: 'capture-wiring.example.com' } }, undefined, {
			scanResultCapture: (r) => {
				scanCaptured = r;
			},
			resultCapture: (r) => {
				checkCaptured = r;
			},
		});

		// The CheckResult hook must NOT fire — scan_domain never produces one.
		expect(checkCaptured).toBeNull();
		// The scan hook must fire, with the nested ScanDomainResult shape.
		expect(scanCaptured).not.toBeNull();
		const scan = scanCaptured as unknown as ScanDomainResult;
		expect(scan.domain).toBe('capture-wiring.example.com');
		expect(typeof scan.score.overall).toBe('number');
		expect(typeof scan.score.grade).toBe('string');
		expect(Array.isArray(scan.score.findings)).toBe(true);
	});

	it('fires resultCapture (not scanResultCapture) for a registry check tool', async () => {
		IN_MEMORY_CACHE.clear();
		mockDns('capture-wiring-leaf.example.com');

		let scanCaptured: ScanDomainResult | null = null;
		let checkCaptured: CheckResult | null = null;

		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'check_spf', arguments: { domain: 'capture-wiring-leaf.example.com' } }, undefined, {
			scanResultCapture: (r) => {
				scanCaptured = r;
			},
			resultCapture: (r) => {
				checkCaptured = r;
			},
		});

		expect(scanCaptured).toBeNull();
		expect(checkCaptured).not.toBeNull();
		expect((checkCaptured as unknown as CheckResult).category).toBe('spf');
	});

	it('projects a real captured scan onto a tenant snapshot that round-trips through result_json', async () => {
		IN_MEMORY_CACHE.clear();
		mockDns('capture-roundtrip.example.com');

		let scanCaptured: ScanDomainResult | null = null;
		const { handleToolsCall } = await import('../src/handlers/tools');
		await handleToolsCall({ name: 'scan_domain', arguments: { domain: 'capture-roundtrip.example.com' } }, undefined, {
			scanResultCapture: (r) => {
				scanCaptured = r;
			},
		});

		const snapshot = toTenantScanSnapshot(scanCaptured as unknown as ScanDomainResult);
		// The columns the tenant `scans` row binds must be populated, not null.
		expect(typeof snapshot.score).toBe('number');
		expect(snapshot.grade.length).toBeGreaterThan(0);

		// result_json is written from the snapshot and read back by the
		// fingerprint pre-flight — the two directions must agree.
		const reparsed = parseTenantScanSnapshot(JSON.stringify(snapshot));
		expect(reparsed).toEqual(snapshot);
	});

	it('rejects unusable result_json rows (DLQ marker, malformed, legacy) rather than re-persisting them', () => {
		expect(parseTenantScanSnapshot(null)).toBeNull();
		expect(parseTenantScanSnapshot('')).toBeNull();
		expect(parseTenantScanSnapshot('not json')).toBeNull();
		expect(parseTenantScanSnapshot('[]')).toBeNull();
		// The DLQ row writeDlqRow persists.
		expect(parseTenantScanSnapshot(JSON.stringify({ error: 'queue_dlq' }))).toBeNull();
		// A legacy CheckResult-shaped row has no `grade`.
		expect(parseTenantScanSnapshot(JSON.stringify({ category: 'spf', score: 90, findings: [] }))).toBeNull();
	});
});
