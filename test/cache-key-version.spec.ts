// SPDX-License-Identifier: BUSL-1.1

// Regression coverage for the "stale-after-deploy" cache bug: scan/check results
// were keyed by domain only, so a deploy kept serving pre-deploy results until the
// TTL expired. The fix threads BOTH the server version AND the dns-checks (scoring)
// version into every cache key — a bump to EITHER auto-invalidates the cache. The
// dns-checks version is essential: a scoring-only recalibration deploy does not move
// SERVER_VERSION, yet must still cold-start the cache (2026-06-01 parity finding).

import { describe, it, expect } from 'vitest';
import { buildCheckCacheKey, buildScanCacheKey } from '../src/lib/cache';
import { SERVER_VERSION } from '../src/lib/server-version';
import { PARITY_CORPUS_VERSION } from '@blackveil/dns-checks';

describe('buildCheckCacheKey', () => {
	it('includes the server version and the dns-checks version', () => {
		const key = buildCheckCacheKey('example.com', 'mx');
		expect(key).toContain(`v${SERVER_VERSION}`);
		expect(key).toContain(`dc${PARITY_CORPUS_VERSION}`);
	});

	it('produces the canonical cache:v<server>-dc<dnsChecks>:<domain>:check:<name> shape', () => {
		expect(buildCheckCacheKey('example.com', 'mx')).toBe(
			`cache:v${SERVER_VERSION}-dc${PARITY_CORPUS_VERSION}:example.com:check:mx`
		);
	});

	it('changes when the server version changes', () => {
		const a = buildCheckCacheKey('example.com', 'mx', '1.0.0');
		const b = buildCheckCacheKey('example.com', 'mx', '1.0.1');
		expect(a).not.toBe(b);
	});

	it('changes when ONLY the dns-checks (scoring) version changes (server version fixed)', () => {
		const a = buildCheckCacheKey('example.com', 'mx', '3.5.0', '1.3.11');
		const b = buildCheckCacheKey('example.com', 'mx', '3.5.0', '1.3.12');
		expect(a).not.toBe(b);
		expect(a).toContain('dc1.3.11');
		expect(b).toContain('dc1.3.12');
	});
});

describe('buildScanCacheKey', () => {
	it('includes the server version and the dns-checks version', () => {
		const key = buildScanCacheKey('example.com');
		expect(key).toContain(`v${SERVER_VERSION}`);
		expect(key).toContain(`dc${PARITY_CORPUS_VERSION}`);
	});

	it('produces the canonical cache:v<server>-dc<dnsChecks>:<domain> shape for the default profile', () => {
		expect(buildScanCacheKey('example.com')).toBe(
			`cache:v${SERVER_VERSION}-dc${PARITY_CORPUS_VERSION}:example.com`
		);
	});

	it('appends an explicit profile when provided', () => {
		expect(buildScanCacheKey('example.com', 'api_heavy')).toBe(
			`cache:v${SERVER_VERSION}-dc${PARITY_CORPUS_VERSION}:example.com:profile:api_heavy`
		);
	});

	it('changes when the server version changes', () => {
		const a = buildScanCacheKey('example.com', undefined, '1.0.0');
		const b = buildScanCacheKey('example.com', undefined, '1.0.1');
		expect(a).not.toBe(b);
	});

	it('changes when ONLY the dns-checks (scoring) version changes', () => {
		const a = buildScanCacheKey('example.com', undefined, '3.5.0', '1.3.11');
		const b = buildScanCacheKey('example.com', undefined, '3.5.0', '1.3.12');
		expect(a).not.toBe(b);
	});
});
