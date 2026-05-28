// SPDX-License-Identifier: BUSL-1.1

// Regression coverage for the "stale-after-deploy" cache bug: scan/check
// results were keyed by domain only, so a deploy kept serving pre-deploy
// results until the TTL expired. The fix threads SERVER_VERSION into every
// scan/check cache key so a version bump auto-invalidates the cache.

import { describe, it, expect } from 'vitest';
import { buildCheckCacheKey, buildScanCacheKey } from '../src/lib/cache';
import { SERVER_VERSION } from '../src/lib/server-version';

describe('buildCheckCacheKey', () => {
	it('includes the server version', () => {
		const key = buildCheckCacheKey('example.com', 'mx');
		expect(key).toContain(`v${SERVER_VERSION}`);
	});

	it('produces the canonical cache:v<version>:<domain>:check:<name> shape', () => {
		expect(buildCheckCacheKey('example.com', 'mx')).toBe(`cache:v${SERVER_VERSION}:example.com:check:mx`);
	});

	it('changes when the version changes', () => {
		const a = buildCheckCacheKey('example.com', 'mx', '1.0.0');
		const b = buildCheckCacheKey('example.com', 'mx', '1.0.1');
		expect(a).not.toBe(b);
		expect(a).toContain('v1.0.0');
		expect(b).toContain('v1.0.1');
	});
});

describe('buildScanCacheKey', () => {
	it('includes the server version', () => {
		const key = buildScanCacheKey('example.com');
		expect(key).toContain(`v${SERVER_VERSION}`);
	});

	it('produces the canonical cache:v<version>:<domain> shape for the default profile', () => {
		expect(buildScanCacheKey('example.com')).toBe(`cache:v${SERVER_VERSION}:example.com`);
	});

	it('appends an explicit profile when provided', () => {
		expect(buildScanCacheKey('example.com', 'api_heavy')).toBe(`cache:v${SERVER_VERSION}:example.com:profile:api_heavy`);
	});

	it('changes when the version changes', () => {
		const a = buildScanCacheKey('example.com', undefined, '1.0.0');
		const b = buildScanCacheKey('example.com', undefined, '1.0.1');
		expect(a).not.toBe(b);
	});
});
