// SPDX-License-Identifier: BUSL-1.1
//
// Bug-hunt: check_subdomain_takeover cacheKey must fold list CONTENTS, not just
// LENGTH. Two different same-length custom subdomain lists for the same domain
// must NOT collide on one cache entry (5-min TTL, global per domain+checkName) —
// otherwise caller B's list silently gets caller A's takeover results.

import { describe, it, expect } from 'vitest';

describe('check_subdomain_takeover cacheKey', () => {
	it('produces DIFFERENT keys for different same-length custom lists', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_subdomain_takeover.cacheKey;

		const keyA = cacheKey({ subdomains: ['a', 'b', 'c'] });
		const keyB = cacheKey({ subdomains: ['x', 'y', 'z'] });

		expect(keyA).not.toBe(keyB);
	});

	it('produces the SAME key for an identical list', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_subdomain_takeover.cacheKey;

		const keyA = cacheKey({ subdomains: ['a', 'b', 'c'] });
		const keyB = cacheKey({ subdomains: ['a', 'b', 'c'] });

		expect(keyA).toBe(keyB);
	});

	it('falls back to the :default key when no custom list is supplied', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_subdomain_takeover.cacheKey;

		expect(cacheKey({})).toBe('subdomain_takeover:default');
	});
});
