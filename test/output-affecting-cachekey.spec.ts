// SPDX-License-Identifier: BUSL-1.1
//
// Bug-hunt: every argument that changes a tool's OUTPUT must be part of that
// tool's cacheKey, because the key is the cache identity
// (`buildCheckCacheKey(domain, cacheKey(args))` in src/handlers/tools.ts).
// An omitted argument lets caller B silently receive caller A's cached result
// for the whole TTL window.
//
// Two omissions are covered here:
//  - `check_fast_flux.rounds` (5-min TTL): 3 rounds vs 5 rounds run a different
//    number of DNS probes, so they disagree on rapid-rotation detection.
//  - `discover_brand_domains.dkim_selectors` (1-hour TTL, and the result is
//    served to every caller of the same seed): the selector list is passed
//    straight into the `dkim_key_reuse` signal probe
//    (src/tools/discover-brand-domains.ts:1292), which changes the candidate
//    set and their confidences.

import { describe, it, expect } from 'vitest';

describe('check_fast_flux cacheKey', () => {
	it('produces DIFFERENT keys for different round counts', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_fast_flux.cacheKey;

		expect(cacheKey({ rounds: 3 })).not.toBe(cacheKey({ rounds: 5 }));
	});

	it('produces the SAME key for an identical round count', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_fast_flux.cacheKey;

		expect(cacheKey({ rounds: 4 })).toBe(cacheKey({ rounds: 4 }));
	});

	it('folds the CLAMPED round count, so out-of-range values share the entry they agree on', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_fast_flux.cacheKey;

		// checkFastFlux clamps with Math.max(3, Math.min(5, rounds ?? 3)).
		// rounds=1 and rounds=99 run 3 and 5 rounds respectively, so they must
		// collide with the explicit values rather than minting unbounded keys.
		expect(cacheKey({ rounds: 1 })).toBe(cacheKey({ rounds: 3 }));
		expect(cacheKey({ rounds: 99 })).toBe(cacheKey({ rounds: 5 }));
		expect(cacheKey({})).toBe(cacheKey({ rounds: 3 }));
	});

	it('keeps the recon-binding prefix distinct from the non-recon key', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.check_fast_flux.cacheKey;

		const recon = cacheKey({ rounds: 3 }, { reconBinding: {} as never });
		expect(recon).toContain('fast_flux:recon');
		expect(recon).not.toBe(cacheKey({ rounds: 3 }));
	});
});

describe('discover_brand_domains cacheKey', () => {
	it('produces DIFFERENT keys for different same-length dkim_selectors lists', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.discover_brand_domains.cacheKey;

		expect(cacheKey({ dkim_selectors: ['google', 'selector1'] })).not.toBe(
			cacheKey({ dkim_selectors: ['k1', 'selector2'] }),
		);
	});

	it('produces the SAME key for an identical selector list regardless of order', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.discover_brand_domains.cacheKey;

		expect(cacheKey({ dkim_selectors: ['b', 'a'] })).toBe(cacheKey({ dkim_selectors: ['a', 'b'] }));
	});

	it('distinguishes an omitted selector list from an explicit one', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.discover_brand_domains.cacheKey;

		// Omitted means "probe the built-in common selectors"; an explicit list
		// means "probe exactly these". Different probes, different candidates.
		expect(cacheKey({})).not.toBe(cacheKey({ dkim_selectors: ['google'] }));
	});

	it('stays stable when the other output-affecting arguments are unchanged', async () => {
		const { TOOL_REGISTRY } = await import('../src/handlers/tools');
		const cacheKey = TOOL_REGISTRY.discover_brand_domains.cacheKey;

		const base = { signals: ['san', 'ns'], depth: 'deep', discovery_mode: 'tiered', min_confidence: 0.8 };
		expect(cacheKey(base)).toBe(cacheKey({ ...base }));
		expect(cacheKey(base)).not.toBe(cacheKey({ ...base, min_confidence: 0.9 }));
	});
});
