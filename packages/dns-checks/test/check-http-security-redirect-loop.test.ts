// SPDX-License-Identifier: BUSL-1.1

/**
 * SQ-204 (chaos SQ-194 H3) — package-level coverage for `checkHTTPSecurity`'s exhausted
 * redirect-hop-cap branch.
 *
 * A persistent redirect loop is correctly BOUNDED by `MAX_REDIRECT_HOPS`, but the cap being
 * exhausted while the last response is STILL a 3xx used to fall through to
 * `analyzeSecurityHeaders()` as if that redirect response were the final page —
 * `checkStatus` stayed undefined (measured) and a probe that never reached the origin
 * produced a confident "header missing" slate (issue #638 law: a cut probe must not be
 * scored as absence). The fix routes that branch to the same abstention shape the
 * deadline-exceeded and blocked-probe branches already use.
 *
 * Imports the SOURCE module, not the built `@blackveil/dns-checks` — this assertion must be
 * meaningful without a dist rebuild (matches src/__tests__/checks/http-security-waf-block.test.ts).
 */

import { describe, it, expect } from 'vitest';
import { checkHTTPSecurity, MAX_REDIRECT_HOPS } from '../src/checks/check-http-security';
import type { FetchFunction } from '../src/types';

describe('checkHTTPSecurity — exhausted redirect hop cap abstains, not scores (SQ-204)', () => {
	it('a chain that never terminates hits the hop cap and abstains with no missingControl / header findings', async () => {
		let calls = 0;
		const loopingFetch: FetchFunction = async () => {
			calls += 1;
			return new Response(null, {
				status: 301,
				headers: new Headers({
					location: `https://loop.example.com/hop-${calls}`,
					// A real header the old code would have read as "present" on the (never-final)
					// redirect hop — proves the fix isn't merely "the redirect had no headers".
					'content-security-policy': "default-src 'self'",
				}),
			});
		};

		const result = await checkHTTPSecurity('loop.example.com', loopingFetch);

		// Bounded: MAX_REDIRECT_HOPS hops inside followRedirects, plus the initial HEAD fetch.
		expect(calls).toBeLessThanOrEqual(MAX_REDIRECT_HOPS + 1);
		expect(calls).toBeGreaterThan(1);

		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);

		const finding = result.findings.find((f) => f.metadata?.errorKind === 'redirect_chain_unresolved');
		expect(finding, 'must carry the redirect_chain_unresolved abstention finding').toBeDefined();
		expect(finding!.metadata?.inconclusive).toBe(true);

		// The two properties in tension (issue #638): no claim of absence, but still an
		// unmeasured zero, not a computed pass.
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		expect(result.findings.some((f) => /^No /.test(f.title))).toBe(false);
	});

	it('negative control: a chain that resolves to a final page WITHIN the hop cap is analyzed normally (byte-identical to pre-fix)', async () => {
		const hops: Record<string, Response> = {
			'https://final.example.com/': new Response(null, {
				status: 200,
				headers: new Headers({
					'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
					'x-frame-options': 'DENY',
					'x-content-type-options': 'nosniff',
					'permissions-policy': 'camera=()',
					'referrer-policy': 'no-referrer',
					'cross-origin-resource-policy': 'same-origin',
					'cross-origin-opener-policy': 'same-origin',
					'cross-origin-embedder-policy': 'require-corp',
				}),
			}),
		};
		const resolvingFetch: FetchFunction = async (url) => {
			if (url === 'https://loop.example.com') {
				return new Response(null, { status: 301, headers: new Headers({ location: 'https://final.example.com/' }) });
			}
			return hops[url as string] ?? new Response(null, { status: 404 });
		};

		const result = await checkHTTPSecurity('loop.example.com', resolvingFetch);

		expect(result.checkStatus).toBeUndefined();
		expect(result.findings.some((f) => f.metadata?.errorKind === 'redirect_chain_unresolved')).toBe(false);
		expect(result.findings.some((f) => f.metadata?.inconclusive === true)).toBe(false);
	});
});
