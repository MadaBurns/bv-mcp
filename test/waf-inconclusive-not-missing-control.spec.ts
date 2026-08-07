// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #638 (secondary defect) — a WAF-intercepted probe must be INCONCLUSIVE ONLY.
 *
 * A WAF challenge/block page means the probe never reached the origin. The scoring model
 * has two mutually-exclusive vocabularies for that situation and the WAF paths were
 * asserting BOTH:
 *
 *   - `missingControl: true`  = "we measured, and the control is ABSENT" → ZEROES the
 *     category (`buildCheckResult` forces score 0 / passed false).
 *   - `inconclusive: true` + `checkStatus: 'error'` = "we could not measure this" → the
 *     category is EXCLUDED from the weighted score and the denominator renormalises over
 *     what WAS measured (`transientFailures` in packages/dns-checks/src/scoring/engine.ts).
 *
 * Asserting absence from a failed probe is the "fabricate rather than abstain" class this
 * repo removed in 9a88e324. Today only the inconclusive path is taken, so the contradiction
 * was latent — but a change in flag precedence would have turned a WAF page into a
 * category-zeroing "control missing" verdict.
 *
 * This corpus pins the honest shape at three layers: the shared finding builder, the two
 * real tools that emit it, and the scoring engine's treatment of the result.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import type { CheckResult } from '../src/lib/scoring';

const { restore } = setupFetchMock();
afterEach(() => {
	restore();
	vi.resetModules();
});

describe('buildWafFinding — inconclusive, never missingControl', () => {
	it('carries inconclusive:true and NO missingControl for a challenge', async () => {
		const { buildWafFinding } = await import('../src/lib/waf-detection');
		const finding = buildWafFinding('http_security', { provider: 'cloudflare', kind: 'challenge' }, 403, { title: 'T', detail: 'D' });
		expect(finding.metadata?.inconclusive).toBe(true);
		expect(finding.metadata?.missingControl).toBeUndefined();
	});

	it('carries inconclusive:true and NO missingControl for a block', async () => {
		const { buildWafFinding } = await import('../src/lib/waf-detection');
		const finding = buildWafFinding('mta_sts', { provider: 'akamai', kind: 'block' }, 403, { title: 'T', detail: 'D' });
		expect(finding.metadata?.inconclusive).toBe(true);
		expect(finding.metadata?.missingControl).toBeUndefined();
	});

	it('carries inconclusive:true and NO missingControl for an edge-artifact 401', async () => {
		const { buildWafFinding } = await import('../src/lib/waf-detection');
		const finding = buildWafFinding('http_security', { provider: 'cloudflare', kind: 'edge-artifact' }, 401, { title: 'T', detail: 'D' });
		expect(finding.metadata?.inconclusive).toBe(true);
		expect(finding.metadata?.missingControl).toBeUndefined();
	});
});

describe('check_http_security — a WAF-blocked probe never claims the control is missing', () => {
	/** Every fetch answers with the same Cloudflare block page. */
	function mockCloudflareBlock(status: number, headers: Record<string, string>, body: string) {
		globalThis.fetch = vi.fn().mockImplementation(() =>
			Promise.resolve({
				ok: false,
				status,
				headers: new Headers(headers),
				body: null,
				text: async () => body,
			} as unknown as Response),
		);
	}

	it('a Cloudflare 403 block page is inconclusive-only (checkStatus error, score 0, no missingControl)', async () => {
		mockCloudflareBlock(403, { 'cf-ray': '91abc1234-SFO', server: 'cloudflare' }, 'Sorry, you have been blocked');
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const result = await checkHttpSecurity('example.com');

		expect(result.checkStatus).toBe('error');
		// An unmeasured check must never read as a PASS.
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		// …but nothing may assert absence.
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		const waf = result.findings.find((f) => f.metadata?.wafEvent === 'cloudflare');
		expect(waf?.metadata?.inconclusive).toBe(true);
	});

	// The sibling generic "blocked by security appliance" fallback (a 403 with no
	// Cloudflare/Akamai signature, handled inside @blackveil/dns-checks rather than here)
	// is pinned at package-source level in
	// packages/dns-checks/src/__tests__/checks/http-security-waf-block.test.ts — this
	// suite resolves the BUILT package, so a package-source assertion here would only be
	// meaningful after a dist rebuild.
});

describe('check_mta_sts — a WAF-blocked policy fetch never claims the control is missing', () => {
	function txtResponse(name: string, records: string[]) {
		return createDohResponse(
			[{ name, type: 16 }],
			records.map((data) => ({ name, type: 16, TTL: 300, data: `"${data}"` })),
		);
	}

	it('a Cloudflare challenge on the policy fetch is inconclusive-only', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('_mta-sts.')) return Promise.resolve(txtResponse('_mta-sts.example.com', ['v=STSv1; id=20260114010000']));
				return Promise.resolve(createDohResponse([], []));
			}
			if (url.includes('mta-sts.') && url.includes('.well-known')) {
				return Promise.resolve(
					new Response(null, { status: 403, headers: { 'cf-ray': '91def5678-AKL', 'cf-mitigated': 'challenge', server: 'cloudflare' } }),
				);
			}
			return Promise.resolve(new Response(null, { status: 404 }));
		});

		const { checkMtaSts } = await import('../src/tools/check-mta-sts');
		const result = await checkMtaSts('example.com');

		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
		const waf = result.findings.find((f) => f.metadata?.wafKind === 'challenge');
		expect(waf?.metadata?.inconclusive).toBe(true);
	});
});

describe('scoring treats a WAF-blocked category as EXCLUDED, not zeroed', () => {
	/** A healthy, measured result for any category. */
	async function healthy(category: string): Promise<CheckResult> {
		const { buildCheckResult, createFinding } = await import('../src/lib/scoring');
		const c = category as Parameters<typeof createFinding>[0];
		return {
			...buildCheckResult(c, [createFinding(c, `${category} OK`, 'info', 'Check passed')], true),
			checkStatus: 'completed' as const,
		};
	}

	it('a WAF-blocked http_security scores identically to omitting the check entirely, and strictly better than a real missing control', async () => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { computeScanScore, buildCheckResult, createFinding, isGraded } = await import('../src/lib/scoring');
		const { buildWafFinding } = await import('../src/lib/waf-detection');

		const others = await Promise.all(SCAN_CATEGORIES.filter((c) => c !== 'http_security').map(healthy));

		// (A) WAF-blocked: the honest shape emitted by check-http-security.ts.
		const wafBlocked: CheckResult = {
			...buildCheckResult('http_security', [
				buildWafFinding('http_security', { provider: 'cloudflare', kind: 'challenge' }, 403, {
					title: 'Cloudflare WAF challenge intercepted',
					detail: 'The fetched response appears to be a Cloudflare challenge page, not the real site.',
				}),
			]),
			score: 0,
			passed: false,
			checkStatus: 'error' as const,
		};

		// (C) A genuinely measured, genuinely absent control — the shape the contradictory
		// `missingControl` flag would have collapsed the WAF case into.
		const genuinelyMissing: CheckResult = {
			...buildCheckResult(
				'http_security',
				[
					createFinding('http_security', 'No security headers found', 'critical', 'The site serves no browser security headers.', {
						missingControl: true,
						confidence: 'deterministic',
					}),
				],
				false,
			),
			checkStatus: 'completed' as const,
		};

		const withWaf = computeScanScore([...others, wafBlocked]);
		const withoutHttp = computeScanScore(others); // (B) never ran at all
		const withMissing = computeScanScore([...others, genuinelyMissing]);

		// `ScanScore.overall` is `number | null` by design — null means "nothing gradeable was
		// measured" (evidence gate / unresolvable zone), and in JS `null < n` is `true`, so an
		// unnarrowed comparison below would silently PASS on an ungraded scan and vacate the
		// whole test. Narrow with the purpose-built `isGraded` guard rather than a cast.
		expect(isGraded(withWaf)).toBe(true);
		expect(isGraded(withMissing)).toBe(true);
		if (!isGraded(withWaf) || !isGraded(withMissing)) throw new Error('scan was ungraded — comparison would be vacuous');

		// EXCLUDED: no category score is published for an unmeasured category…
		expect(withWaf.categoryScores.http_security).toBeUndefined();
		// …and the headline renormalises to exactly the "never ran" score.
		expect(withWaf.overall).toBe(withoutHttp.overall);

		// ZEROED: a real missing control IS published as 0 and drags the headline down.
		expect(withMissing.categoryScores.http_security).toBe(0);
		expect(withMissing.overall).toBeLessThan(withWaf.overall);

		// The evidence ratio is what reports the shortfall honestly — not a lower score.
		expect(withWaf.evidence.completed).toBe(SCAN_CATEGORIES.length - 1);
		expect(withWaf.evidence.attempted).toBe(SCAN_CATEGORIES.length);
	});

	// The other three never-completed-probe branches (401, residual 4xx, connection
	// failure/timeout) are emitted by @blackveil/dns-checks, whose SHAPE is pinned in
	// packages/dns-checks/src/__tests__/checks/http-security-waf-block.test.ts against the
	// source module. Here we pin the ENGINE's treatment of that shape, using literals rather
	// than calling the built package — so this stays meaningful without a dist rebuild.
	const UNMEASURED_SHAPES: Array<[label: string, severity: 'info' | 'medium', checkStatus: 'error' | 'timeout']> = [
		['401 auth-gated endpoint', 'info', 'error'],
		['residual 4xx (404/429/…)', 'medium', 'error'],
		['connection failure', 'medium', 'error'],
		['connection timeout', 'medium', 'timeout'],
	];

	it.each(UNMEASURED_SHAPES)('%s is EXCLUDED, not zeroed', async (label, severity, checkStatus) => {
		const { SCAN_CATEGORIES } = await import('../src/tools/scan-domain');
		const { computeScanScore, buildCheckResult, createFinding } = await import('../src/lib/scoring');

		const others = await Promise.all(SCAN_CATEGORIES.filter((c) => c !== 'http_security').map(healthy));
		const unmeasured: CheckResult = {
			...buildCheckResult('http_security', [
				createFinding('http_security', label, severity, 'The probe never completed, so no header was observed.', { inconclusive: true }),
			]),
			// The explicit zeroing the package now applies in place of the removed
			// `missingControl` flag — without it these compute to 100 (info) / 85 (medium)
			// and an unmeasured check would read as a PASS.
			score: 0,
			passed: false,
			checkStatus,
		};

		const withUnmeasured = computeScanScore([...others, unmeasured]);
		const withoutHttp = computeScanScore(others);

		expect(withUnmeasured.categoryScores.http_security).toBeUndefined();
		expect(withUnmeasured.overall).toBe(withoutHttp.overall);
		expect(withUnmeasured.grade).toBe(withoutHttp.grade);
	});
});
