// SPDX-License-Identifier: BUSL-1.1

import { describe, expect, it } from 'vitest';

/**
 * Unit tests for the shared WAF interception detection (issue #455).
 *
 * Mock isolation: import the unit under test dynamically inside each test fn
 * (bv-mcp workers-pool convention). No fetch mocking is needed here — these are
 * pure functions over real `Headers` objects.
 */

function headers(init: Record<string, string>): Headers {
	return new Headers(init);
}

describe('detectWafEvent — Akamai branch (tightened, #455)', () => {
	it('returns null for a 200 with Server: akamaighost regardless of body', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ server: 'AkamaiGHost' }), 'Access Denied', 200)).toBeNull();
	});

	it('returns an akamai block for a 403 with akamaighost AND an access-denied body', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ server: 'AkamaiGHost' }), 'Access Denied Reference #18.abc', 403)).toEqual({
			provider: 'akamai',
			kind: 'block',
		});
	});

	it('returns null for a genuine origin 404 with akamaighost and a benign body (NOT a WAF block)', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ server: 'AkamaiGHost' }), 'not found', 404)).toBeNull();
	});

	it('returns null for a 403 with akamaighost but no body signature (bare Server header)', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ server: 'AkamaiGHost' }), '', 403)).toBeNull();
	});
});

describe('detectWafEvent — Cloudflare branch (unchanged)', () => {
	it('returns a cloudflare block for a 403 with cf-mitigated present', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ 'cf-mitigated': 'block' }), '', 403)).toEqual({
			provider: 'cloudflare',
			kind: 'block',
		});
	});

	it('returns null for a 403 with cf-ray only and a benign body', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ 'cf-ray': '8aabcdef1234-AKL' }), 'not found', 403)).toBeNull();
	});

	it('returns a cloudflare challenge for cf-mitigated: challenge', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ 'cf-mitigated': 'challenge' }), '', 403)).toEqual({
			provider: 'cloudflare',
			kind: 'challenge',
		});
	});

	it('returns a cloudflare challenge for a "Just a moment" body with cf-ray', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ 'cf-ray': '8aabcdef1234-AKL' }), 'Just a moment...', 403)).toEqual({
			provider: 'cloudflare',
			kind: 'challenge',
		});
	});
});

describe('detectWafEvent — edge-challenged 401 (#567)', () => {
	it('classifies a 401 carrying Cloudflare edge signals as an edge-artifact (not a real auth gate)', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		// Live repro (api-au.spotto.ai): the scanner receives HTTP 401 from a Cloudflare-fronted
		// origin while a normal client gets HTTP 200 for a fully public page. The 401 is an edge
		// fingerprinting/challenge artifact, not an origin auth requirement.
		expect(
			detectWafEvent(
				headers({ 'cf-ray': '91xyz4567-SYD', server: 'cloudflare' }),
				'<html><head><title>Spotto API Documentation</title></head><body>Public docs</body></html>',
				401,
			),
		).toEqual({ provider: 'cloudflare', kind: 'edge-artifact' });
	});

	it('classifies a 401 with cf-ray only (no block/challenge body) as an edge-artifact', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ 'cf-ray': '91xyz4567-SYD' }), '', 401)).toEqual({
			provider: 'cloudflare',
			kind: 'edge-artifact',
		});
	});

	it('returns null for a genuine 401 with NO edge signals (a real auth-gated origin)', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({}), '', 401)).toBeNull();
	});

	it('still prefers the challenge classification over edge-artifact for a "Just a moment" 401', async () => {
		const { detectWafEvent } = await import('../src/lib/waf-detection');
		expect(detectWafEvent(headers({ 'cf-ray': '91xyz4567-SYD', server: 'cloudflare' }), 'Just a moment...', 401)).toEqual({
			provider: 'cloudflare',
			kind: 'challenge',
		});
	});
});

describe('buildWafFinding — canonical inconclusive WAF info-finding', () => {
	it('builds an info-severity finding with the canonical metadata contract', async () => {
		const { buildWafFinding } = await import('../src/lib/waf-detection');
		const finding = buildWafFinding('http_security', { provider: 'cloudflare', kind: 'block' }, 403, {
			title: 'My Title',
			detail: 'My detail',
		});
		expect(finding.severity).toBe('info');
		expect(finding.metadata?.wafEvent).toBe('cloudflare');
		expect(finding.metadata?.wafKind).toBe('block');
		expect(finding.metadata?.httpStatus).toBe(403);
		expect(finding.metadata?.inconclusive).toBe(true);
		// Issue #638: `inconclusive` and `missingControl` are mutually exclusive. A WAF page
		// means the probe never reached the origin, so absence was never established.
		expect(finding.metadata?.missingControl).toBeUndefined();
	});

	it('adds wafChallenge=provider for a challenge event', async () => {
		const { buildWafFinding } = await import('../src/lib/waf-detection');
		const finding = buildWafFinding('mta_sts', { provider: 'cloudflare', kind: 'challenge' }, 403, {
			title: 'T',
			detail: 'D',
		});
		expect(finding.metadata?.wafChallenge).toBe('cloudflare');
	});

	it('omits wafChallenge for a block event', async () => {
		const { buildWafFinding } = await import('../src/lib/waf-detection');
		const finding = buildWafFinding('http_security', { provider: 'akamai', kind: 'block' }, 403, {
			title: 'T',
			detail: 'D',
		});
		expect(finding.metadata && 'wafChallenge' in finding.metadata).toBe(false);
	});
});
