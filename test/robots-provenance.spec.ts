// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #745 — the robots gate's fail-open branch must leave a record.
 *
 * Covers the collector itself and, end to end, the two checks the issue names:
 * `check_ssl` and `check_http_security`. The assertions that matter are the
 * ones proving two scans of the SAME domain are distinguishable when one read
 * robots.txt and the other did not.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';
import { createRobotsProvenance } from '../src/lib/robots-provenance';
import type { CheckResult } from '../src/lib/scoring';

const { restore } = setupFetchMock();

afterEach(() => {
	restore();
	vi.resetModules();
});

/** Minimal, valid `CheckResult` to stamp. */
function bareResult(): CheckResult {
	return { category: 'ssl', passed: true, score: 100, findings: [] };
}

describe('createRobotsProvenance', () => {
	it('returns the result untouched when no request was gated', () => {
		const provenance = createRobotsProvenance('example.com');
		const result = bareResult();
		expect(provenance.stamp(result)).toBe(result);
		expect(provenance.summarize()).toBeUndefined();
	});

	it('stamps metadata.robotsResolution without touching findings or score', () => {
		const provenance = createRobotsProvenance('example.com');
		provenance.onResolution({ host: 'example.com', path: '/', resolution: 'unreachable', failOpen: true, status: 502 });
		const before = bareResult();
		const after = provenance.stamp(before);
		expect(after.metadata?.robotsResolution).toEqual({
			host: 'example.com',
			resolution: 'unreachable',
			failOpen: true,
			status: 502,
		});
		expect(after.score).toBe(before.score);
		expect(after.passed).toBe(before.passed);
		expect(after.findings).toEqual(before.findings);
	});

	it('preserves metadata a caller already attached', () => {
		const provenance = createRobotsProvenance('example.com');
		provenance.onResolution({ host: 'example.com', path: '/', resolution: 'allowed', failOpen: false, status: 200 });
		// Annotated: `stamp` is generic in its argument, so an inline literal would
		// narrow `metadata` to exactly `{ certificate: ... }` and the returned type
		// would not admit `robotsResolution`.
		const withMetadata: CheckResult = { ...bareResult(), metadata: { certificate: { issuer: 'X' } } };
		const stamped = provenance.stamp(withMetadata);
		expect(stamped.metadata?.certificate).toEqual({ issuer: 'X' });
		expect(stamped.metadata?.robotsResolution).toMatchObject({ resolution: 'allowed' });
	});

	it('summarizes the domain under test, not a redirect target, and lists the others', () => {
		const provenance = createRobotsProvenance('example.com');
		provenance.onResolution({ host: 'cdn.example.net', path: '/', resolution: 'allowed', failOpen: false, status: 200 });
		provenance.onResolution({ host: 'example.com', path: '/', resolution: 'timeout', failOpen: true, errorName: 'TimeoutError' });
		expect(provenance.summarize()).toEqual({
			host: 'example.com',
			resolution: 'timeout',
			failOpen: true,
			errorName: 'TimeoutError',
			otherHosts: ['cdn.example.net'],
		});
	});

	it('keeps the first record per host — later replays of a memoized decision add nothing', () => {
		const provenance = createRobotsProvenance('example.com');
		provenance.onResolution({ host: 'example.com', path: '/a', resolution: 'allowed', failOpen: false, status: 200 });
		provenance.onResolution({ host: 'example.com', path: '/b', resolution: 'allowed', failOpen: false, status: 200 });
		expect(provenance.summarize()?.otherHosts).toBeUndefined();
	});
});

/** Route every fetch: robots.txt handled by `robots`, everything else a bare 200. */
function mockFetch(robots: () => Response | Promise<Response>): void {
	globalThis.fetch = (async (url: string | URL | Request) => {
		const href = typeof url === 'string' ? url : url instanceof URL ? url.href : url.url;
		if (href.endsWith('/robots.txt')) return robots();
		return new Response(null, { status: 200, headers: { 'strict-transport-security': 'max-age=31536000' } });
	}) as typeof fetch;
}

describe('check_ssl — robots resolution provenance', () => {
	async function run(domain = 'example.com') {
		const { checkSsl } = await import('../src/tools/check-ssl');
		return checkSsl(domain);
	}

	it('records the fail-open branch when robots.txt is unreachable (the crt.sh 502 case)', async () => {
		mockFetch(() => new Response('', { status: 502 }));
		const result = await run('crt.sh');
		expect(result.metadata?.robotsResolution).toMatchObject({
			host: 'crt.sh',
			resolution: 'unreachable',
			failOpen: true,
			status: 502,
		});
		// Policy unchanged: the check still ran and still produced findings.
		expect(result.findings.length).toBeGreaterThan(0);
	});

	it('records the allowed branch when robots.txt was actually read', async () => {
		mockFetch(() => new Response('User-agent: *\nDisallow: /private\n', { status: 200 }));
		const result = await run();
		expect(result.metadata?.robotsResolution).toMatchObject({
			resolution: 'allowed',
			failOpen: false,
			scope: 'blanket',
		});
	});

	it('makes a scored scan distinguishable from one that merely guessed', async () => {
		// The whole point of the issue: same domain, same code, two runs — one read
		// the policy, one did not. Before #745 both looked identical in the record.
		mockFetch(() => new Response('User-agent: *\nDisallow: /private\n', { status: 200 }));
		const read = await run();
		vi.resetModules();
		mockFetch(() => new Response('', { status: 502 }));
		const guessed = await run();
		expect(read.metadata?.robotsResolution).not.toEqual(guessed.metadata?.robotsResolution);
		expect((read.metadata?.robotsResolution as { failOpen: boolean }).failOpen).toBe(false);
		expect((guessed.metadata?.robotsResolution as { failOpen: boolean }).failOpen).toBe(true);
	});

	it('records the disallowed branch on the abstention path', async () => {
		mockFetch(() => new Response('User-agent: *\nDisallow: /\n', { status: 200 }));
		const result = await run();
		expect(result.metadata?.robotsResolution).toMatchObject({ resolution: 'disallowed', failOpen: false, scope: 'blanket' });
	});
});

describe('check_http_security — robots resolution provenance', () => {
	async function run(domain = 'example.com') {
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		return checkHttpSecurity(domain);
	}

	it('records the fail-open branch when the robots.txt fetch throws', async () => {
		mockFetch(() => {
			throw new TypeError('network error');
		});
		const result = await run();
		expect(result.metadata?.robotsResolution).toMatchObject({ resolution: 'unreachable', failOpen: true, errorName: 'TypeError' });
	});

	it('records `no_policy` for a 404 robots.txt — a measurement, not a guess', async () => {
		mockFetch(() => new Response('', { status: 404 }));
		const result = await run('nopolicy.example');
		expect(result.metadata?.robotsResolution).toMatchObject({ resolution: 'no_policy', failOpen: false, status: 404 });
	});

	it('records the disallowed branch alongside the existing exclusion', async () => {
		mockFetch(() => new Response('User-agent: *\nDisallow: /\n', { status: 200 }));
		const result = await run('blocked.example');
		expect(result.checkStatus).toBe('error');
		expect(result.metadata?.robotsResolution).toMatchObject({ resolution: 'disallowed', failOpen: false });
	});
});
