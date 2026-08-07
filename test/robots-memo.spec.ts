// SPDX-License-Identifier: BUSL-1.1

/**
 * Issue #641 — per-scan robots.txt fetch memo.
 *
 * `checkSSL` runs three STRICTLY SEQUENTIAL fetches (robots.txt 3s → https 4s →
 * http redirect probe 4s = 11s worst case) inside an 8s per-check budget, and
 * `src/tools/check-ssl.ts` built a fresh `withRobotsGate` closure per call — so
 * `ssl` and `http_security`, which probe the SAME host, each paid their own
 * blocking `https://<domain>/robots.txt` fetch. Sharing one memo per scan removes
 * one of them.
 *
 * These tests pin the three things that make that safe:
 *   1. the memo is actually HIT (one robots.txt fetch across both checks, vs two
 *      without it),
 *   2. it CANNOT leak across domains (keyed by absolute URL — two hosts in one
 *      scan each get their own fetch and never see each other's rules), and
 *   3. findings/severities/scores are byte-identical with and without it, on both
 *      the happy path and every fail-soft path (fetch throws, 404, disallow).
 *
 * Each case uses a UNIQUE domain: `check-http-security.ts` keeps module-scope,
 * isolate-lifetime gates for the no-memo (direct tool call) path, and those caches
 * survive across tests in a file. Unique hosts keep every case's fetch count honest.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

/** Full security-header set, so `http_security` lands on its clean "well configured" finding. */
const SECURITY_HEADERS: Record<string, string> = {
	'content-security-policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
	'x-frame-options': 'DENY',
	'x-content-type-options': 'nosniff',
	'permissions-policy': 'camera=(), microphone=()',
	'referrer-policy': 'strict-origin-when-cross-origin',
	'cross-origin-resource-policy': 'same-origin',
	'cross-origin-opener-policy': 'same-origin',
	'cross-origin-embedder-policy': 'require-corp',
	'strict-transport-security': 'max-age=31536000; includeSubDomains',
};

function urlOf(input: string | URL | Request): string {
	return typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
}

/** Per-host robots.txt behaviour. `'throw'` models a stalled/aborted robots fetch. */
type RobotsBehaviour = string | 'throw' | { status: number };

/**
 * Install a fetch mock that serves a healthy HTTPS site (and an HTTP→HTTPS
 * redirect) for every host, with per-host robots.txt behaviour. Returns the
 * recorded URL list so a test can count robots.txt fetches exactly.
 */
function installMock(robotsByHost: Record<string, RobotsBehaviour>): string[] {
	const calls: string[] = [];
	globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
		const url = urlOf(input);
		calls.push(url);
		const parsed = new URL(url);
		if (parsed.pathname === '/robots.txt') {
			const behaviour = robotsByHost[parsed.hostname];
			if (behaviour === 'throw') throw new Error('The operation was aborted due to timeout');
			if (behaviour && typeof behaviour === 'object') return new Response(null, { status: behaviour.status });
			if (typeof behaviour === 'string') return new Response(behaviour, { status: 200 });
			return new Response(null, { status: 404 });
		}
		if (parsed.protocol === 'http:') {
			return new Response(null, { status: 301, headers: { location: `https://${parsed.hostname}/` } });
		}
		return new Response(null, { status: 200, headers: SECURITY_HEADERS });
	});
	return calls;
}

const robotsFetches = (calls: string[], host?: string): string[] =>
	calls.filter((u) => u.endsWith('/robots.txt') && (!host || new URL(u).hostname === host));

const ALLOW_ALL = 'User-agent: *\nDisallow:\n';
const DISALLOW_ALL = 'User-agent: *\nDisallow: /\n';

// ---------------------------------------------------------------------------
// Unit: the memo wrapper itself
// ---------------------------------------------------------------------------

describe('withRobotsFetchMemo', () => {
	it('returns the original function object when no memo is supplied (pure pass-through)', async () => {
		const { withRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const inner = vi.fn(async (_url: string, _init?: RequestInit) => new Response('x'));
		expect(withRobotsFetchMemo(inner)).toBe(inner);
	});

	it('fetches a given robots.txt once and replays an independently readable body', async () => {
		const { withRobotsFetchMemo, createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const inner = vi.fn(async (_url: string, _init?: RequestInit) => new Response(ALLOW_ALL, { status: 200 }));
		const memoized = withRobotsFetchMemo(inner, createRobotsFetchMemo());

		const first = await memoized('https://a.example/robots.txt');
		const second = await memoized('https://a.example/robots.txt');

		expect(inner).toHaveBeenCalledTimes(1);
		expect(await first.text()).toBe(ALLOW_ALL);
		// The replay is a fresh Response — the first caller consuming the body must
		// not leave the second with a locked/disturbed stream.
		expect(await second.text()).toBe(ALLOW_ALL);
	});

	it('never memoizes non-robots URLs', async () => {
		const { withRobotsFetchMemo, createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const inner = vi.fn(async (_url: string, _init?: RequestInit) => new Response(null, { status: 200 }));
		const memoized = withRobotsFetchMemo(inner, createRobotsFetchMemo());

		await memoized('https://a.example/');
		await memoized('https://a.example/');
		expect(inner).toHaveBeenCalledTimes(2);
	});

	it('keys on the absolute URL, so two hosts never see each other robots.txt', async () => {
		const { withRobotsFetchMemo, createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const inner = vi.fn(async (url: string, _init?: RequestInit) => new Response(`body-for-${new URL(url).hostname}`, { status: 200 }));
		const memoized = withRobotsFetchMemo(inner, createRobotsFetchMemo());

		const a = await memoized('https://a.example/robots.txt');
		const b = await memoized('https://b.example/robots.txt');

		expect(inner).toHaveBeenCalledTimes(2);
		expect(await a.text()).toBe('body-for-a.example');
		expect(await b.text()).toBe('body-for-b.example');
	});

	it('replays a non-OK status without a body (matching what the gate consumes)', async () => {
		const { withRobotsFetchMemo, createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const inner = vi.fn(async (_url: string, _init?: RequestInit) => new Response('not found', { status: 404 }));
		const memoized = withRobotsFetchMemo(inner, createRobotsFetchMemo());

		const first = await memoized('https://a.example/robots.txt');
		const second = await memoized('https://a.example/robots.txt');

		expect(inner).toHaveBeenCalledTimes(1);
		expect(first.status).toBe(404);
		expect(second.status).toBe(404);
		expect(second.ok).toBe(false);
	});

	it('memoizes a FAILED fetch as a failure (one attempt, both callers throw)', async () => {
		// Deliberate: the gate turns any throw into `null` — "no applicable group",
		// its fail-OPEN default — so replaying the failure can only ever reproduce
		// fail-open. It can never manufacture a disallow. Retrying instead would
		// re-pay the full 3s robots timeout per check, which is the bug.
		const { withRobotsFetchMemo, createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const inner = vi.fn(async (_url: string, _init?: RequestInit): Promise<Response> => {
			throw new Error('The operation was aborted due to timeout');
		});
		const memoized = withRobotsFetchMemo(inner, createRobotsFetchMemo());

		await expect(memoized('https://a.example/robots.txt')).rejects.toThrow(/aborted due to timeout/);
		await expect(memoized('https://a.example/robots.txt')).rejects.toThrow(/aborted due to timeout/);
		expect(inner).toHaveBeenCalledTimes(1);
	});

	it('deduplicates concurrent callers onto one in-flight fetch', async () => {
		const { withRobotsFetchMemo, createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		let resolveInner: (() => void) | undefined;
		const gate = new Promise<void>((resolve) => (resolveInner = resolve));
		const inner = vi.fn(async (_url: string, _init?: RequestInit) => {
			await gate;
			return new Response(ALLOW_ALL, { status: 200 });
		});
		const memoized = withRobotsFetchMemo(inner, createRobotsFetchMemo());

		const both = Promise.all([memoized('https://a.example/robots.txt'), memoized('https://a.example/robots.txt')]);
		resolveInner!();
		const [first, second] = await both;

		expect(inner).toHaveBeenCalledTimes(1);
		expect(await first.text()).toBe(ALLOW_ALL);
		expect(await second.text()).toBe(ALLOW_ALL);
	});
});

// ---------------------------------------------------------------------------
// Integration: ssl + http_security sharing one scan's memo
// ---------------------------------------------------------------------------

describe('ssl + http_security sharing one per-scan robots memo', () => {
	async function runBoth(domain: string, robotsMemo?: import('../src/lib/robots-memo').RobotsFetchMemo) {
		const { checkSsl } = await import('../src/tools/check-ssl');
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		return Promise.all([checkSsl(domain, { robotsMemo }), checkHttpSecurity(domain, { robotsMemo })]);
	}

	it('BEFORE (no memo): the same host robots.txt is fetched twice, once per check', async () => {
		const domain = 'baseline-nomemo.example.com';
		const calls = installMock({ [domain]: ALLOW_ALL });

		await runBoth(domain);

		expect(robotsFetches(calls, domain)).toHaveLength(2);
	});

	it('AFTER (shared memo): the same host robots.txt is fetched exactly once', async () => {
		const domain = 'shared-memo.example.com';
		const calls = installMock({ [domain]: ALLOW_ALL });
		const { createRobotsFetchMemo } = await import('../src/lib/robots-memo');

		await runBoth(domain, createRobotsFetchMemo());

		expect(robotsFetches(calls, domain)).toHaveLength(1);
	});

	it('two hosts in one scan each get their own fetch, and never cross-contaminate', async () => {
		// `allowed` permits everything; `blocked` disallows everything. If the memo
		// leaked, the second host resolved would inherit the first's rules and either
		// wrongly exclude a healthy domain or wrongly scan an opted-out one.
		const allowed = 'memo-allowed.example.com';
		const blocked = 'memo-blocked.example.com';
		const calls = installMock({ [allowed]: ALLOW_ALL, [blocked]: DISALLOW_ALL });
		const { createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const memo = createRobotsFetchMemo();

		const [allowedSsl] = await runBoth(allowed, memo);
		const [blockedSsl] = await runBoth(blocked, memo);

		expect(robotsFetches(calls, allowed)).toHaveLength(1);
		expect(robotsFetches(calls, blocked)).toHaveLength(1);

		// The allowing host was scanned normally...
		expect(allowedSsl.checkStatus).toBeUndefined();
		expect(allowedSsl.findings.some((f) => /robots\.txt/i.test(f.title))).toBe(false);
		// ...and the disallowing host was excluded, exactly as without a memo.
		expect(blockedSsl.checkStatus).toBe('error');
		expect(blockedSsl.findings.some((f) => /robots\.txt/i.test(f.title))).toBe(true);
	});

	it('the reverse order also stays isolated (blocked host resolved first)', async () => {
		const allowed = 'reverse-allowed.example.com';
		const blocked = 'reverse-blocked.example.com';
		installMock({ [allowed]: ALLOW_ALL, [blocked]: DISALLOW_ALL });
		const { createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const memo = createRobotsFetchMemo();

		const [blockedSsl] = await runBoth(blocked, memo);
		const [allowedSsl] = await runBoth(allowed, memo);

		expect(blockedSsl.checkStatus).toBe('error');
		expect(allowedSsl.checkStatus).toBeUndefined();
	});
});

// ---------------------------------------------------------------------------
// The load-bearing constraint: same observable result, only faster
// ---------------------------------------------------------------------------

describe('memo produces identical findings and scores', () => {
	/** Comparable projection of a CheckResult — the whole scored surface. */
	function shape(result: { score: number; passed: boolean; checkStatus?: string; findings: { title: string; severity: string; detail: string }[] }) {
		return {
			score: result.score,
			passed: result.passed,
			checkStatus: result.checkStatus,
			findings: result.findings.map((f) => ({ title: f.title, severity: f.severity, detail: f.detail })),
		};
	}

	/**
	 * Run ssl + http_security against `domain` twice — once with no memo, once with
	 * a fresh memo — and assert both checks' full scored shape is identical. The
	 * same domain is used for both passes so finding text (which embeds the domain)
	 * is directly comparable.
	 */
	async function assertIdentical(domain: string, robots: Record<string, RobotsBehaviour>) {
		const { checkSsl } = await import('../src/tools/check-ssl');
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const { createRobotsFetchMemo } = await import('../src/lib/robots-memo');

		installMock(robots);
		const withoutSsl = await checkSsl(domain);
		const withoutHttp = await checkHttpSecurity(domain);

		installMock(robots);
		const memo = createRobotsFetchMemo();
		const withSsl = await checkSsl(domain, { robotsMemo: memo });
		const withHttp = await checkHttpSecurity(domain, { robotsMemo: memo });

		expect(shape(withSsl)).toEqual(shape(withoutSsl));
		expect(shape(withHttp)).toEqual(shape(withoutHttp));
	}

	it('happy path — robots.txt allows everything', async () => {
		const domain = 'identical-allow.example.com';
		await assertIdentical(domain, { [domain]: ALLOW_ALL });
	});

	it('fail-soft — robots.txt 404 (no rules; fail open)', async () => {
		const domain = 'identical-404.example.com';
		await assertIdentical(domain, { [domain]: { status: 404 } });
	});

	it('fail-soft — robots.txt fetch throws / times out (fail open)', async () => {
		const domain = 'identical-throw.example.com';
		await assertIdentical(domain, { [domain]: 'throw' });
	});

	it('fail-soft — robots.txt 500 (fail open, per the gate own non-OK handling)', async () => {
		const domain = 'identical-500.example.com';
		await assertIdentical(domain, { [domain]: { status: 500 } });
	});

	it('robots.txt disallow still excludes the ssl category', async () => {
		const domain = 'identical-disallow.example.com';
		await assertIdentical(domain, { [domain]: DISALLOW_ALL });
	});
});

// ---------------------------------------------------------------------------
// Wiring: scan_domain actually creates and threads the memo
// ---------------------------------------------------------------------------

describe('scan_domain threads one robots memo per scan', () => {
	it('fetches the apex robots.txt exactly once across a full scan', async () => {
		// Without the wiring this is 2 (ssl + http_security each pay their own), which
		// is the whole point of the fix — so this assertion is what proves the memo is
		// reaching the dispatch table rather than sitting unused in scan-domain.ts.
		const domain = 'scanwiring.example.com';
		const calls: string[] = [];
		const { createDohResponse, dnssecResponse } = await import('./helpers/dns-mock');
		globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
			const url = urlOf(input);
			calls.push(url);
			if (url.includes('cloudflare-dns.com')) {
				// The apex must RESOLVE or scanDomain short-circuits before any check runs.
				if (url.includes('type=A') || url.includes('type=1&')) return dnssecResponse(domain, true);
				return createDohResponse([], []);
			}
			const parsed = new URL(url);
			if (parsed.pathname === '/robots.txt') return new Response(ALLOW_ALL, { status: 200 });
			if (parsed.protocol === 'http:') return new Response(null, { status: 301, headers: { location: `https://${parsed.hostname}/` } });
			return new Response(null, { status: 200, headers: SECURITY_HEADERS });
		});

		const { IN_MEMORY_CACHE } = await import('../src/lib/cache');
		IN_MEMORY_CACHE.clear();
		const { scanDomain } = await import('../src/tools/scan-domain');
		await scanDomain(domain);

		expect(robotsFetches(calls, domain)).toHaveLength(1);
	});
});

// ---------------------------------------------------------------------------
// Fail-soft under a shared memo
// ---------------------------------------------------------------------------

describe('fail-soft robots behaviour under a shared memo', () => {
	it('a throwing robots.txt is attempted ONCE per scan and both checks still run', async () => {
		const domain = 'failsoft-shared.example.com';
		const calls = installMock({ [domain]: 'throw' });
		const { checkSsl } = await import('../src/tools/check-ssl');
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const { createRobotsFetchMemo } = await import('../src/lib/robots-memo');
		const memo = createRobotsFetchMemo();

		const [ssl, http] = await Promise.all([checkSsl(domain, { robotsMemo: memo }), checkHttpSecurity(domain, { robotsMemo: memo })]);

		// One attempt total — a stalled robots.txt must not be re-paid per check.
		expect(robotsFetches(calls, domain)).toHaveLength(1);
		// Fail-OPEN: both checks proceeded to the site itself and produced real results.
		expect(ssl.checkStatus).toBeUndefined();
		expect(ssl.findings.some((f) => /robots\.txt/i.test(f.title))).toBe(false);
		expect(http.findings.some((f) => /robots\.txt/i.test(f.title))).toBe(false);
		expect(calls.some((u) => u.startsWith(`https://${domain}`) && !u.endsWith('/robots.txt'))).toBe(true);
	});
});
