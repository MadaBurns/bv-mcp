// SPDX-License-Identifier: BUSL-1.1

/**
 * R7 — abort (not just abandon) in-flight subrequests on per-check / scan
 * timeout.
 *
 * These specs prove that:
 *  1. The signal-composition helpers compose a caller signal with a fetch
 *     `init.signal` and are pure pass-throughs when no caller signal is given.
 *  2. `checkSsl` / `checkHttpSecurity` thread a caller-supplied abort signal
 *     into their raw `fetch`es — when the caller aborts, the in-flight fetch's
 *     own signal becomes aborted (the OS-level request is cancelled).
 *  3. A NON-aborted call completes normally with an UNCHANGED result (no
 *     behavioural drift on the hot path).
 *
 * Mock isolation: dynamic imports inside each test, `restore()` in afterEach.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('R7 abort-signal helpers', () => {
	it('composeSignal returns init unchanged when no caller signal', async () => {
		const { composeSignal } = await import('../src/lib/abort-signal');
		const init = { method: 'HEAD' as const };
		expect(composeSignal(init, undefined)).toBe(init);
		expect(composeSignal(undefined, undefined)).toBe(undefined);
	});

	it('composeSignal attaches the caller signal when init has none', async () => {
		const { composeSignal } = await import('../src/lib/abort-signal');
		const ctrl = new AbortController();
		const out = composeSignal({ method: 'GET' }, ctrl.signal);
		expect(out?.signal).toBe(ctrl.signal);
		expect((out as RequestInit).method).toBe('GET');
	});

	it('composeSignal aborts the combined signal when EITHER source fires', async () => {
		const { composeSignal } = await import('../src/lib/abort-signal');
		const inner = new AbortController();
		const caller = new AbortController();
		const out = composeSignal({ signal: inner.signal }, caller.signal);
		const combined = out!.signal!;
		expect(combined.aborted).toBe(false);
		caller.abort();
		expect(combined.aborted).toBe(true);

		// And the other direction: the inner (timeout) source also aborts it.
		const inner2 = new AbortController();
		const caller2 = new AbortController();
		const combined2 = composeSignal({ signal: inner2.signal }, caller2.signal)!.signal!;
		inner2.abort();
		expect(combined2.aborted).toBe(true);
	});

	it('withAbortSignal returns the original fetchFn when no caller signal (zero overhead)', async () => {
		const { withAbortSignal } = await import('../src/lib/abort-signal');
		const fn = vi.fn((_input: string, _init?: RequestInit) => Promise.resolve(new Response('ok')));
		expect(withAbortSignal(fn, undefined)).toBe(fn);
	});
});

describe('R7 checkSsl signal threading', () => {
	it('aborts the in-flight HTTPS fetch when the caller signal fires', async () => {
		const { checkSsl } = await import('../src/tools/check-ssl');
		const caller = new AbortController();
		let observedSignal: AbortSignal | undefined;

		// A fetch that never resolves until its signal aborts — proving the
		// caller-abort actually reaches and cancels the in-flight request.
		globalThis.fetch = vi.fn().mockImplementation((_input: unknown, init?: RequestInit) => {
			observedSignal = init?.signal ?? undefined;
			return new Promise((_resolve, reject) => {
				const sig = init?.signal;
				if (sig?.aborted) {
					reject(new DOMException('aborted', 'AbortError'));
					return;
				}
				sig?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
			});
		});

		const resultPromise = checkSsl('example.com', { signal: caller.signal });
		// Let the fetch kick off, then abort as a per-check/scan timeout would.
		await Promise.resolve();
		caller.abort();

		const result = await resultPromise;
		expect(observedSignal).toBeDefined();
		expect(observedSignal!.aborted).toBe(true);
		// Aborted fetch surfaces as a connection/timeout finding, never throws.
		expect(result.category).toBe('ssl');
	});

	it('completes normally and unchanged when NO signal is supplied', async () => {
		const { checkSsl } = await import('../src/tools/check-ssl');
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
				});
			}
			return Promise.resolve({ ok: false, status: 301, headers: new Headers({ location: 'https://example.com/' }) });
		});

		const withoutSignal = await checkSsl('example.com');
		const withInertSignal = await checkSsl('example.com', { signal: new AbortController().signal });

		// Result is byte-for-byte the same whether or not an (un-fired) signal is passed.
		expect(withInertSignal.passed).toBe(withoutSignal.passed);
		expect(withInertSignal.score).toBe(withoutSignal.score);
		expect(withInertSignal.findings.map((f) => f.title)).toEqual(withoutSignal.findings.map((f) => f.title));
		expect(withoutSignal.findings[0].severity).toBe('info');
	});
});

describe('R7 checkHttpSecurity signal threading', () => {
	it('aborts the in-flight HEAD probes when the caller signal fires', async () => {
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		const caller = new AbortController();
		const observed: (AbortSignal | undefined)[] = [];

		globalThis.fetch = vi.fn().mockImplementation((_input: unknown, init?: RequestInit) => {
			observed.push(init?.signal ?? undefined);
			return new Promise((_resolve, reject) => {
				const sig = init?.signal;
				if (sig?.aborted) {
					reject(new DOMException('aborted', 'AbortError'));
					return;
				}
				sig?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
			});
		});

		const resultPromise = checkHttpSecurity('example.com', { signal: caller.signal });
		await Promise.resolve();
		caller.abort();

		const result = await resultPromise;
		expect(observed.length).toBeGreaterThan(0);
		// Every fetch the check launched received a signal that is now aborted.
		for (const s of observed) {
			expect(s).toBeDefined();
			expect(s!.aborted).toBe(true);
		}
		expect(result.category).toBe('http_security');
	});

	it('completes normally and unchanged when NO signal is supplied', async () => {
		const { checkHttpSecurity } = await import('../src/tools/check-http-security');
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			headers: new Headers({
				'content-security-policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
				'x-frame-options': 'DENY',
				'x-content-type-options': 'nosniff',
				'permissions-policy': 'camera=(), microphone=()',
				'referrer-policy': 'strict-origin-when-cross-origin',
				'cross-origin-resource-policy': 'same-origin',
				'cross-origin-opener-policy': 'same-origin',
				'cross-origin-embedder-policy': 'require-corp',
			}),
		});

		const baseline = await checkHttpSecurity('example.com');
		const withInertSignal = await checkHttpSecurity('example.com', { signal: new AbortController().signal });

		expect(withInertSignal.passed).toBe(baseline.passed);
		expect(withInertSignal.score).toBe(baseline.score);
		expect(withInertSignal.findings.map((f) => f.title).sort()).toEqual(baseline.findings.map((f) => f.title).sort());
	});
});
