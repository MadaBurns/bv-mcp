import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, mockFetchError } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

describe('checkSsl', () => {
	async function run(domain = 'example.com') {
		const { checkSsl } = await import('../src/tools/check-ssl');
		return checkSsl(domain);
	}

	it('should return info finding when HTTPS connection succeeds with HSTS', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({
						'strict-transport-security': 'max-age=31536000; includeSubDomains',
						'expect-ct': 'max-age=86400, enforce',
					}),
				});
			}
			// HTTP redirect check
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		expect(result.category).toBe('ssl');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/properly configured/i);
		expect(result.passed).toBe(true);
	});

	it('should return critical finding when HTTPS redirects to HTTP', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: false,
					status: 301,
					headers: new Headers({ location: 'http://example.com/' }),
				});
			}
			return Promise.reject(new Error('HTTP blocked'));
		});
		const result = await run();
		const finding = result.findings.find((f) => /redirects to HTTP/i.test(f.title));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('critical');
	});

	// A Worker-vantage network failure is an unmeasured abstention, never a scored SSL
	// security defect (#638 law): we did not measure the origin's TLS, we failed to reach
	// it. `checkStatus` is what excludes the category from scoring; the finding itself must
	// also read as `info` + `inconclusive`, not a `high`/`critical` deficiency.
	it('should return an info, inconclusive finding (not scored) on connection timeout', async () => {
		globalThis.fetch = vi.fn().mockRejectedValue(new Error('The operation was aborted due to timeout'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/timeout/i);
		expect(result.findings[0].metadata).toMatchObject({ inconclusive: true, errorKind: 'timeout' });
		expect(result.checkStatus).toBe('timeout');
	});

	it('should return an info, inconclusive finding (not scored) on connection failure', async () => {
		mockFetchError(new Error('ECONNREFUSED'));
		const result = await run();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toMatch(/not assessed/i);
		expect(result.findings[0].metadata).toMatchObject({ inconclusive: true, errorKind: 'transport_error' });
		expect(result.checkStatus).toBe('error');
	});

	it('should return medium finding when HSTS header is missing', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers(),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No HSTS header');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should return low finding when HSTS max-age is too short', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=3600; includeSubDomains' }),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'HSTS max-age too short');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should return low finding when HSTS missing includeSubDomains', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.startsWith('https://')) {
				return Promise.resolve({
					url: 'https://example.com/',
					ok: true,
					status: 200,
					headers: new Headers({ 'strict-transport-security': 'max-age=31536000' }),
				});
			}
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'HSTS missing includeSubDomains');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('low');
	});

	it('should not produce redirect finding when HTTP redirects to HTTPS', async () => {
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
			return Promise.resolve({
				ok: false,
				status: 301,
				headers: new Headers({ location: 'https://example.com/' }),
			});
		});
		const result = await run();
		const redirectFinding = result.findings.find((f) => f.title.includes('redirect'));
		expect(redirectFinding).toBeUndefined();
	});

	it('should return medium finding when no HTTP to HTTPS redirect', async () => {
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
			// HTTP returns 200 instead of redirect
			return Promise.resolve({
				ok: true,
				status: 200,
				headers: new Headers(),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No HTTP to HTTPS redirect');
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('medium');
	});

	it('should NOT emit a redirect finding when the plain-HTTP probe returns a no-content 204 (issue #806)', async () => {
		// A 204 carried no page and measured nothing about redirect posture (observed live:
		// google.com's real http:// answer is a 301, yet a scan emitted "status 204").
		// The sub-probe is skipped, matching the silent-skip posture for a failed HTTP probe.
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
			// Anomalous no-content answer on the http:// probe
			return Promise.resolve({
				ok: true,
				status: 204,
				headers: new Headers(),
			});
		});
		const result = await run();
		const finding = result.findings.find((f) => f.title === 'No HTTP to HTTPS redirect');
		expect(finding).toBeUndefined();
	});

	describe('issue #972 — an unfingerprinted UA/TLS-based block completes the check with false findings', () => {
		it.each([[401], [403], [429], [202]])(
			'should NOT emit "No HSTS header" when the https:// probe returns a blocked %d with no headers',
			async (status) => {
				globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
					const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
					if (url.startsWith('https://')) {
						return Promise.resolve({
							url: 'https://example.com/',
							ok: status >= 200 && status < 300,
							status,
							headers: new Headers(),
						});
					}
					return Promise.resolve({
						ok: false,
						status: 301,
						headers: new Headers({ location: 'https://example.com/' }),
					});
				});
				const result = await run();
				expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
				expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
				expect(result.checkStatus).toBe('error');
				expect(result.score).toBe(0);
				expect(result.passed).toBe(false);
			},
		);

		it('should NOT emit "No HTTP to HTTPS redirect" when the http:// probe is answered with a 202 interstitial (the exact reported shape)', async () => {
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
				// The origin does a real 301 for honest clients, but the scanner's probe is
				// answered with a 202 interstitial (issue #972's reported shape).
				return Promise.resolve({ ok: true, status: 202, headers: new Headers() });
			});
			const result = await run();
			expect(result.findings.some((f) => f.title === 'No HTTP to HTTPS redirect')).toBe(false);
			expect(result.checkStatus).toBeUndefined();
		});

		it('headers that ARE present on a blocked 403 must not be reported missing', async () => {
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.startsWith('https://')) {
					return Promise.resolve({
						url: 'https://example.com/',
						ok: false,
						status: 403,
						headers: new Headers({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }),
					});
				}
				return Promise.resolve({
					ok: false,
					status: 301,
					headers: new Headers({ location: 'https://example.com/' }),
				});
			});
			const result = await run();
			expect(result.findings.some((f) => f.title === 'No HSTS header')).toBe(false);
			expect(result.checkStatus).toBe('error');
		});
	});

	it.each([[204], [205]])(
		'should NOT emit an HSTS finding when the https:// probe returns a no-content %d (issue #806 follow-up)',
		async (status) => {
			// A terminal 204/205 on the https:// leg satisfies neither the redirect nor the
			// error branch, so before the guard its EMPTY header set flowed into
			// getHttpsFindings() and produced a confident scored "No HSTS header" medium
			// finding from a response that delivered no page. Same family as the http:// leg
			// fixed in #819: withhold the verdict, exclude the category.
			globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				if (url.startsWith('https://')) {
					// Anomalous no-content answer on the https:// probe (robots.txt included —
					// an empty robots answer fails open, matching this file's other mocks).
					return Promise.resolve({
						url: 'https://example.com/',
						ok: true,
						status,
						headers: new Headers(),
					});
				}
				return Promise.resolve({
					ok: false,
					status: 301,
					headers: new Headers({ location: 'https://example.com/' }),
				});
			});
			const result = await run();
			expect(result.findings.find((f) => f.title === 'No HSTS header')).toBeUndefined();
			expect(result.findings.some((f) => f.metadata?.missingControl === true)).toBe(false);
			const marker = result.findings.find((f) => f.metadata?.inconclusive === true);
			expect(marker).toBeDefined();
			expect(marker!.metadata?.errorKind).toBe('no_content');
			expect(result.checkStatus).toBe('error');
		},
	);

	describe('GET fallback budget (#1088)', () => {
		// These call the package's checkSSL directly (not the src/tools/check-ssl wrapper,
		// which never exposes a caller-controlled `timeout`) so a short budget can prove the
		// HEAD+GET pair shares ONE timeout instead of the GET re-arming a fresh copy of it.
		it('a HEAD 403 followed by a GET that never resolves on its own keeps total elapsed within ~1.5x the budget', async () => {
			const { checkSSL } = await import('@blackveil/dns-checks');
			const timeoutMs = 300;
			const fetchFn = vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
				if (init?.method === 'GET') {
					// Settles only when its OWN AbortSignal fires — the old bug re-armed this with
					// a fresh `timeoutMs`, doubling the pair's real elapsed time.
					return new Promise<Response>((_resolve, reject) => {
						init.signal!.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')));
					});
				}
				return Promise.resolve(new Response(null, { status: 403 }));
			});
			const startedAt = Date.now();
			const result = await checkSSL('example.com', fetchFn, { timeout: timeoutMs });
			const elapsed = Date.now() - startedAt;

			expect(result.checkStatus).toBe('error');
			expect(result.findings.some((f) => f.title === 'HTTPS endpoint not assessable (status 403)')).toBe(true);
			expect(elapsed).toBeLessThan(timeoutMs * 1.5);
		});

		it('skips the GET fallback entirely when the HEAD already spent nearly the whole budget', async () => {
			const { checkSSL } = await import('@blackveil/dns-checks');
			const timeoutMs = 300;
			let getAttempted = false;
			const fetchFn = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
				if (init?.method === 'GET') {
					getAttempted = true;
					return new Response(null, { status: 200, headers: { 'strict-transport-security': 'max-age=31536000' } });
				}
				// Leaves well under the 250ms floor (GET_FALLBACK_MIN_BUDGET_MS) of the budget.
				await new Promise((resolve) => setTimeout(resolve, timeoutMs - 100));
				return new Response(null, { status: 403 });
			});
			const startedAt = Date.now();
			const result = await checkSSL('example.com', fetchFn, { timeout: timeoutMs });
			const elapsed = Date.now() - startedAt;

			expect(getAttempted).toBe(false);
			expect(result.checkStatus).toBe('error');
			expect(result.findings.some((f) => f.title === 'HTTPS endpoint not assessable (status 403)')).toBe(true);
			expect(elapsed).toBeLessThan(timeoutMs * 1.5);
		});
	});

	describe('Redirect-chain deadline (#1093)', () => {
		// HEAD + GET fallback + the HTTPS redirect chain that follows either of them now share the
		// SAME ONE `timeoutMs` budget (measured from the HEAD start), not a fresh copy per chain.
		it('a HEAD 403 → GET 301 → hop that hangs still resolves to the existing unresolved/timeout outcome within ~1.5x the budget', async () => {
			const { checkSSL } = await import('@blackveil/dns-checks');
			// A larger budget, with the HEAD and GET each deliberately spending over a third of it,
			// so the old per-hop-fresh-timeout bug (a chain-local `AbortSignal.timeout(timeoutMs)`
			// re-armed the FULL budget at chain-entry, ignoring what HEAD+GET already spent) pushes
			// total elapsed past 1.5x — this is what makes the test a real regression guard rather
			// than one that happens to pass either way.
			const timeoutMs = 1000;
			const fetchFn = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
				if (init?.method === 'GET') {
					await new Promise((resolve) => setTimeout(resolve, 350));
					return new Response(null, { status: 301, headers: new Headers({ location: 'https://hop.example.com/' }) });
				}
				if (url === 'https://example.com') {
					await new Promise((resolve) => setTimeout(resolve, 350));
					return new Response(null, { status: 403 });
				}
				// The redirect-chain hop settles only when its own AbortSignal fires — proves the
				// chain shares the HEAD+GET pair's remaining budget rather than a fresh timeoutMs.
				return new Promise<Response>((_resolve, reject) => {
					init!.signal!.addEventListener('abort', () => reject(new DOMException('The operation was aborted.', 'AbortError')));
				});
			});
			const startedAt = Date.now();
			const result = await checkSSL('example.com', fetchFn, { timeout: timeoutMs });
			const elapsed = Date.now() - startedAt;

			expect(elapsed).toBeLessThan(timeoutMs * 1.5);
			expect(result.checkStatus).toBe('timeout');
			expect(result.findings.some((f) => f.title === 'HTTPS redirect chain not assessable')).toBe(true);
		});

		it('issues no redirect-chain hop when the HEAD already spent nearly the whole budget', async () => {
			const { checkSSL } = await import('@blackveil/dns-checks');
			const timeoutMs = 300;
			let hopAttempted = false;
			const fetchFn = vi.fn().mockImplementation(async (url: string) => {
				if (url === 'https://example.com') {
					// Leaves well under the 250ms floor (GET_FALLBACK_MIN_BUDGET_MS) of the budget.
					await new Promise((resolve) => setTimeout(resolve, timeoutMs - 100));
					return new Response(null, { status: 301, headers: new Headers({ location: 'https://hop.example.com/' }) });
				}
				hopAttempted = true;
				return new Response(null, { status: 200, headers: new Headers({ 'strict-transport-security': 'max-age=31536000' }) });
			});
			const startedAt = Date.now();
			const result = await checkSSL('example.com', fetchFn, { timeout: timeoutMs });
			const elapsed = Date.now() - startedAt;

			expect(hopAttempted).toBe(false);
			expect(fetchFn).toHaveBeenCalledTimes(1);
			expect(result.checkStatus).toBe('timeout');
			expect(elapsed).toBeLessThan(timeoutMs * 1.5);
		});
	});
});
