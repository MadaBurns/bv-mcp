import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';

const { restore } = setupFetchMock();

afterEach(() => restore());

function cnameResponse(name: string, cname: string) {
	return createDohResponse(
		[{ name, type: 5 }],
		[{ name, type: 5, TTL: 300, data: `${cname}.` }],
	);
}

function aResponse(name: string, ips: string[]) {
	return createDohResponse(
		[{ name, type: 1 }],
		ips.map((ip) => ({ name, type: 1, TTL: 300, data: ip })),
	);
}

function emptyResponse(name: string, type: number) {
	return createDohResponse([{ name, type }], []);
}

describe('checkSubdomainTakeover', () => {
	async function run(domain: string) {
		const { checkSubdomainTakeover } = await import('../src/tools/check-subdomain-takeover');
		return checkSubdomainTakeover(domain);
	}

	it('returns info when no CNAME records found on any subdomain', async () => {
		// All CNAME queries return empty
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('type=CNAME') || url.includes('type=5')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}
			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		expect(result.category).toBe('subdomain_takeover');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('No dangling CNAME');
		expect(result.findings[0].metadata?.verificationStatus).toBe('not_exploitable');
	});

	it('detects dangling CNAME to third-party service (high finding)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// staging.example.com has a CNAME pointing to herokuapp.com
				if (url.includes('staging.example.com')) {
					return Promise.resolve(cnameResponse('staging.example.com', 'old-app.herokuapp.com'));
				}
				// All other subdomains return empty
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			// A-record lookup for the CNAME target returns empty (dangling)
			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('old-app.herokuapp.com')) {
					return Promise.resolve(emptyResponse('old-app.herokuapp.com', 1));
				}
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		expect(result.category).toBe('subdomain_takeover');
		const high = result.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high!.title).toContain('Dangling CNAME');
		expect(high!.title).toContain('staging.example.com');
		expect(high!.title).toContain('herokuapp.com');
		expect(high!.detail).toContain('subdomain takeover');
		expect(high!.metadata?.verificationStatus).toBe('potential');
	});

	it('does not flag third-party CNAME that resolves successfully and has no fingerprint', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			// DNS-over-HTTPS queries go to cloudflare-dns.com
			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					if (url.includes('app.example.com')) {
						return Promise.resolve(cnameResponse('app.example.com', 'my-app.herokuapp.com'));
					}
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}

				// A-record lookup resolves successfully
				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('my-app.herokuapp.com')) {
						return Promise.resolve(aResponse('my-app.herokuapp.com', ['54.243.123.45']));
					}
				}

				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// HTTP fingerprint probe — return healthy page (no takeover fingerprint)
			return Promise.resolve(new Response('<html><body>Welcome to my app</body></html>', { status: 200 }));
		});

		const result = await run('example.com');
		// Should only have the "no dangling CNAME" info finding
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
	});

	it('abstains instead of scoring when the CNAME TARGET query throws (#983)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('portal.example.com')) {
					return Promise.resolve(cnameResponse('portal.example.com', 'old-site.azurewebsites.net'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			// A-record lookup throws an error
			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('old-site.azurewebsites.net')) {
					return Promise.reject(new Error('DNS resolution failed'));
				}
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');

		// The probe never reached the origin, so nothing may be scored on it: the finding is
		// an `info` disclosure carrying `inconclusive` + `errorKind`, never a scored `high`
		// and never `missingControl` (#638 law). The title is stable because
		// `parseTakeoverTarget` in brand-audit recovers the FQDN from it.
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		const failed = result.findings.find((f) => f.title.includes('CNAME resolution failed'));
		expect(failed).toBeDefined();
		expect(failed!.severity).toBe('info');
		expect(failed!.metadata?.inconclusive).toBe(true);
		expect(failed!.metadata?.errorKind).toBe('dns_error');
		expect(failed!.metadata?.missingControl).toBeUndefined();
		expect(failed!.detail).toContain('NOT assessed');

		// Other subdomains DID answer, so the clean verdict still stands — narrowed to the
		// subdomains actually swept, with the unassessed one disclosed.
		const clean = result.findings.find((f) => f.title.includes('No dangling CNAME'));
		expect(clean).toBeDefined();
		expect(clean!.metadata?.subdomainsUnmeasured).toContain('portal');

		// The category is not penalized for a measurement that never completed.
		expect(result.checkStatus).toBeUndefined();
		expect(result.score).toBe(100);
		expect(result.passed).toBe(true);
	});

	it('excludes the category when EVERY probe fails, target-resolution throws included (#983)', async () => {
		// The issue's scenario: one subdomain's CNAME answers but its target query throws,
		// while every other sweep query throws too. Before the fix the answered CNAME leg made
		// `answeredCount` non-zero, so the scored `high` stood alone as the whole verdict for a
		// sweep in which nothing was actually assessed.
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('www.example.com')) {
					return Promise.resolve(cnameResponse('www.example.com', 'd123.cloudfront.net'));
				}
				return Promise.reject(new Error('resolver unreachable'));
			}
			return Promise.reject(new Error('resolver unreachable'));
		});

		const result = await run('example.com');

		// `checkStatus: 'error'` is what makes the scoring engine EXCLUDE the category and
		// arms scan_domain's transient retry; `partial: true` keeps the non-answer out of the
		// 5-minute cache.
		expect(result.checkStatus).toBe('error');
		expect(result.partial).toBe(true);
		expect(result.findings.some((f) => f.severity === 'high')).toBe(false);
		const notAssessed = result.findings.find((f) => f.title.includes('not assessed'));
		expect(notAssessed).toBeDefined();
		expect(notAssessed!.metadata?.inconclusive).toBe(true);
		expect(notAssessed!.metadata?.missingControl).toBeUndefined();
		expect(notAssessed!.metadata?.subdomainsUnmeasured).toContain('www');
	});

	it('ignores non-third-party CNAME records (no finding)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// CNAME pointing to own infrastructure, not a third-party takeover service
				if (url.includes('www.example.com')) {
					return Promise.resolve(cnameResponse('www.example.com', 'lb.example.com'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		// Non-third-party CNAME should not trigger any findings
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('No dangling CNAME');
	});

	it('abstains when every outer CNAME query fails (#948)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// All CNAME queries fail
				return Promise.reject(new Error('Network timeout'));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		// Nothing was measured, so the clean "no dangling CNAME" verdict must NOT be
		// issued: the category abstains and is excluded from scoring instead.
		expect(result.category).toBe('subdomain_takeover');
		expect(result.checkStatus).toBe('error');
		expect(result.score).toBe(0);
		expect(result.passed).toBe(false);
		expect(result.partial).toBe(true);
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('not assessed');
		expect(result.findings[0].metadata?.inconclusive).toBe(true);
		expect(result.findings[0].metadata?.errorKind).toBe('dns_error');
		// #638 law: an unmeasured probe may never claim the control is absent.
		expect(result.findings[0].metadata?.missingControl).toBeUndefined();
		expect((result.findings[0].metadata?.subdomainsUnmeasured as string[]).length).toBeGreaterThan(0);
	});

	it('keeps the clean verdict when only SOME subdomain probes fail (#948)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				// One subdomain's probe fails; every other answers empty.
				if (url.includes('www.example.com')) return Promise.reject(new Error('Network timeout'));
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		// A partial failure still emits the verdict — narrowed to what answered.
		expect(result.checkStatus).toBeUndefined();
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].title).toContain('No dangling CNAME');
		expect(result.findings[0].metadata?.subdomainsUnmeasured).toEqual(['www']);
	});

	it('detects multiple dangling CNAMEs across subdomains', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('staging.example.com')) {
					return Promise.resolve(cnameResponse('staging.example.com', 'old.herokuapp.com'));
				}
				if (url.includes('api.example.com')) {
					return Promise.resolve(cnameResponse('api.example.com', 'dead.cloudfront.net'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			// Both A-record lookups return empty
			if (url.includes('type=A') || url.includes('type=1')) {
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 1));
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		const highs = result.findings.filter((f) => f.severity === 'high');
		expect(highs).toHaveLength(2);
		expect(highs.some((f) => f.title.includes('staging.example.com'))).toBe(true);
		expect(highs.some((f) => f.title.includes('api.example.com'))).toBe(true);
	});

	it('detects HTTP fingerprint takeover signal on resolving CNAME (Heroku)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					if (url.includes('app.example.com')) {
						return Promise.resolve(cnameResponse('app.example.com', 'old-app.herokuapp.com'));
					}
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}

				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('old-app.herokuapp.com')) {
						return Promise.resolve(aResponse('old-app.herokuapp.com', ['75.2.60.5']));
					}
				}

				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// HTTP probe returns Heroku deprovisioned fingerprint
			return Promise.resolve(
				new Response('<html><head><title>no-such-app</title></head><body>No such app</body></html>', { status: 404 }),
			);
		});

		const result = await run('example.com');
		const finding = result.findings.find((f) => f.title.includes('Heroku'));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
		expect(finding!.title).toContain('possible takeover signal');
		expect(finding!.detail).toContain('deprovisioned');
		expect(finding!.detail).toContain('not proof of exploitability');
		expect(finding!.metadata?.verificationStatus).toBe('potential');
		expect(finding!.metadata?.evidenceStrength).toBe('provider_deprovisioned_fingerprint');
		expect(finding!.metadata?.proofRequired).toBe('authorized_proof_of_control');
	});

	it('detects HTTP fingerprint takeover signal on resolving CNAME (GitHub Pages)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					if (url.includes('docs.example.com')) {
						return Promise.resolve(cnameResponse('docs.example.com', 'example.github.io'));
					}
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}

				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('example.github.io')) {
						return Promise.resolve(aResponse('example.github.io', ['185.199.108.153']));
					}
				}

				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// HTTP probe returns GitHub Pages 404 fingerprint
			return Promise.resolve(
				new Response("<html><body>There isn't a GitHub Pages site here.</body></html>", { status: 404 }),
			);
		});

		const result = await run('example.com');
		const finding = result.findings.find((f) => f.title.includes('GitHub Pages'));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
		expect(finding!.title).toContain('possible takeover signal');
		expect(finding!.metadata?.verificationStatus).toBe('potential');
	});

	it('silently skips HTTP fingerprint probe on timeout/error', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					if (url.includes('blog.example.com')) {
						return Promise.resolve(cnameResponse('blog.example.com', 'example.ghost.io'));
					}
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}

				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('example.ghost.io')) {
						return Promise.resolve(aResponse('example.ghost.io', ['178.128.1.2']));
					}
				}

				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// HTTP probe fails with network error
			return Promise.reject(new Error('Connection refused'));
		});

		const result = await run('example.com');
		// Should not produce a critical finding since the probe errored out
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('No dangling CNAME');
	});

	it('detects A/AAAA-only host pointing to unclaimed Cloudways infrastructure (#973)', async () => {
		// `app` has NO CNAME (empty CNAME answer) but its A record resolves to shared
		// Cloudways infrastructure that serves the provider's verbatim "unmapped
		// domain" page — the reproduction from issue #973.
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}
				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('app.example.com')) {
						return Promise.resolve(aResponse('app.example.com', ['45.77.51.111']));
					}
				}
				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// HTTP fingerprint probe — Cloudways' verbatim unmapped-domain block page.
			return Promise.resolve(
				new Response(
					'The request was unfortunately blocked by our system because the requested domain is not authorized on Cloudways server i.e. The domain has been successfully pointed to a Cloudways server but it is not mapped to an application.',
					{ status: 403 },
				),
			);
		});

		const result = await run('example.com');
		const finding = result.findings.find((f) => f.title.includes('Cloudways'));
		expect(finding).toBeDefined();
		expect(finding!.severity).toBe('high');
		expect(finding!.title).toContain('possible takeover signal');
		expect(finding!.detail).toContain('no CNAME');
		expect(finding!.detail).toContain('not proof of exploitability');
		expect(finding!.metadata?.verificationStatus).toBe('potential');
		expect(finding!.metadata?.vector).toBe('a_record');
	});

	it('does not flag an A/AAAA-only host serving a normal page (no fingerprint)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}
				if (url.includes('type=A') || url.includes('type=1')) {
					if (url.includes('app.example.com')) {
						return Promise.resolve(aResponse('app.example.com', ['203.0.113.10']));
					}
				}
				return Promise.resolve(emptyResponse('unknown', 1));
			}

			// A normally-serving origin — no takeover fingerprint anywhere in the body.
			return Promise.resolve(new Response('<html><body>Welcome to our site</body></html>', { status: 200 }));
		});

		const result = await run('example.com');
		expect(result.findings).toHaveLength(1);
		expect(result.findings[0].severity).toBe('info');
		expect(result.findings[0].title).toContain('No dangling CNAME');
	});

	describe('Cloudways iframe-marker live miss (#973 reopen, 2026-09-15)', () => {
		// Production reproduction: toolbelt/intranet.ltmcguinness.co.nz resolve via
		// A record only (no CNAME) to shared Cloudways infrastructure. HTTPS fails
		// outright (TLS/connect failure, no response); HTTP answers 403 with a
		// body whose ENTIRE content is an <iframe> pointing at Cloudways'
		// S3-hosted maintenance page — the "not mapped to an application" wording
		// the 3.81.0 fix looked for lives only inside that iframe document, never
		// fetched. The exact 343-byte body from the issue.
		const iframeOnlyBody =
			'<!DOCTYPE html>\n<html>\n    <iframe src="https://cloudways-static-content.s3.us-east-1.amazonaws.com/error_page/maintenance-domain-mapping.html" frameborder="0" style="overflow:hidden;overflow-x:hidden;overflow-y:hidden;height:100%;width:100%;position:absolute;top:0px;left:0px;right:0px;bottom:0px" height="100%" width="100%"></iframe>\n</html>';

		function dohMock(getFetch: () => (input: string | URL | Request) => Promise<Response>) {
			return vi.fn().mockImplementation((input: string | URL | Request) => {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

				if (url.includes('cloudflare-dns.com')) {
					if (url.includes('type=CNAME') || url.includes('type=5')) {
						const nameMatch = url.match(/name=([^&]+)/);
						const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
						return Promise.resolve(emptyResponse(name, 5));
					}
					if (url.includes('type=A') || url.includes('type=1')) {
						if (url.includes('app.example.com')) {
							return Promise.resolve(aResponse('app.example.com', ['45.77.51.111']));
						}
					}
					return Promise.resolve(emptyResponse('unknown', 1));
				}

				return getFetch()(url);
			});
		}

		it('matches the iframe marker on a direct HTTPS 403 (no fallback needed)', async () => {
			globalThis.fetch = dohMock(() => (_url) => Promise.resolve(new Response(iframeOnlyBody, { status: 403 })));

			const result = await run('example.com');
			const finding = result.findings.find((f) => f.title.includes('Cloudways'));
			expect(finding).toBeDefined();
			expect(finding!.severity).toBe('high');
			expect(finding!.metadata?.verificationStatus).toBe('potential');
			expect(finding!.metadata?.vector).toBe('a_record');
		});

		it('falls back to plain HTTP when HTTPS fails outright, and matches the iframe marker', async () => {
			globalThis.fetch = dohMock(() => (url) => {
				// HTTPS (including the robots.txt probe it gates behind) fails with
				// no response at all — the live reproduction's exact wording.
				if (url.startsWith('https://')) {
					return Promise.reject(new Error('connect ECONNREFUSED'));
				}
				// The HTTP fallback reaches the origin and gets the iframe-only 403 body.
				return Promise.resolve(new Response(iframeOnlyBody, { status: 403 }));
			});

			const result = await run('example.com');
			const finding = result.findings.find((f) => f.title.includes('Cloudways'));
			expect(finding).toBeDefined();
			expect(finding!.severity).toBe('high');
			expect(finding!.detail).toContain('no CNAME');
			expect(finding!.metadata?.verificationStatus).toBe('potential');
			expect(finding!.metadata?.vector).toBe('a_record');
		});

		it('stays silent when both HTTPS and the HTTP fallback fail', async () => {
			globalThis.fetch = dohMock(() => (_url) => Promise.reject(new Error('connect ECONNREFUSED')));

			const result = await run('example.com');
			expect(result.findings).toHaveLength(1);
			expect(result.findings[0].severity).toBe('info');
			expect(result.findings[0].title).toContain('No dangling CNAME');
		});

		it('control: a normal page with an unrelated iframe produces no finding', async () => {
			globalThis.fetch = dohMock(
				() => (_url) =>
					Promise.resolve(
						new Response('<!DOCTYPE html><html><body><iframe src="https://maps.example.com/embed"></iframe></body></html>', {
							status: 200,
						}),
					),
			);

			const result = await run('example.com');
			expect(result.findings).toHaveLength(1);
			expect(result.findings[0].severity).toBe('info');
			expect(result.findings[0].title).toContain('No dangling CNAME');
		});
	});

	it('fetches each host robots.txt once across a multi-host A-vector sweep (HTTPS + HTTP fallback share one decision)', async () => {
		// Regression: every in-flight robots.txt cache entry used to reserve ~2 MiB of the
		// 4 MiB cache, so a sibling host's pending entry evicted the first one and the
		// HTTP fallback leg re-fetched robots.txt for the same host.
		const hosts = ['www.example.com', 'app.example.com', 'api.example.com'];
		const robotsFetches = new Map<string, number>();
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('cloudflare-dns.com')) {
				if (url.includes('type=CNAME') || url.includes('type=5')) {
					const nameMatch = url.match(/name=([^&]+)/);
					const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
					return Promise.resolve(emptyResponse(name, 5));
				}
				if (url.includes('type=A') || url.includes('type=1')) {
					const host = hosts.find((h) => url.includes(`name=${h}`));
					if (host) return Promise.resolve(aResponse(host, ['203.0.113.10']));
				}
				return Promise.resolve(emptyResponse('unknown', 1));
			}

			const parsed = new URL(url);
			if (parsed.pathname === '/robots.txt') {
				robotsFetches.set(parsed.hostname, (robotsFetches.get(parsed.hostname) ?? 0) + 1);
			}
			// HTTPS fails outright so every host also takes the HTTP fallback leg.
			if (url.startsWith('https://')) return Promise.reject(new Error('connect ECONNREFUSED'));
			return Promise.resolve(new Response('<html><body>Welcome</body></html>', { status: 200 }));
		});

		const result = await run('example.com');
		expect(result.findings[0].title).toContain('No dangling CNAME');
		expect(robotsFetches).toEqual(new Map(hosts.map((h) => [h, 1])));
	});

	it('detects dangling CNAME to newly added service (Vercel)', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;

			if (url.includes('type=CNAME') || url.includes('type=5')) {
				if (url.includes('staging.example.com')) {
					return Promise.resolve(cnameResponse('staging.example.com', 'cname.vercel-dns.com'));
				}
				const nameMatch = url.match(/name=([^&]+)/);
				const name = nameMatch ? decodeURIComponent(nameMatch[1]) : 'unknown';
				return Promise.resolve(emptyResponse(name, 5));
			}

			if (url.includes('type=A') || url.includes('type=1')) {
				if (url.includes('cname.vercel-dns.com')) {
					return Promise.resolve(emptyResponse('cname.vercel-dns.com', 1));
				}
			}

			return Promise.resolve(emptyResponse('unknown', 1));
		});

		const result = await run('example.com');
		const high = result.findings.find((f) => f.severity === 'high');
		expect(high).toBeDefined();
		expect(high!.title).toContain('Dangling CNAME');
		expect(high!.title).toContain('vercel-dns.com');
	});
});
