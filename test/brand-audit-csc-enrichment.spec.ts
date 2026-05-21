import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { setupFetchMock } from './helpers/dns-mock';

describe('enrichCandidatesForDefensiveDetection', () => {
	let fetchMock: ReturnType<typeof setupFetchMock>;

	beforeEach(() => {
		fetchMock = setupFetchMock();
	});

	afterEach(() => {
		fetchMock.restore();
	});

	it('stamps defensive=true with reason=redirect-to-target on a candidate that 301s to target', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('dns.google') && url.includes('forrd.com') && url.includes('type=MX')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ Answer: [] }) });
			}
			if (url === 'https://forrd.com/') {
				return Promise.resolve({
					ok: false,
					status: 301,
					headers: new Headers({ Location: 'https://ford.com/' }),
				});
			}
			return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) });
		});

		const { enrichCandidatesForDefensiveDetection } = await import('../src/lib/brand-audit-csc-enrichment');
		const result = await enrichCandidatesForDefensiveDetection({
			target: 'ford.com',
			candidates: [{ domain: 'forrd.com', combinedConfidence: 0.9 }],
			budgetMs: 5_000,
		});

		expect(result.enrichmentStatus).toBe('ready');
		const forrd = result.candidates[0];
		expect(forrd.defensive).toBe(true);
		expect(forrd.defensiveReason).toBe('redirect-to-target');
	});

	it('returns enrichmentStatus=partial when some fetches fail', async () => {
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('dns.google') && url.includes('forrd.com') && url.includes('type=MX')) {
				return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ Answer: [] }) });
			}
			if (url === 'https://forrd.com/') {
				return Promise.resolve({
					ok: false,
					status: 301,
					headers: new Headers({ Location: 'https://ford.com/' }),
				});
			}
			// timeout.com fetches all throw
			return Promise.reject(new Error('timeout'));
		});

		const { enrichCandidatesForDefensiveDetection } = await import('../src/lib/brand-audit-csc-enrichment');
		const result = await enrichCandidatesForDefensiveDetection({
			target: 'ford.com',
			candidates: [
				{ domain: 'forrd.com', combinedConfidence: 0.9 },
				{ domain: 'timeout.com', combinedConfidence: 0.7 },
			],
			budgetMs: 5_000,
		});

		expect(result.enrichmentStatus).toBe('partial');
	});

	it('caps candidates at 50 by combinedConfidence', async () => {
		// Return fast empty responses for all fetches so the test is deterministic
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: () => Promise.resolve({ Answer: [] }),
			headers: new Headers(),
		});

		const candidates = Array.from({ length: 100 }, (_, i) => ({
			domain: `c${i}.com`,
			combinedConfidence: i / 100,
		}));
		const { enrichCandidatesForDefensiveDetection } = await import('../src/lib/brand-audit-csc-enrichment');
		const result = await enrichCandidatesForDefensiveDetection({
			target: 'ford.com',
			candidates,
			budgetMs: 5_000,
		});
		expect(result.candidates.length).toBe(50);
		// Sorted descending by combinedConfidence — c99 (99/100) is first
		expect(result.candidates[0].domain).toBe('c99.com');
	});

	it('respects budgetMs and returns partial enrichment if budget exceeded', async () => {
		// Simulate slow fetches — delay longer than the 1ms budget
		globalThis.fetch = vi.fn().mockImplementation(
			(_input: string | URL | Request, init?: RequestInit) =>
				new Promise<Response>((resolve, reject) => {
					const timer = setTimeout(() => {
						resolve({
							ok: true,
							status: 200,
							json: () => Promise.resolve({ Answer: [] }),
							headers: new Headers(),
						} as unknown as Response);
					}, 100);
					// Respect abort signal
					init?.signal?.addEventListener('abort', () => {
						clearTimeout(timer);
						reject(new DOMException('Aborted', 'AbortError'));
					});
				}),
		);

		const candidates = Array.from({ length: 50 }, (_, i) => ({
			domain: `c${i}.com`,
			combinedConfidence: 0.9,
		}));
		const { enrichCandidatesForDefensiveDetection } = await import('../src/lib/brand-audit-csc-enrichment');
		const result = await enrichCandidatesForDefensiveDetection({
			target: 'ford.com',
			candidates,
			budgetMs: 1,
		});
		expect(result.enrichmentStatus).toBe('partial');
	});
});
