import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest';
import { setupFetchMock } from '../helpers/dns-mock';

describe('CHAOS: CSC pipeline failure modes', () => {
	let fetchMock: ReturnType<typeof setupFetchMock>;

	beforeEach(() => {
		fetchMock = setupFetchMock();
	});

	afterEach(() => {
		fetchMock.restore();
	});

	it('Given: every enrichment HTTP fetch fails, Then: enrichmentStatus="partial", no crash', async () => {
		// Mock fetch to fail all HTTP HEAD requests while allowing DoH MX lookups to return empty
		globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			// Mock DoH MX lookups to return empty (no MX records found)
			if (url.includes('dns.google') && url.includes('type=MX')) {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: () => Promise.resolve({ Answer: [] }),
					headers: new Headers(),
				});
			}
			// All HTTP HEAD fetches fail (timeout/connection error)
			if (url.startsWith('https://')) {
				return Promise.reject(new Error('HTTP request timeout'));
			}
			// Fallback for any other URL
			return Promise.reject(new Error('Unexpected fetch'));
		});

		const { enrichCandidatesForDefensiveDetection } = await import('../../src/lib/brand-audit-csc-enrichment');
		const result = await enrichCandidatesForDefensiveDetection({
			target: 'ford.com',
			candidates: [
				{ domain: 'a.com', combinedConfidence: 0.9 },
				{ domain: 'b.com', combinedConfidence: 0.8 },
			],
			budgetMs: 5_000,
		});

		// When all HTTP fetches fail, enrichmentStatus should be 'partial'
		expect(result.enrichmentStatus).toBe('partial');
		// Candidates should still be present (unenriched) even though fetches failed
		expect(result.candidates.length).toBe(2);
	});

	it('Given: scan_domain throws on 1 of 3 apexes, Then: apex absent from posture, others present, stage=ready', async () => {
		// Inject an internalCall that throws for 'broken.com' but returns valid scan results for others
		const internalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
			if (args.domain === 'broken.com' && tool === 'scan_domain') {
				throw new Error('upstream timeout');
			}
			// Return valid response structure for other calls
			return {
				structured: {
					domain: args.domain,
					score: 70,
					grade: 'C+',
					categoryScores: {},
					findings: [],
					totalSubdomains: 10,
					subdomains: [],
				},
			};
		};

		const { runDeepScan } = await import('../../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({
			anchorApex: 'ok1.com',
			apexes: ['ok1.com', 'broken.com', 'ok2.com'],
			internalCall,
		});

		// Stage should still reach 'ready' despite one apex failing
		expect(result.postureSnapshot.stage).toBe('ready');
		// The broken apex should be absent from the results
		expect(result.postureSnapshot.apexes.find((a) => a.apex === 'broken.com')).toBeUndefined();
		// The two successful apexes should be present
		expect(result.postureSnapshot.apexes.find((a) => a.apex === 'ok1.com')).toBeDefined();
		expect(result.postureSnapshot.apexes.find((a) => a.apex === 'ok2.com')).toBeDefined();
		// apexesScanned should reflect only the successful scans
		expect(result.postureSnapshot.apexesScanned).toBe(2);
		expect(result.postureSnapshot.apexesTotal).toBe(3);
	});

	it('Given: discover_subdomains throws on apex, Then: inventory entry omitted gracefully, no posture crash', async () => {
		// Inject an internalCall that throws on discover_subdomains but returns valid scan results
		const internalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
			if (tool === 'discover_subdomains') {
				throw new Error('certstream unavailable');
			}
			// scan_domain succeeds
			return {
				structured: {
					domain: args.domain,
					score: 60,
					grade: 'C',
					categoryScores: {},
					findings: [],
					totalSubdomains: 0,
					subdomains: [],
				},
			};
		};

		const { runDeepScan } = await import('../../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({
			anchorApex: 'a.com',
			apexes: ['a.com', 'b.com'],
			internalCall,
		});

		// Pipeline should not crash even with discover_subdomains failing
		// Stage should still be 'ready' or 'running'
		expect(['ready', 'running']).toContain(result.deepScan.stage);
		// Both apexes should be in the total count
		expect(result.deepScan.apexesTotal).toBe(2);
	});
});
