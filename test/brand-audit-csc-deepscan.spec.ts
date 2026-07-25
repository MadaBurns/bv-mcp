// SPDX-License-Identifier: BUSL-1.1

import { describe, it, expect } from 'vitest';

describe('runDeepScan', () => {
	it('runs scan_domain + discover_subdomains for each apex (parallel cap 5)', async () => {
		const calls: Array<{ tool: string; domain: string }> = [];

		const mockInternalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
			calls.push({ tool, domain: args.domain });
			if (tool === 'scan_domain') {
				return {
					content: [{ type: 'text', text: 'scan ok' }],
					structured: {
						domain: args.domain,
						score: 70,
						grade: 'C+',
						categoryScores: {},
						findings: [],
					},
				};
			}
			if (tool === 'discover_subdomains') {
				return {
					content: [{ type: 'text', text: 'discovered' }],
					structured: {
						domain: args.domain,
						totalSubdomains: 42,
						subdomains: [],
					},
				};
			}
			return {};
		};

		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({
			anchorApex: 'ford.com',
			apexes: ['ford.com', 'ford.com.au', 'fordcorp.com'],
			internalCall: mockInternalCall,
		});

		expect(calls.filter((c) => c.tool === 'scan_domain').length).toBe(3);
		expect(calls.filter((c) => c.tool === 'discover_subdomains').length).toBe(3);

		expect(result.postureSnapshot.stage).toBe('ready');
		expect(result.postureSnapshot.apexes.length).toBe(3);
		expect(result.deepScan.stage).toBe('ready');
		expect(result.deepScan.subdomainInventoryByApex['ford.com'].total).toBe(42);
		expect(result.deepScan.subdomainInventoryByApex['ford.com'].source).toBe('certificate_transparency');
	});

	it('caps apexes at 25 ranked by passed order; later apexes are dropped', async () => {
		const calls: Array<{ tool: string; domain: string }> = [];
		const mockInternalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
			calls.push({ tool, domain: args.domain });
			return {
				content: [],
				structured: { domain: args.domain, score: 50, grade: 'D', categoryScores: {}, findings: [], totalSubdomains: 0, subdomains: [] },
			};
		};

		const apexes = Array.from({ length: 40 }, (_, i) => `apex${i}.com`);
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'apex0.com', apexes, internalCall: mockInternalCall });

		expect(result.postureSnapshot.apexesTotal).toBe(25);
		expect(result.postureSnapshot.apexes.length).toBe(25);
	});

	it('treats per-apex failures as partial without aborting the whole scan', async () => {
		const mockInternalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
			if (args.domain === 'broken.com' && tool === 'scan_domain') {
				throw new Error('scan failed');
			}
			return {
				content: [],
				structured: {
					domain: args.domain,
					score: 75,
					grade: 'C+',
					categoryScores: {},
					findings: [],
					totalSubdomains: 10,
					subdomains: [],
				},
			};
		};

		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({
			anchorApex: 'a.com',
			apexes: ['a.com', 'broken.com', 'b.com'],
			internalCall: mockInternalCall,
		});

		expect(result.postureSnapshot.apexes.find((a) => a.apex === 'broken.com')).toBeUndefined();
		expect(result.postureSnapshot.apexes.length).toBe(2);
		expect(result.postureSnapshot.apexesScanned).toBe(2);
		expect(result.postureSnapshot.apexesTotal).toBe(3);
		expect(result.postureSnapshot.stage).toBe('ready');
	});

	it('excludes an unresolvable apex (measured:false + a placeholder score/grade pair) from the grade distribution and median', async () => {
		const mockInternalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
			if (tool === 'discover_subdomains') {
				return { content: [], structured: { domain: args.domain, totalSubdomains: 0, subdomains: [] } };
			}
			// nxdomain.com mirrors the wire shape buildNonResolvingResult emitted BEFORE 3.35.0:
			// zero checks ran (`measured: false`) but the degraded score/grade placeholders are
			// still populated. The producer now emits nulls; this keeps the hostile pair pinned,
			// since `measured` — not nullness — is the load-bearing exclusion signal here.
			if (args.domain === 'nxdomain.com') {
				return {
					content: [],
					structured: { domain: args.domain, score: 0, grade: 'N/A', measured: false, categoryScores: {}, findings: [] },
				};
			}
			return {
				content: [],
				structured: { domain: args.domain, score: 90, grade: 'A', measured: true, categoryScores: {}, findings: [] },
			};
		};

		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({
			anchorApex: 'graded.com',
			apexes: ['graded.com', 'nxdomain.com'],
			internalCall: mockInternalCall,
		});

		// Only the one genuinely-graded apex may appear in the customer-visible rollup.
		expect(result.postureSnapshot.distribution).toEqual({ A: 1 });
		// The placeholder letter sorts after 'F' lexically, so counting it drags the median to
		// the worst bucket.
		expect(result.postureSnapshot.medianGrade).toBe('A');

		const ungraded = result.postureSnapshot.apexes.find((a) => a.apex === 'nxdomain.com');
		expect(ungraded).toBeDefined();
		expect(ungraded?.grade).toBeNull();
		expect(ungraded?.score).toBeNull();
	});

	it('excludes a measured:false apex even when it carries a real-looking letter (degenerate zero-check A+)', async () => {
		const mockInternalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
			if (tool === 'discover_subdomains') {
				return { content: [], structured: { domain: args.domain, totalSubdomains: 0, subdomains: [] } };
			}
			// computeScanScore([]) returns overall 100 / grade 'A+' for a scan that ran ZERO
			// checks — a real-looking letter with no measurement behind it. `measured` is the
			// only signal that separates it from a genuine A+.
			if (args.domain === 'nochecks.com') {
				return {
					content: [],
					structured: { domain: args.domain, score: 100, grade: 'A+', measured: false, categoryScores: {}, findings: [] },
				};
			}
			return {
				content: [],
				structured: { domain: args.domain, score: 78, grade: 'B', measured: true, categoryScores: {}, findings: [] },
			};
		};

		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({
			anchorApex: 'graded.com',
			apexes: ['graded.com', 'nochecks.com'],
			internalCall: mockInternalCall,
		});

		expect(result.postureSnapshot.distribution).toEqual({ B: 1 });

		const ungraded = result.postureSnapshot.apexes.find((a) => a.apex === 'nochecks.com');
		expect(ungraded).toBeDefined();
		expect(ungraded?.grade).toBeNull();
		expect(ungraded?.score).toBeNull();
	});
});
