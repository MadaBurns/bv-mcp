// SPDX-License-Identifier: BUSL-1.1

/**
 * `runDeepScan` is driven by an injected `internalCall` that, in production, IS
 * `handleToolsCall` (see the brand-audit queue-consumer closure in
 * `src/index.ts`). Every envelope in these tests is therefore built with the
 * SAME production emitters the real path uses — `buildToolResult` wrapping
 * `buildStructuredScanResult` / a real `SubdomainDiscoveryResult` / a real
 * `CheckResult` — rather than a hand-written literal.
 *
 * That is deliberate. Earlier revisions of this spec injected
 * `{ content: [], structured: {...} }`, a shape `handleToolsCall` has never
 * emitted (the machine-readable channel is `structuredContent`). The orchestrator
 * read `.structured`, got `undefined` for every apex, and reported
 * `apexesScanned: 0` — while these tests passed. Build envelopes from the real
 * builders so a rename or reshape on the emitting side fails here first.
 */

import { describe, it, expect } from 'vitest';
import { checkSubdomainTakeover } from '@blackveil/dns-checks';
import { buildToolResult, formatCheckResult } from '../src/handlers/tool-formatters';
import { buildStructuredScanResult, formatScanReport } from '../src/tools/scan/format-report';
import { formatSubdomainDiscovery } from '../src/tools/discover-subdomains';
import type { SubdomainDiscoveryResult } from '../src/tools/discover-subdomains';
import type { ScanDomainResult } from '../src/tools/scan-domain';

/**
 * A minimal-but-real `ScanDomainResult`, the input `buildStructuredScanResult` takes
 * in production.
 *
 * `checks` is non-empty by default and that is load-bearing, not decoration:
 * `buildStructuredScanResult` derives the wire field `measured` from
 * `checks.length > 0` (`isMeasured`, `src/lib/ungraded-display.ts`), and the deep-scan
 * orchestrator abstains (null grade + null score) for any apex whose scan reports
 * `measured: false`. A `checks: []` fixture is therefore an UNMEASURED scan, never a
 * clean one — pass `measured: false` to build that case deliberately.
 */
function makeScanResult(domain: string, overall: number, grade: string, opts?: { measured?: boolean }): ScanDomainResult {
	const checks: ScanDomainResult['checks'] =
		opts?.measured === false
			? []
			: [{ category: 'spf', score: 80, passed: true, findings: [] as ScanDomainResult['checks'][number]['findings'] }];
	return {
		domain,
		score: {
			overall,
			grade,
			categoryScores: { spf: 80, dmarc: 70, subdomain_takeover: 100 } as ScanDomainResult['score']['categoryScores'],
			findings: [],
			summary: `${domain} scored ${overall}/100. Grade: ${grade}`,
		},
		checks,
		maturity: { stage: 2, label: 'Developing', description: 'partial coverage', nextStep: 'Enforce DMARC.' },
		context: { profile: 'mail_enabled', signals: [], weights: {} as never, detectedProvider: null },
		cached: false,
		timestamp: '2026-06-02T00:00:00.000Z',
		scoringNote: null,
		adaptiveWeightDeltas: null,
		interactionEffects: [],
	};
}

/** A real `SubdomainDiscoveryResult` — the exact object `discover_subdomains` passes to `buildToolResult`. */
function makeDiscoveryResult(domain: string, names: string[]): SubdomainDiscoveryResult {
	return {
		domain,
		totalSubdomains: names.length,
		totalCertificates: names.length,
		subdomains: names.map((subdomain) => ({
			subdomain,
			firstSeen: '2026-01-01T00:00:00Z',
			lastSeen: '2026-06-01T00:00:00Z',
			issuer: "Let's Encrypt",
			certCount: 1,
			isWildcard: false,
			isExpired: false,
		})),
		wildcardCerts: 0,
		expiredCerts: 0,
		uniqueIssuers: ["Let's Encrypt"],
		issues: [],
	};
}

/**
 * Run the REAL takeover check with an injected resolver so the findings (and
 * therefore their title/detail text, which is where the dangling FQDN lives)
 * are genuinely package-produced, not hand-written.
 *
 * `www.<domain>` dangles at a Heroku target that has no A record.
 */
async function makeTakeoverResult(domain: string, dangling: boolean) {
	const target = `${domain.split('.')[0]}-brand.herokuapp.com`;
	const queryDNS = async (name: string, recordType: string): Promise<string[]> => {
		if (dangling && recordType === 'CNAME' && name === `www.${domain}`) return [target];
		return [];
	};
	return checkSubdomainTakeover(domain, queryDNS, { fetchFn: async () => new Response('', { status: 200 }) });
}

/**
 * Build the production MCP envelope for a tool call. Mirrors the tail of
 * `handleToolsCall`: `buildToolResult(<text>, <structured payload>, format)`.
 */
async function makeInternalCall(options?: { dangling?: boolean; failOn?: { tool: string; domain: string } }) {
	const calls: Array<{ tool: string; domain: string }> = [];
	const envelopes: Array<Record<string, unknown>> = [];

	const internalCall = async (tool: string, args: { domain: string }): Promise<unknown> => {
		calls.push({ tool, domain: args.domain });
		if (options?.failOn && options.failOn.tool === tool && options.failOn.domain === args.domain) {
			throw new Error(`${tool} failed`);
		}
		let envelope: Record<string, unknown>;
		if (tool === 'scan_domain') {
			const scan = makeScanResult(args.domain, 72, 'C+');
			envelope = buildToolResult(formatScanReport(scan), buildStructuredScanResult(scan), 'full');
		} else if (tool === 'discover_subdomains') {
			const discovery = makeDiscoveryResult(args.domain, [`www.${args.domain}`, `api.${args.domain}`]);
			envelope = buildToolResult(formatSubdomainDiscovery(discovery), discovery, 'full');
		} else if (tool === 'check_subdomain_takeover') {
			const result = await makeTakeoverResult(args.domain, options?.dangling ?? false);
			envelope = buildToolResult(formatCheckResult(result), result, 'full');
		} else {
			envelope = { content: [] };
		}
		envelopes.push(envelope);
		return envelope;
	};

	return { internalCall, calls, envelopes };
}

describe('runDeepScan — production internal-call envelope', () => {
	it('reads structuredContent, the only machine-readable field handleToolsCall emits', async () => {
		const { internalCall, envelopes } = await makeInternalCall();
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'ford.com', apexes: ['ford.com'], internalCall });

		// Pin the contract on the emitting side: the envelope carries
		// `structuredContent` and has no `structured` key at all.
		for (const envelope of envelopes) {
			expect(envelope).toHaveProperty('structuredContent');
			expect(envelope).not.toHaveProperty('structured');
		}

		// ...and on the consuming side: a real envelope actually produces posture.
		expect(result.postureSnapshot.apexesScanned).toBe(1);
		// NOTE: the display grade is recomputed from the score by `buildStructuredScanResult`
		// (NIST 6-band `displayGradeFor`), so 72 → 'C' regardless of the fixture's letter.
		expect(result.postureSnapshot.apexes[0].grade).toBe('C');
		expect(result.postureSnapshot.apexes[0].score).toBe(72);
	});

	it('regression: an envelope keyed `structured` yields nothing (the shape that silently shipped)', async () => {
		// The pre-fix injection. Kept as an explicit negative so the class of bug
		// — "consumer reads a field the producer never sets" — stays visible: a
		// non-production envelope must NOT look like a successful scan.
		const legacyShapedCall = async (_tool: string, args: { domain: string }): Promise<unknown> => ({
			content: [],
			structured: { domain: args.domain, score: 80, grade: 'B+', categoryScores: {}, findings: [] },
		});
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'ford.com', apexes: ['ford.com'], internalCall: legacyShapedCall });

		expect(result.postureSnapshot.apexesScanned).toBe(0);
		expect(result.postureSnapshot.apexes).toHaveLength(0);
	});

	it('runs scan_domain + discover_subdomains + check_subdomain_takeover for each apex', async () => {
		const { internalCall, calls } = await makeInternalCall();
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({
			anchorApex: 'ford.com',
			apexes: ['ford.com', 'ford.com.au', 'fordcorp.com'],
			internalCall,
		});

		expect(calls.filter((c) => c.tool === 'scan_domain').length).toBe(3);
		expect(calls.filter((c) => c.tool === 'discover_subdomains').length).toBe(3);
		expect(calls.filter((c) => c.tool === 'check_subdomain_takeover').length).toBe(3);

		expect(result.postureSnapshot.stage).toBe('ready');
		expect(result.postureSnapshot.apexes.length).toBe(3);
		expect(result.postureSnapshot.medianGrade).toBe('C');
		expect(result.postureSnapshot.distribution).toEqual({ C: 3 });

		expect(result.deepScan.stage).toBe('ready');
		const inventory = result.deepScan.subdomainInventoryByApex['ford.com'];
		expect(inventory.total).toBe(2);
		expect(inventory.source).toBe('certificate_transparency');
		expect(inventory.sample).toEqual(['www.ford.com', 'api.ford.com']);
		expect(inventory.partial).toBe(false);
	});

	it('extracts dangling DNS from real check_subdomain_takeover findings', async () => {
		const { internalCall } = await makeInternalCall({ dangling: true });
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'ford.com', apexes: ['ford.com'], internalCall });

		expect(result.deepScan.danglingDnsTotal).toBe(1);
		const [finding] = result.deepScan.danglingDns;
		expect(finding.subdomain).toBe('www.ford.com');
		expect(finding.apex).toBe('ford.com');
		expect(finding.recordType).toBe('CNAME');
		expect(finding.target).toBe('ford-brand.herokuapp.com');
		expect(finding.severity).toBe('high');
		expect(result.deepScan.subdomainInventoryByApex['ford.com'].dangling).toBe(1);
	});

	it('emits no dangling entries for the all-clear (info) takeover finding', async () => {
		const { internalCall } = await makeInternalCall({ dangling: false });
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'ford.com', apexes: ['ford.com'], internalCall });

		expect(result.deepScan.danglingDns).toEqual([]);
		expect(result.deepScan.danglingDnsTotal).toBe(0);
	});

	it('caps apexes at 25; later apexes are dropped', async () => {
		const { internalCall } = await makeInternalCall();
		const apexes = Array.from({ length: 40 }, (_, i) => `apex${i}.com`);
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'apex0.com', apexes, internalCall });

		expect(result.postureSnapshot.apexesTotal).toBe(25);
		expect(result.postureSnapshot.apexes.length).toBe(25);
	});

	it('treats a scan_domain failure as partial without aborting sibling apexes', async () => {
		const { internalCall } = await makeInternalCall({ failOn: { tool: 'scan_domain', domain: 'broken.com' } });
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({
			anchorApex: 'a.com',
			apexes: ['a.com', 'broken.com', 'b.com'],
			internalCall,
		});

		expect(result.postureSnapshot.apexes.find((a) => a.apex === 'broken.com')).toBeUndefined();
		expect(result.postureSnapshot.apexesScanned).toBe(2);
		expect(result.postureSnapshot.apexesTotal).toBe(3);
		expect(result.postureSnapshot.stage).toBe('ready');
	});

	it('keeps posture when discover_subdomains fails, dropping only that inventory entry', async () => {
		const { internalCall } = await makeInternalCall({ failOn: { tool: 'discover_subdomains', domain: 'a.com' } });
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'a.com', apexes: ['a.com', 'b.com'], internalCall });

		expect(result.postureSnapshot.apexesScanned).toBe(2);
		expect(result.deepScan.subdomainInventoryByApex['a.com']).toBeUndefined();
		expect(result.deepScan.subdomainInventoryByApex['b.com']).toBeDefined();
	});

	it('treats an isError envelope as a failed call rather than a zero-value result', async () => {
		const erroringCall = async (tool: string): Promise<unknown> =>
			tool === 'scan_domain' ? { content: [{ type: 'text', text: 'Error: Invalid domain' }], isError: true } : { content: [] };
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'a.com', apexes: ['a.com'], internalCall: erroringCall });

		expect(result.postureSnapshot.apexesScanned).toBe(0);
		expect(result.postureSnapshot.apexesTotal).toBe(1);
	});

	// ---------------------------------------------------------------------------
	// Ungraded-abstention coverage (nullable ScanScore branch). These pin that the
	// orchestrator excludes an UNMEASURED apex from every customer-visible rollup,
	// no matter what score/grade letters that apex's payload happens to carry.
	// ---------------------------------------------------------------------------

	/** Production envelope for one apex, with `measured` under test control. */
	async function postureCall(postures: Record<string, { overall: number; grade: string; measured: boolean }>) {
		return async (tool: string, args: { domain: string }): Promise<unknown> => {
			if (tool === 'scan_domain') {
				const p = postures[args.domain];
				const scan = makeScanResult(args.domain, p.overall, p.grade, { measured: p.measured });
				return buildToolResult(formatScanReport(scan), buildStructuredScanResult(scan), 'full');
			}
			if (tool === 'discover_subdomains') {
				const discovery = makeDiscoveryResult(args.domain, []);
				return buildToolResult(formatSubdomainDiscovery(discovery), discovery, 'full');
			}
			return { content: [] };
		};
	}

	it('excludes an unresolvable apex (measured:false carrying a placeholder score/grade pair) from the grade distribution and median', async () => {
		// nxdomain.com mirrors the wire shape the non-resolving path emitted BEFORE the
		// nullable-grade work: zero checks ran (`measured: false`) but the degraded
		// score/grade placeholders are still populated. `measured` — not nullness — is
		// the load-bearing exclusion signal, so the hostile pair stays pinned here.
		const internalCall = await postureCall({
			'graded.com': { overall: 90, grade: 'A', measured: true },
			'nxdomain.com': { overall: 0, grade: 'F', measured: false },
		});
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'graded.com', apexes: ['graded.com', 'nxdomain.com'], internalCall });

		// Only the one genuinely-graded apex may appear in the customer-visible rollup.
		expect(result.postureSnapshot.distribution).toEqual({ A: 1 });
		expect(result.postureSnapshot.medianGrade).toBe('A');

		const ungraded = result.postureSnapshot.apexes.find((a) => a.apex === 'nxdomain.com');
		expect(ungraded).toBeDefined();
		expect(ungraded?.grade).toBeNull();
		expect(ungraded?.score).toBeNull();
	});

	it('excludes a measured:false apex even when it carries a real-looking letter (degenerate zero-check A+)', async () => {
		// `computeScanScore([])` returns overall 100 / grade 'A+' for a scan that ran ZERO
		// checks — a real-looking letter with no measurement behind it. `measured` is the
		// only signal separating it from a genuine A+.
		const internalCall = await postureCall({
			'graded.com': { overall: 85, grade: 'B', measured: true },
			'nochecks.com': { overall: 100, grade: 'A+', measured: false },
		});
		const { runDeepScan } = await import('../src/lib/brand-audit-csc-deepscan');
		const result = await runDeepScan({ anchorApex: 'graded.com', apexes: ['graded.com', 'nochecks.com'], internalCall });

		// NOTE (same as the envelope test above): `buildStructuredScanResult` recomputes
		// the display letter from the numeric score via the NIST 6-band `displayGradeFor`,
		// so 85 → 'B' regardless of the fixture's letter. The point of the assertion is
		// that the distribution has exactly ONE entry — the unmeasured A+ apex is absent.
		expect(result.postureSnapshot.distribution).toEqual({ B: 1 });

		const ungraded = result.postureSnapshot.apexes.find((a) => a.apex === 'nochecks.com');
		expect(ungraded).toBeDefined();
		expect(ungraded?.grade).toBeNull();
		expect(ungraded?.score).toBeNull();
	});
});
