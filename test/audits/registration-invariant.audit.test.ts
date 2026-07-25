import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, servfailResponse, nxdomainResponse } from '../helpers/dns-mock';

/**
 * Capture of every `createFinding` call, recorded at the CALL boundary — i.e.
 * BEFORE `withConfidenceMetadata` rewrites `metadata.confidence` with
 * `inferFindingConfidence`. Asserting the post-normalisation value cannot
 * discriminate: an out-of-union literal is rejected by `isExplicitConfidence`
 * and falls through to the `'deterministic'` DEFAULT, so a typo'd or invented
 * member reads identically to the correct one. Intercepting here is the only
 * way to pin what the emission site actually DECLARED.
 *
 * `vi.hoisted` because `vi.mock` factories are hoisted above the imports.
 */
const captured = vi.hoisted(() => ({ calls: [] as Array<{ title: string; confidence: unknown }> }));

vi.mock('@blackveil/dns-checks/scoring', async (importOriginal) => {
	const orig = await importOriginal<typeof import('@blackveil/dns-checks/scoring')>();
	return {
		...orig,
		createFinding: (category: string, title: string, severity: string, detail: string, metadata?: Record<string, unknown>) => {
			captured.calls.push({ title, confidence: metadata?.confidence });
			return (orig.createFinding as (...a: unknown[]) => unknown)(category, title, severity, detail, metadata);
		},
	};
});

const { restore } = setupFetchMock();
afterEach(() => {
	restore();
	captured.calls.length = 0;
});

function routeAll(builder: (name: string, type: string) => Response) {
	globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
		const href = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const url = new URL(href);
		return builder(url.searchParams.get('name') ?? '', url.searchParams.get('type') ?? '');
	}) as unknown as typeof fetch;
}

/** Titles that assert a domain does not exist. */
const UNREGISTERED_TITLES = new Set(['Brand variant unregistered']);

/**
 * Confidence values acceptable on a finding derived from a FAILED or ambiguous
 * lookup. `FindingConfidence` (packages/dns-checks/src/scoring/model.ts:18) is
 * exactly `'deterministic' | 'heuristic' | 'verified'` — any other string is
 * rejected by `isExplicitConfidence` and silently falls back to the
 * `'deterministic'` DEFAULT, which is the exact defect this rule exists to stop.
 * So the only in-union value expressing "we could not measure this" is
 * `'heuristic'`. A genuine NXDOMAIN is a parsed protocol answer and may stay
 * `'deterministic'`.
 */
const ABSENCE_CONFIDENCE = new Set(['heuristic']);

/** Extract the variant names a set of findings makes a claim about. */
function variantsIn(findings: Array<{ title: string; metadata?: Record<string, unknown> }>, title: string): string[] {
	return findings.filter((f) => f.title === title).map((f) => String((f.metadata as { variant?: string } | undefined)?.variant ?? ''));
}

describe('registration invariants (audit)', () => {
	it('routes each rcode to the right verdict — only NXDOMAIN may claim unregistered', async () => {
		// Three rcodes, three required outcomes, asserted on the STATE RESOLUTION
		// rather than on the shape of the emitted metadata literal. The previous
		// version of this test looped over unregistered findings asserting
		// `canClaimUnregistered(metadata)`, but the sole producer of that title
		// hardcodes `{ ns: [], mx: [], hasSpf: false }` — so it asserted that `[]`
		// has length 0 and stayed green with the original SERVFAIL->unregistered
		// bug reintroduced.
		routeAll((name, type) => {
			// Primary + a registered variant (bnz.com) so classifyVariant actually
			// runs and the mixed-rcode claim is genuinely exercised.
			if (name.endsWith('bnz.co.nz') || name === 'bnz.com') {
				return type === 'NS'
					? createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'a1-97.akam.net.' }])
					: createDohResponse([], []);
			}
			if (name.startsWith('bnz.de')) return servfailResponse(name, type === 'NS' ? 2 : 1);
			if (name.startsWith('bnz.kiwi')) return nxdomainResponse(name, type === 'NS' ? 2 : 1);
			return createDohResponse([], []);
		});

		const { checkShadowDomains } = await import('../../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		const claimedUnregistered = variantsIn(result.findings, 'Brand variant unregistered');
		const claimedUnknown = variantsIn(result.findings, 'Brand variant registration unknown');

		// NXDOMAIN is the only rcode that may support a non-existence claim.
		expect(claimedUnregistered).toContain('bnz.kiwi');
		// SERVFAIL is a measurement failure. Reintroducing the original bug — making
		// resolveRegistrationUncached return `unregistered` on SERVFAIL — moves
		// bnz.de into the list above and fails this line.
		expect(claimedUnregistered).not.toContain('bnz.de');
		expect(claimedUnknown).toContain('bnz.de');

		// The mixed-rcode scenario must reach classifyVariant, or the registered
		// arm of this matrix is never exercised.
		expect(result.findings.some((f) => f.title.startsWith('Shadow domain '))).toBe(true);

		// A genuine NXDOMAIN IS a parsed authoritative answer, so 'deterministic' is
		// the correct confidence. SCOPE OF THIS ASSERTION: it pins the
		// CUSTOMER-VISIBLE value only — `inferFindingConfidence` normalises any
		// out-of-union declaration to a 'deterministic' default, so this line alone
		// cannot detect a wrong literal at the emission site. The declaration itself
		// is pinned pre-normalisation by the last test in this file.
		const unregistered = result.findings.filter((f) => UNREGISTERED_TITLES.has(f.title));
		expect(unregistered.length).toBeGreaterThan(0);
		for (const f of unregistered) {
			expect((f.metadata as { confidence?: string } | undefined)?.confidence).toBe('deterministic');
		}
	});

	it('absence-derived findings declare confidence explicitly, never inheriting deterministic', async () => {
		routeAll((name, type) => {
			if (name.endsWith('bnz.co.nz')) return createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'a1-97.akam.net.' }]);
			return servfailResponse(name, type === 'NS' ? 2 : 1);
		});

		const { checkShadowDomains } = await import('../../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		// A FAILED/ambiguous lookup must never inherit the 'deterministic' default.
		// (This mock has no NXDOMAIN branch, so no 'Brand variant unregistered'
		// finding is ever produced here — that pairing is asserted in the first
		// test above, against a scenario that actually produces one.)
		const unknownFindings = result.findings.filter((f) => f.title === 'Brand variant registration unknown');
		expect(unknownFindings.length).toBeGreaterThan(0);
		for (const f of unknownFindings) {
			const declared = (f.metadata as { confidence?: string } | undefined)?.confidence;
			expect(ABSENCE_CONFIDENCE.has(declared ?? 'deterministic')).toBe(true);
		}
	});

	it('the Phase-2 registered-but-no-records fallthrough declares heuristic confidence', async () => {
		// Mirrors test/check-shadow-domains.spec.ts's "never emits an unregistered
		// finding alongside observed records" mock shape: NS answers only for the
		// primary domain (empty for every variant), so resolveRegistration
		// escalates to A — which IS present — and reports `registered` with
		// `ns: []`. TXT answers an SPF record for every queried name, including
		// the `_dmarc.<variant>` probe, whose value doesn't start with
		// 'v=dmarc1' and so contributes no DMARC policy. That combination reaches
		// classifyVariant's final fallthrough: registered (via A evidence), but
		// with no NS and no MX observed at the detail-probe stage — the exact
		// shape that emits 'Shadow domain registered, records not observed' with
		// `confidence: 'heuristic'` declared in its metadata
		// (src/tools/check-shadow-domains.ts:389).
		routeAll((name, type) => {
			if (type === 'NS') {
				return name === 'bnz.co.nz'
					? createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.bnz.co.nz.' }])
					: createDohResponse([], []);
			}
			if (type === 'A') return createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '203.0.113.10' }]);
			if (type === 'TXT') return createDohResponse([{ name, type: 16 }], [{ name, type: 16, TTL: 300, data: '"v=spf1 mx -all"' }]);
			return createDohResponse([], []);
		});

		const { checkShadowDomains } = await import('../../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		const fallthrough = result.findings.filter((f) => f.title === 'Shadow domain registered, records not observed');
		expect(fallthrough.length).toBeGreaterThan(0);
		for (const f of fallthrough) {
			expect((f.metadata as { confidence?: string } | undefined)?.confidence).toBe('heuristic');
		}
	});

	it('DECLARES the right confidence at each emission site (asserted pre-normalisation)', async () => {
		// The discriminating counterpart to the assertions above. Those read
		// `finding.metadata.confidence` AFTER `withConfidenceMetadata` has rewritten
		// it, so 'deterministic' is unfalsifiable there. This one reads the literal
		// handed to `createFinding`, where an invented member like 'probable' — the
		// exact defect that slipped past tests, typecheck, eslint and prettier
		// earlier on this branch — shows up as itself and fails.
		//
		// One mock producing all three registration outcomes in a single scan:
		//   bnz.kiwi  NXDOMAIN everywhere      -> 'Brand variant unregistered'
		//   bnz.de    SERVFAIL everywhere      -> 'Brand variant registration unknown'
		//   bnz.com   NS/SOA empty + A hit     -> 'Shadow domain registered, records not observed'
		routeAll((name, type) => {
			if (name.endsWith('bnz.co.nz')) {
				return type === 'NS'
					? createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'a1-97.akam.net.' }])
					: createDohResponse([], []);
			}
			if (name.startsWith('bnz.kiwi')) return nxdomainResponse(name, type === 'NS' ? 2 : 1);
			if (name.startsWith('bnz.de')) return servfailResponse(name, type === 'NS' ? 2 : 1);
			if (name.startsWith('bnz.com')) {
				// Registered via the A escalation only: no NS, no SOA, no MX — the
				// shape that reaches classifyVariant's final fallthrough.
				if (type === 'A') return createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '203.0.113.10' }]);
				if (type === 'TXT') return createDohResponse([{ name, type: 16 }], [{ name, type: 16, TTL: 300, data: '"v=spf1 mx -all"' }]);
				return createDohResponse([], []);
			}
			return createDohResponse([], []);
		});

		captured.calls.length = 0;
		const { checkShadowDomains } = await import('../../src/tools/check-shadow-domains');
		await checkShadowDomains('bnz.co.nz');

		// The interception itself must be live, or every assertion below is vacuous.
		expect(captured.calls.length).toBeGreaterThan(0);

		const declaredFor = (title: string) => captured.calls.filter((c) => c.title === title).map((c) => c.confidence);

		// An NXDOMAIN is a parsed protocol answer — 'deterministic' is correct here,
		// and is now pinned as the DECLARED literal rather than the default.
		const unregistered = declaredFor('Brand variant unregistered');
		expect(unregistered.length).toBeGreaterThan(0);
		expect([...new Set(unregistered)]).toEqual(['deterministic']);

		// Both absence-derived sites must declare 'heuristic' explicitly.
		const unknown = declaredFor('Brand variant registration unknown');
		expect(unknown.length).toBeGreaterThan(0);
		expect([...new Set(unknown)]).toEqual(['heuristic']);

		const fallthrough = declaredFor('Shadow domain registered, records not observed');
		expect(fallthrough.length).toBeGreaterThan(0);
		expect([...new Set(fallthrough)]).toEqual(['heuristic']);
	});
});
