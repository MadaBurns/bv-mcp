import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse, servfailResponse, nxdomainResponse } from '../helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

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
		// the correct confidence. LIMIT OF THIS ASSERTION: `inferFindingConfidence`
		// (packages/dns-checks/src/scoring/model.ts) rejects any out-of-union value
		// and falls through to a 'deterministic' DEFAULT, so this line passes for
		// the correct literal, for an invalid literal, and for no declaration at
		// all. It pins the customer-visible confidence, NOT the emission site's
		// declaration. The discriminating half of the pair is the 'heuristic'
		// assertion in the next test — 'heuristic' is only reachable by declaring
		// it explicitly (or by keyword inference, which these details do not trip).
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
});
