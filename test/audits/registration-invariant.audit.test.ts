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

describe('registration invariants (audit)', () => {
	it('no unregistered finding coexists with observed records, across mixed rcodes', async () => {
		routeAll((name, type) => {
			if (name.endsWith('bnz.co.nz')) return createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'a1-97.akam.net.' }]);
			if (name.startsWith('bnz.de')) return servfailResponse(name, type === 'NS' ? 2 : 1);
			if (name.startsWith('bnz.kiwi')) return nxdomainResponse(name, type === 'NS' ? 2 : 1);
			return createDohResponse([], []);
		});

		const { checkShadowDomains, canClaimUnregistered } = await import('../../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		for (const f of result.findings) {
			if (!UNREGISTERED_TITLES.has(f.title)) continue;
			const m = (f.metadata ?? {}) as { ns?: string[]; mx?: string[]; hasSpf?: boolean };
			expect(canClaimUnregistered({ ns: m.ns ?? [], mx: m.mx ?? [], hasSpf: m.hasSpf === true })).toBe(true);
		}

		// A genuine NXDOMAIN (bnz.kiwi, routed above) IS a parsed authoritative
		// answer, so 'deterministic' is the correct confidence here. This scenario
		// always produces exactly one such finding, so the guard below is not
		// theatre — it fails loudly if a future regression stops emitting it,
		// rather than letting the loop below pass vacuously over zero elements.
		const unregistered = result.findings.filter((f) => f.title === 'Brand variant unregistered');
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
