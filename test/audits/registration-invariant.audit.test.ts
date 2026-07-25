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

		const { checkShadowDomains } = await import('../../src/tools/check-shadow-domains');
		const { canClaimUnregistered } = await import('../../src/tools/check-shadow-domains');
		const result = await checkShadowDomains('bnz.co.nz');

		for (const f of result.findings) {
			if (!UNREGISTERED_TITLES.has(f.title)) continue;
			const m = (f.metadata ?? {}) as { ns?: string[]; mx?: string[]; hasSpf?: boolean };
			expect(canClaimUnregistered({ ns: m.ns ?? [], mx: m.mx ?? [], hasSpf: m.hasSpf === true })).toBe(true);
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
		const unknownFindings = result.findings.filter((f) => f.title === 'Brand variant registration unknown');
		expect(unknownFindings.length).toBeGreaterThan(0);
		for (const f of unknownFindings) {
			const declared = (f.metadata as { confidence?: string } | undefined)?.confidence;
			expect(ABSENCE_CONFIDENCE.has(declared ?? 'deterministic')).toBe(true);
		}

		// A genuine NXDOMAIN IS a parsed authoritative answer, so 'deterministic'
		// is correct there — asserted separately so the two cases cannot be
		// conflated into one permissive set.
		for (const f of result.findings.filter((f) => f.title === 'Brand variant unregistered')) {
			expect((f.metadata as { confidence?: string } | undefined)?.confidence).toBe('deterministic');
		}
	});
});
