// SPDX-License-Identifier: BUSL-1.1

/**
 * Cross-cutting structural-invariant audit — ownership-attribution
 * followups, item 1 (2026-07-27, "full match only" ruling).
 *
 * THE LOAD-BEARING SAFETY PROPERTY THIS AUDIT LOCKS: `correlateNs()`'s
 * confidence-1 / `matchType: 'in_bailiwick'` result — the near-deterministic
 * ownership signal that `evidenceTier()` (`src/lib/brand-evidence.ts`) grants
 * a single-observation `'strong'` tier, which `clearsOwnershipGate()` then
 * lets bypass N-of-M corroboration ENTIRELY — may only ever be produced for
 * a candidate whose own nameserver set is FULLY in-bailiwick to the seed
 * apex. A PARTIAL in-bailiwick subset (e.g. 1 of 5 nameservers under the
 * seed apex, 4 external) must fall through to the existing `set_overlap`
 * ratio/count math and be graded — or dropped — accordingly, never take the
 * free strong-tier bypass.
 *
 * WHY A SIBLING AUDIT, NOT AN EXTENSION OF `ownership-severity-gate.audit.
 * test.ts`: that audit locks a DIFFERENT invariant (finding-severity
 * justification inside `checkShadowDomains()`/`checkLookalikes()`, keyed on
 * `ownershipVerdict`/`findingAxis` metadata) using a DoH-mock fixture idiom
 * built entirely around those two tools' finding shapes. This audit's
 * invariant lives one layer up the brand-discovery pipeline — the
 * `correlateNs()` → `evidenceTier()` → `clearsOwnershipGate()` →
 * `discoverBrandDomains()` auto-include handoff — and needs its own
 * `dnsQuery`-injection + deps-injection fixtures. Bolting it onto the
 * existing file would mean two unrelated fixture idioms sharing one
 * describe block; a focused sibling keeps each audit's fixture surface
 * legible.
 *
 * THE GAP THIS CLOSES: before this file existed, NOTHING in `test/audits/`
 * imported `correlateNs`, `discover-brand-domains.ts`, or `brand-evidence.ts`
 * — a regression reintroducing the free strong-tier bypass for a partial
 * in-bailiwick match was caught by NOTHING but the ordinary unit specs
 * (`test/tenants/discovery/ns-correlator.test.ts`, `test/brand-evidence.
 * test.ts`), which a future "optimisation" could edit alongside the source
 * regression. This audit is deliberately independent of those files' fixture
 * data (it builds its own) so it cannot be silently weakened in lockstep.
 *
 * Every assertion below was proven to go RED against the pre-fix source (the
 * unconditional `inBailiwick.length > 0` bypass) by direct mutation — see
 * the task report for the mutation-by-mutation transcript.
 */

import { describe, it, expect, vi } from 'vitest';
import { correlateNs } from '../../src/tenants/discovery/ns-correlator';
import { evidenceTier, clearsOwnershipGate, type BrandEvidenceObservation } from '../../src/lib/brand-evidence';
import type { DohResponse } from '../../src/lib/dns-types';
import type { DiscoverBrandDomainsDeps } from '../../src/tools/discover-brand-domains';
import type { NsCorrelationResult } from '../../src/tenants/discovery/ns-correlator';

interface NsAnswerFixture {
	name: string;
	data: string;
}

function nsResponse(answers: NsAnswerFixture[]): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name: 'x', type: 2 }],
		Answer: answers.map((a) => ({ name: a.name, type: 2, TTL: 3600, data: a.data })),
	};
}

function emptyDnsResponse(): DohResponse {
	return { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false, Question: [{ name: 'x', type: 2 }], Answer: [] };
}

/** Build a dnsQuery mock keyed by domain -> NS-data array (mirrors ns-correlator.test.ts). */
function dnsQueryFromMap(map: Record<string, string[]>): (name: string, type: string) => Promise<DohResponse> {
	return vi.fn(async (name: string) => {
		const key = name.toLowerCase().replace(/\.$/, '');
		const ns = map[key];
		if (!ns) return emptyDnsResponse();
		return nsResponse(ns.map((d) => ({ name: key, data: d })));
	});
}

/**
 * Builds the SAME `BrandEvidenceObservation` shape `discover-brand-domains.
 * ts`'s `addObservation()` call site constructs for the 'ns' signal
 * (`sharedNs`, `nsConfidence`, `matchType` in metadata; `confidence` from
 * the correlator result) — see `discover-brand-domains.ts` around the 'ns'
 * job's `addObservation(aggregator, c.domain, 'ns', c.confidence, {
 * sharedNs, nsConfidence, matchType })` call.
 */
function nsObservation(candidate: NsCorrelationResult['coOwnedDomains'][number]): BrandEvidenceObservation {
	return {
		signal: 'ns',
		confidence: candidate.confidence,
		metadata: { sharedNs: candidate.sharedNs, nsConfidence: candidate.confidence, matchType: candidate.matchType },
	};
}

const SEED = 'bnz.co.nz';
/** Seed self-hosts two dedicated NS — a full-migration candidate can match ALL of them in-bailiwick. */
const SEED_NS = ['ns1.bnz.co.nz.', 'ns2.bnz.co.nz.'];

describe('ns-in-bailiwick full-match audit (ownership-attribution followups, item 1)', () => {
	it('FULL in-bailiwick match: correlateNs -> evidenceTier -> clearsOwnershipGate all agree this is a legitimate single-signal auto-include', async () => {
		const dnsQuery = dnsQueryFromMap({
			[SEED]: SEED_NS,
			'bnz-migrated.nz': ['ns1.bnz.co.nz.', 'ns2.bnz.co.nz.', 'ns3.bnz.co.nz.'],
		});
		const result = await correlateNs(SEED, { dnsQuery, candidateDomains: ['bnz-migrated.nz'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toHaveLength(1);
		const candidate = result.coOwnedDomains[0];
		expect(candidate).toMatchObject({ matchType: 'in_bailiwick', confidence: 1 });

		expect(evidenceTier('ns', { matchType: candidate.matchType })).toBe('strong');
		expect(clearsOwnershipGate([nsObservation(candidate)])).toBe(true);
	});

	it('PARTIAL in-bailiwick match (1 in-bailiwick NS, 4 external): correlateNs must NOT emit matchType in_bailiwick / confidence 1', async () => {
		const dnsQuery = dnsQueryFromMap({
			[SEED]: SEED_NS,
			'bnz-partial.nz': [
				'ns1.bnz.co.nz.',
				'ns9.external-registrar.example.',
				'ns10.external-registrar.example.',
				'ns11.external-registrar.example.',
				'ns12.external-registrar.example.',
			],
		});
		const result = await correlateNs(SEED, { dnsQuery, candidateDomains: ['bnz-partial.nz'] });
		expect(result.queryStatus).toBe('ok');
		// May legitimately be graded (set_overlap) or dropped entirely — either
		// is acceptable per the ruling's accepted cost. What is NEVER
		// acceptable is confidence 1 / matchType 'in_bailiwick'.
		const candidate = result.coOwnedDomains.find((c) => c.domain === 'bnz-partial.nz');
		if (candidate) {
			expect(candidate.matchType).not.toBe('in_bailiwick');
			expect(candidate.confidence).not.toBe(1);
		}
	});

	it('PARTIAL in-bailiwick match must NEVER reach evidenceTier "strong" by any route, and must NOT clear the ownership gate alone', async () => {
		const dnsQuery = dnsQueryFromMap({
			[SEED]: SEED_NS,
			'bnz-partial.nz': [
				'ns1.bnz.co.nz.',
				'ns9.external-registrar.example.',
				'ns10.external-registrar.example.',
				'ns11.external-registrar.example.',
				'ns12.external-registrar.example.',
			],
		});
		const result = await correlateNs(SEED, { dnsQuery, candidateDomains: ['bnz-partial.nz'] });
		const candidate = result.coOwnedDomains.find((c) => c.domain === 'bnz-partial.nz');
		// The candidate DOES survive here (1 shared NS host, ns1.bnz.co.nz,
		// literally overlaps the seed's own 2-host NS set -> set_overlap 0.5) —
		// asserting that up front so the "does not clear the gate" conclusion
		// below is proven against a real, non-vacuous observation.
		expect(candidate, 'fixture must produce a candidate — otherwise the tier/gate checks below are vacuous').toBeDefined();
		expect(candidate!.matchType).toBe('set_overlap');
		expect(candidate!.confidence).toBe(0.5);

		const tier = evidenceTier('ns', { matchType: candidate!.matchType });
		expect(tier, 'a partial in-bailiwick match must never reach the strong tier by any route').not.toBe('strong');
		expect(
			clearsOwnershipGate([nsObservation(candidate!)]),
			'a single medium-tier ns observation must not alone clear the ownership gate',
		).toBe(false);
	});

	it('END-TO-END: discoverBrandDomains() auto-includes a FULL in-bailiwick candidate but does NOT auto-include a PARTIAL in-bailiwick candidate on the same ns signal alone', async () => {
		const { discoverBrandDomains } = await import('../../src/tools/discover-brand-domains');

		// Full match: real correlateNs result computed via injected dnsQuery,
		// fed into discoverBrandDomains through the deps seam exactly as
		// production wires it (src/tools/discover-brand-domains.ts ~:1141).
		const fullDnsQuery = dnsQueryFromMap({
			[SEED]: SEED_NS,
			'bnz-migrated.nz': ['ns1.bnz.co.nz.', 'ns2.bnz.co.nz.', 'ns3.bnz.co.nz.'],
		});
		// Deliberately NOT passed via `candidate_domains` — that would mark the
		// domain caller-asserted and bypass `clearsOwnershipGate()`'s tier
		// check entirely (a different code path), which would make this test
		// pass for the wrong reason. `correlateNs` is mocked, so it returns
		// this fixed result regardless of what candidates the 'ns' job asks
		// for internally.
		const fullResult = await correlateNs(SEED, { dnsQuery: fullDnsQuery, candidateDomains: ['bnz-migrated.nz'] });
		const fullDeps: Partial<DiscoverBrandDomainsDeps> = { correlateNs: vi.fn().mockResolvedValue(fullResult) };
		const fullScan = await discoverBrandDomains(SEED, { signals: ['ns'], min_confidence: 0.1 }, fullDeps as DiscoverBrandDomainsDeps);
		const fullCandidateFinding = fullScan.findings.find((f) => f.metadata?.candidate === 'bnz-migrated.nz');
		expect(fullCandidateFinding, 'full in-bailiwick match must be discovered').toBeDefined();
		expect(fullCandidateFinding!.severity, 'a legitimate full in-bailiwick match earns the auto-include severity').toBe('low');

		// Partial match: same shape, but the candidate's NS set is only 1/5
		// in-bailiwick.
		const partialDnsQuery = dnsQueryFromMap({
			[SEED]: SEED_NS,
			'bnz-partial.nz': [
				'ns1.bnz.co.nz.',
				'ns9.external-registrar.example.',
				'ns10.external-registrar.example.',
				'ns11.external-registrar.example.',
				'ns12.external-registrar.example.',
			],
		});
		const partialResult = await correlateNs(SEED, { dnsQuery: partialDnsQuery, candidateDomains: ['bnz-partial.nz'] });
		const partialDeps: Partial<DiscoverBrandDomainsDeps> = { correlateNs: vi.fn().mockResolvedValue(partialResult) };
		const partialScan = await discoverBrandDomains(SEED, { signals: ['ns'], min_confidence: 0.1 }, partialDeps as DiscoverBrandDomainsDeps);
		const partialCandidateFinding = partialScan.findings.find((f) => f.metadata?.candidate === 'bnz-partial.nz');
		expect(
			partialCandidateFinding,
			'a partial in-bailiwick match must NOT auto-include on the ns signal alone — a single medium-tier observation cannot clear the ownership gate',
		).toBeUndefined();
	});
});
