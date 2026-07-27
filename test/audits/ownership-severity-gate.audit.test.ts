// SPDX-License-Identifier: BUSL-1.1

/**
 * Cross-cutting structural-invariant audit — Task 8 (2026-07-26 correctness-
 * defects design, slice 4 "ownership attribution").
 *
 * THE LOAD-BEARING SAFETY PROPERTY THIS AUDIT LOCKS: a finding may exceed
 * `info` severity ONLY when it is justified by ownership — `owned_by_seed` —
 * or is an explicitly-named threat OBSERVATION about a candidate that is NOT
 * the scanned organisation's own domain. Nothing else above `info` is
 * permitted to slip through `checkShadowDomains()` / `checkLookalikes()`.
 *
 * CONTROLLER AMENDMENTS TO THE ORIGINAL TASK-8 BRIEF (binding, see
 * `.superpowers/sdd/2026-07-26-slice4-ownership-attribution/task-8-brief.md`
 * for the superseded text):
 *
 *  (1) POSITIVE-ASSERTION FORM. The brief's audit inspected only findings
 *      that already CARRY `ownershipVerdict` — a finding that omits the
 *      verdict entirely escaped it. This audit instead sweeps EVERY finding
 *      both tools emit (`assertSeverityJustified` below) and requires each
 *      one above `info` to affirmatively justify itself:
 *        (`ownershipVerdict === 'owned_by_seed'`) OR
 *        (`findingAxis === 'threat_observation'` AND `ownershipVerdict` is
 *         present and `!== 'owned_by_seed'` AND a candidate domain is named
 *         in metadata).
 *      A finding with NEITHER above `info` is an AUDIT FAILURE, full stop.
 *
 *  (2) THE AXIS MODEL (lookalikes only — `check-shadow-domains.ts` has no
 *      `findingAxis` field by design ruling, so its invariant is simply
 *      "nothing above info without `ownershipVerdict === 'owned_by_seed'`",
 *      which (1) above already covers). For `checkLookalikes`:
 *        - every finding carries one of `'attribution' | 'threat_observation'
 *          | 'scan_status'`;
 *        - every `'scan_status'` finding is `info`;
 *        - every `'threat_observation'` finding carries `ownershipVerdict
 *          !== 'owned_by_seed'` and names a candidate;
 *        - every `'attribution'` finding for a non-owned candidate is `info`
 *          AND carries no ownership-framed prose ("shadow domain", "your",
 *          "owned by same entity") in its title or detail.
 *      `check-shadow-domains.ts` carries a SEPARATE, single carve-out for
 *      this same framing rule — `AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE` (the
 *      Phase-2 "records not observed" fallthrough keeps its ownership-framed
 *      title because `registration-invariant.audit.test.ts` — byte-frozen —
 *      pins that exact title literal). This audit asserts that carve-out is
 *      EXACTLY one title and EXACTLY the known string, so it cannot silently
 *      widen to swallow other framed titles.
 *
 *  (3) THE PRIMITIVE-LEVEL INVARIANT (task 7c). The three candidate-side
 *      signals (`soaInBailiwick`, `spfIncludesSeedApex`, `httpRedirectToSeedApex`)
 *      must never — alone or combined — produce `owned_by_seed` from
 *      `classifyOwnership()` directly. Pinned once more here (unit tests
 *      already pin it) so a future "optimisation" of those unit tests can't
 *      silently drop the property from BOTH places at once.
 *
 * METHOD NOTE: every clause below was proven to go RED by a real source
 * mutation (ungating a call site, retagging a `scan_status` finding, undoing
 * Ruling A, widening the framed-title carve-out, forcing an empty findings
 * array) — see `.superpowers/sdd/2026-07-26-slice4-ownership-attribution/
 * task-8-report.md` for the mutation-by-mutation evidence. The mutations
 * themselves are not preserved in this file; only their proof they were run.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import type { Finding } from '../../src/lib/scoring';
import { setupFetchMock, createDohResponse } from '../helpers/dns-mock';

const { restore } = setupFetchMock();
afterEach(() => restore());

// ---------------------------------------------------------------------------
// DoH mock plumbing (mirrors test/check-shadow-domains.spec.ts and
// test/check-lookalikes.spec.ts's own local helpers).
// ---------------------------------------------------------------------------

function parseDohQuery(input: string | URL | Request): { name: string; type: string } | null {
	const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
	try {
		const parsed = new URL(url);
		return { name: parsed.searchParams.get('name') ?? '', type: parsed.searchParams.get('type') ?? '' };
	} catch {
		return null;
	}
}

function empty() {
	return createDohResponse([], []);
}
function nsRecords(domain: string, nameservers: string[]) {
	return createDohResponse(
		[{ name: domain, type: 2 }],
		nameservers.map((ns) => ({ name: domain, type: 2, TTL: 300, data: ns })),
	);
}
function aRecords(domain: string, ips: string[]) {
	return createDohResponse(
		[{ name: domain, type: 1 }],
		ips.map((ip) => ({ name: domain, type: 1, TTL: 300, data: ip })),
	);
}
function mxRecords(domain: string, records: string[]) {
	return createDohResponse(
		[{ name: domain, type: 15 }],
		records.map((data) => ({ name: domain, type: 15, TTL: 300, data })),
	);
}
function servfail(domain: string, type: number) {
	return createDohResponse([{ name: domain, type }], [], { status: 2 });
}

/** Real bnz.co.nz-style Akamai NS pool (2026-07-26 correctness-defects design §3.3). */
const SEED_AKAMAI_NS = ['a1-97.akam.net.', 'a3-67.akam.net.', 'a8-66.akam.net.', 'a9-65.akam.net.', 'a16-65.akam.net.', 'a24-64.akam.net.'];

// ---------------------------------------------------------------------------
// Shared invariant assertions (the actual "gate" this audit locks).
// ---------------------------------------------------------------------------

interface Violation {
	tool: string;
	title: string;
	severity: string;
	reason: string;
}

/**
 * Amendment (1) — THE positive-assertion rule. Returns violations rather than
 * throwing immediately so a single sweep can report every offender at once
 * (and so the "exactly one framed title" check elsewhere can reuse it).
 */
function findSeverityViolations(tool: string, findings: readonly Finding[]): Violation[] {
	const violations: Violation[] = [];
	for (const f of findings) {
		if (f.severity === 'info') continue;
		const meta = f.metadata as Record<string, unknown> | undefined;
		const verdict = meta?.ownershipVerdict;
		if (verdict === 'owned_by_seed') continue;

		const axis = meta?.findingAxis;
		if (axis === 'threat_observation' && verdict !== undefined && verdict !== 'owned_by_seed') {
			const named =
				typeof meta?.lookalikeDomain === 'string' ||
				(Array.isArray(meta?.lookalikeDomains) && (meta.lookalikeDomains as unknown[]).length > 0) ||
				typeof meta?.domain === 'string';
			if (named) continue;
			violations.push({ tool, title: f.title, severity: f.severity, reason: 'threat_observation above info names no candidate domain' });
			continue;
		}

		violations.push({
			tool,
			title: f.title,
			severity: f.severity,
			reason: `above-info with no ownership justification (verdict=${JSON.stringify(verdict)}, axis=${JSON.stringify(axis)})`,
		});
	}
	return violations;
}

/** Vacuous-green guard: a sweep over zero findings would trivially "pass". Call before every sweep. */
function assertNonEmpty(tool: string, findings: readonly Finding[]) {
	expect(findings.length, `${tool}: fixture produced zero findings — the sweep below would be vacuously green`).toBeGreaterThan(0);
}

function assertSeverityJustified(tool: string, findings: readonly Finding[]) {
	assertNonEmpty(tool, findings);
	const violations = findSeverityViolations(tool, findings);
	expect(violations, `${tool}: unjustified above-info findings:\n${JSON.stringify(violations, null, 2)}`).toEqual([]);
}

const BANNED_FRAMING = [/shadow domain/i, /\byour\b/i, /owned by same entity/i];

function framingViolations(title: string, detail: string): string[] {
	return BANNED_FRAMING.filter((re) => re.test(title) || re.test(detail)).map((re) => re.source);
}

// =============================================================================
// Fixture A — checkShadowDomains, one combined scan carrying every required
// scenario: owned (in-bailiwick), third-party with active-MX threat signals,
// the shared-provider (Akamai) partial-overlap trap, and the "registered,
// records not observed" unattributed carve-out branch.
// =============================================================================

async function runShadowDomainsFixture() {
	const seed = 'bnz.co.nz';
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const q = parseDohQuery(input);
		if (!q) return Promise.resolve(empty());
		const { name, type } = q;

		if (name === seed) {
			if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(seed, SEED_AKAMAI_NS));
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(seed, ['10 mail.bnz.co.nz.']));
		}

		// OWNED — in-bailiwick NS, fully spoofable shape. Must stay unclamped:
		// it is the seed's own domain, above-info is correct here.
		if (name === 'bnz.com') {
			if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.bnz.co.nz.']));
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mx.bnz.com.']));
		}

		// THIRD-PARTY THREAT — distinct NS, fully spoofable shape. Must be
		// capped to info via the D4 gate.
		if (name === 'bnz.de') {
			if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.attacker-dns.com.']));
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mx.bnz.de.']));
		}

		// SHARED-PROVIDER (AKAMAI) PARTIAL-OVERLAP TRAP — shares exactly ONE
		// Akamai NS host with the seed, otherwise distinct, ALSO fully
		// spoofable shape. Must be capped to info (1/6 shared-provider overlap
		// is not ownership evidence).
		if (name === 'bnz.eu') {
			if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, [SEED_AKAMAI_NS[0], 'ns2.unrelated-registrar.com.']));
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mx.bnz.eu.']));
		}

		// RECORDS-NOT-OBSERVED / UNATTRIBUTED carve-out — NS empty, A resolves,
		// no MX, no SPF. classifyOwnership() falls all the way through to
		// 'unattributed' (candidateNs is empty — no NS evidence at all).
		if (name === 'bnz.ca') {
			if (type === 'NS' || type === '2') return Promise.resolve(empty());
			if (type === 'A' || type === '1') return Promise.resolve(aRecords(name, ['192.0.2.50']));
		}

		// SERVFAIL-ish — resolver-broken delegation, stays 'unknown' end to
		// end (info-only, no ownershipVerdict at all).
		if (name === 'bnz.nl' && (type === 'NS' || type === '2')) return Promise.resolve(servfail(name, 2));

		// THIRD-PARTY, REGISTERED WITH NO MAIL — exercises the OTHER
		// NEUTRAL_INFO_TITLES entry ("Shadow domain registered, no mail" →
		// "Confusable domain registered, no mail") end to end, so the
		// exactly-one-carve-out check below has more than one candidate title
		// to actually discriminate against.
		if (name === 'bnz.jp' && (type === 'NS' || type === '2')) return Promise.resolve(nsRecords(name, ['ns1.attacker-dns.com.']));

		return Promise.resolve(empty());
	});

	const { checkShadowDomains } = await import('../../src/tools/check-shadow-domains');
	return checkShadowDomains(seed);
}

/** A fully clean scan: nothing registered anywhere. Sanity + vacuous-green guard target. */
async function runShadowDomainsCleanFixture() {
	globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(empty()));
	const { checkShadowDomains } = await import('../../src/tools/check-shadow-domains');
	return checkShadowDomains('cleanbrand9182.com');
}

// =============================================================================
// Fixture B — checkLookalikes, one combined scan: owned (in-bailiwick,
// disposable MX to prove owned candidates get no threat axis at all),
// third-party with an active disposable-MX threat (the #264 HIGH tier), and
// the shared-provider (Akamai) partial-overlap trap.
// =============================================================================

async function runLookalikesFixture() {
	const seed = 'testco.com';
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const q = parseDohQuery(input);
		if (!q) return Promise.resolve(empty());
		const { name, type } = q;

		if (name === seed && (type === 'NS' || type === '2')) return Promise.resolve(nsRecords(seed, SEED_AKAMAI_NS));

		// OWNED (in-bailiwick) — even with a disposable-MX shape, an owned
		// candidate must get NO threat_observation finding at all (Task 7b
		// requirement 5 — a domain is not an impersonation threat to itself).
		if (name === 'testc0.com') {
			if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.testco.com.']));
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mx.mailgun.org.']));
		}

		// THIRD-PARTY THREAT — distinct NS, live mail on a disposable provider:
		// the #264 HIGH tier. Attribution axis capped at info; threat axis
		// carries the real HIGH, verdict !== owned_by_seed, candidate named.
		if (name === 'twstco.com') {
			if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, ['ns1.unrelated-dns.com.']));
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mx.mailgun.org.']));
		}

		// SHARED-PROVIDER (AKAMAI) TRAP — shares exactly ONE Akamai host with
		// the seed, otherwise distinct, with plain (non-disposable) mail infra
		// — the #264 MEDIUM tier. Attribution axis still capped at info.
		if (name === 'trstco.com') {
			if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(name, [SEED_AKAMAI_NS[0], 'ns2.other-registrar.com.']));
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(name, ['10 mx.trstco.com.']));
		}

		return Promise.resolve(empty());
	});

	const { checkLookalikes } = await import('../../src/tools/check-lookalikes');
	return checkLookalikes(seed);
}

/** A fully clean scan: nothing registered anywhere. Sanity + vacuous-green guard target. */
async function runLookalikesCleanFixture() {
	globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(empty()));
	const { checkLookalikes } = await import('../../src/tools/check-lookalikes');
	return checkLookalikes('nomatch918273brand.com');
}

// =============================================================================
// Tests
// =============================================================================

describe('ownership severity gate (audit) — load-bearing safety property', () => {
	it('checkShadowDomains: no above-info finding without ownership justification (positive-assertion sweep, exhaustive)', async () => {
		const result = await runShadowDomainsFixture();
		assertSeverityJustified('checkShadowDomains', result.findings);

		// Sanity the fixture actually exercised both directions, not just a
		// uniformly-info result that would make the sweep trivially green.
		expect(result.findings.some((f) => f.severity !== 'info')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
	});

	it('checkShadowDomains: clean scan sweeps green and is never vacuously empty', async () => {
		const result = await runShadowDomainsCleanFixture();
		assertSeverityJustified('checkShadowDomains (clean)', result.findings);
		expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
	});

	it('checkShadowDomains: ownership framing absent from non-owned findings, except the exactly-one audit-pinned carve-out', async () => {
		const { AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE } = await import('../../src/tools/check-shadow-domains');
		expect(AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE).toBe('Shadow domain registered, records not observed');

		const result = await runShadowDomainsFixture();
		const nonOwned = result.findings.filter((f) => {
			const v = f.metadata?.ownershipVerdict;
			return v !== undefined && v !== 'owned_by_seed';
		});
		expect(nonOwned.length).toBeGreaterThan(0);

		const framedTitles = new Set<string>();
		for (const f of nonOwned) {
			if (f.title === AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE) continue; // the one sanctioned carve-out
			const hits = framingViolations(f.title, f.detail);
			if (hits.length > 0) framedTitles.add(f.title);
		}
		expect([...framedTitles]).toEqual([]);

		// The carve-out itself must actually have been exercised by this
		// fixture (bnz.ca) — otherwise "exactly one" is an unverified claim.
		expect(result.findings.some((f) => f.title === AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE)).toBe(true);
	});

	it('checkLookalikes: no above-info finding without ownership justification (positive-assertion sweep, exhaustive)', async () => {
		const result = await runLookalikesFixture();
		assertSeverityJustified('checkLookalikes', result.findings);

		expect(result.findings.some((f) => f.severity === 'high')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
	});

	it('checkLookalikes: clean scan sweeps green and is never vacuously empty', async () => {
		const result = await runLookalikesCleanFixture();
		assertSeverityJustified('checkLookalikes (clean)', result.findings);
		expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
	});

	it('checkLookalikes: every finding carries a findingAxis, and axis-specific invariants hold (Task 7b axis model)', async () => {
		const mainResult = await runLookalikesFixture();
		const cleanResult = await runLookalikesCleanFixture();
		// Merge both fixtures so the scan_status clause is genuinely exercised
		// (the main fixture has no unregistered/empty path — scan_status only
		// appears in the clean scan's "no active lookalikes" notice).
		const result = { findings: [...mainResult.findings, ...cleanResult.findings] };
		assertNonEmpty('checkLookalikes (axis)', result.findings);

		for (const f of result.findings) {
			expect(['attribution', 'threat_observation', 'scan_status']).toContain(f.metadata?.findingAxis);
		}
		// All three axes actually represented — a degenerate "everything is
		// attribution" world would otherwise satisfy the loop above.
		expect(result.findings.some((f) => f.metadata?.findingAxis === 'attribution')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.findingAxis === 'threat_observation')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.findingAxis === 'scan_status')).toBe(true);

		for (const f of result.findings) {
			if (f.metadata?.findingAxis !== 'scan_status') continue;
			expect(f.severity, `scan_status finding "${f.title}" is not info`).toBe('info');
		}

		for (const f of result.findings) {
			if (f.metadata?.findingAxis !== 'threat_observation') continue;
			expect(f.metadata?.ownershipVerdict, `threat_observation "${f.title}" carries no ownershipVerdict`).toBeDefined();
			expect(f.metadata?.ownershipVerdict, `threat_observation "${f.title}" carries owned_by_seed`).not.toBe('owned_by_seed');
			const named =
				typeof f.metadata?.lookalikeDomain === 'string' ||
				(Array.isArray(f.metadata?.lookalikeDomains) && (f.metadata.lookalikeDomains as unknown[]).length > 0) ||
				typeof f.metadata?.domain === 'string';
			expect(named, `threat_observation "${f.title}" names no candidate`).toBe(true);
		}

		for (const f of result.findings) {
			if (f.metadata?.findingAxis !== 'attribution') continue;
			const verdict = f.metadata?.ownershipVerdict;
			if (verdict === undefined || verdict === 'owned_by_seed') continue;
			expect(f.severity, `non-owned attribution finding "${f.title}" is above info`).toBe('info');
			const hits = framingViolations(f.title, f.detail);
			expect(hits, `non-owned attribution finding "${f.title}" carries ownership-framed prose: ${hits.join(', ')}`).toEqual([]);
		}
	});

	it('checkLookalikes: an owned_by_seed candidate gets no threat_observation finding at all', async () => {
		const result = await runLookalikesFixture();
		const ownedThreat = result.findings.filter(
			(f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === 'testc0.com',
		);
		expect(ownedThreat).toEqual([]);
	});

	it('classifyOwnership(): candidate-side signals — soaInBailiwick, spfIncludesSeedApex, httpRedirectToSeedApex — never independently or combined produce owned_by_seed (Ruling A, task 7c)', async () => {
		const { classifyOwnership } = await import('../../src/lib/ownership-attribution');
		const { isSharedNsHost } = await import('../../src/tenants/discovery/shared-ns-hosts');

		const base = {
			seedDomain: 'bnz.co.nz',
			seedNs: ['ns-cloud1.googledomains.com'],
			candidateDomain: 'evilbnz.co.nz',
			registration: { state: 'registered' as const, ns: ['ns1.attacker-dns.com'], evidence: ['ns' as const] },
			isSharedNsHost,
		};

		// Each signal alone.
		expect(classifyOwnership({ ...base, soaInBailiwick: true }).verdict).not.toBe('owned_by_seed');
		expect(classifyOwnership({ ...base, spfIncludesSeedApex: true }).verdict).not.toBe('owned_by_seed');
		expect(classifyOwnership({ ...base, httpRedirectToSeedApex: true }).verdict).not.toBe('owned_by_seed');

		// All three combined.
		const combined = classifyOwnership({
			...base,
			soaInBailiwick: true,
			spfIncludesSeedApex: true,
			httpRedirectToSeedApex: true,
		});
		expect(combined.verdict).not.toBe('owned_by_seed');
		expect(combined.verdict).toBe('third_party');
	});
});
