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
 * Ownership framing in prose ("shadow domain", "your", "owned by same
 * entity") is likewise never permitted on a non-owned finding, on EITHER
 * axis — a threat observation describes the CANDIDATE's behaviour, never
 * the scanned organisation's ownership of it.
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
 *         in metadata that is DISTINCT FROM THE SCANNED SEED — `lookalikeDomain`
 *         preferred; `lookalikeDomains`/`domain` accepted only as a fallback,
 *         and only when the value is not the seed itself (fix round 1, F4 —
 *         the predicate used to accept a bare `meta.domain` unconditionally,
 *         which is exactly what the recon-corroboration emission site in
 *         `check-lookalikes.ts` used to set to the SEED, not a candidate)).
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
 *          !== 'owned_by_seed'` and names a candidate (per the tightened
 *          predicate in (1));
 *        - every finding of ANY axis for a non-owned candidate carries NO
 *          ownership-framed prose ("shadow domain", "your", "owned by same
 *          entity") in its title or detail (fix round 1, F2 — the original
 *          version of this audit only framing-checked the `attribution` axis,
 *          leaving a `critical` `threat_observation` titled e.g. "Your shadow
 *          domain portfolio is exposed" undetected).
 *      `check-shadow-domains.ts` carries a SEPARATE, single carve-out for
 *      this same framing rule — `AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE` (the
 *      Phase-2 "records not observed" fallthrough keeps its ownership-framed
 *      title because `registration-invariant.audit.test.ts` — byte-frozen —
 *      pins that exact title literal). This audit asserts that carve-out is
 *      EXACTLY one title and EXACTLY the known string, so it cannot silently
 *      widen to swallow other framed titles. `checkLookalikes` has NO such
 *      carve-out — the framing sweep against it is unconditional.
 *
 *  (3) THE PRIMITIVE-LEVEL INVARIANT (task 7c). The three candidate-side
 *      signals (`soaInBailiwick`, `spfIncludesSeedApex`, `httpRedirectToSeedApex`)
 *      must never — alone or combined — produce `owned_by_seed` from
 *      `classifyOwnership()` directly. Pinned once more here (unit tests
 *      already pin it) so a future "optimisation" of those unit tests can't
 *      silently drop the property from BOTH places at once.
 *
 *  (4) FIX ROUND 1 (2026-07-27, adversarial re-review). Four findings, all
 *      addressed:
 *        F1 — LIVE VIOLATION. `check-lookalikes.ts`'s recon-corroboration
 *             emission site (`CT_LOOKALIKE`) emitted a `medium`
 *             `threat_observation` with NO `ownershipVerdict` and
 *             `domain: <the seed>` — a real production bug this audit's
 *             ORIGINAL fixture set never exercised (no recon-binding
 *             fixture existed). Fixed at the SOURCE (see
 *             `extractReconMatchedDomain()` + the emission site in
 *             `check-lookalikes.ts`) and now covered by
 *             `runLookalikesReconFixture()` below, permanently inside the
 *             sweep.
 *        F2 — the framing sweep now covers every axis, not just `attribution`
 *             (see amendment (2) above).
 *        F3 — an EXPECTED-VERDICT map (`assertExpectedVerdicts` below) pins
 *             each fixture's candidates to their REQUIRED stamped verdict, so
 *             a mutation that stamps `owned_by_seed` everywhere (which would
 *             trivially satisfy the severity-justification sweep AND exit the
 *             framing filter simultaneously) is still caught.
 *        F4 — the named-candidate predicate tightened (see amendment (1)).
 *
 * METHOD NOTE: every clause below was proven to go RED by a real source
 * mutation — see `.superpowers/sdd/2026-07-26-slice4-ownership-attribution/
 * task-8-report.md` (fix round 1 addendum) for the mutation-by-mutation
 * evidence, including the F1 live-violation fix, the A5/A8b/A8c re-runs. The
 * mutations themselves are not preserved in this file; only their proof they
 * were run.
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

function normalizeDomain(d: string): string {
	return d.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * F4 (fix round 1): the named-candidate predicate. `lookalikeDomain` is
 * PREFERRED and authoritative when present — it is never overridden by a
 * fallback field even if it happens to equal the seed (in which case this
 * correctly returns false rather than silently trying `domain` next).
 * `lookalikeDomains` (the aggregate summary) and `domain` (the shadow-domains
 * "variant" field lives under a different key entirely — see
 * `assertExpectedVerdicts`'s `domainKeys` param — this predicate is scoped to
 * the fields `checkLookalikes` actually emits) are accepted as fallbacks, and
 * ONLY when the named value is not the seed itself.
 */
function namesNonSeedCandidate(meta: Record<string, unknown> | undefined, seedNorm: string): boolean {
	if (typeof meta?.lookalikeDomain === 'string') {
		const v = meta.lookalikeDomain.trim();
		return v !== '' && normalizeDomain(v) !== seedNorm;
	}
	if (Array.isArray(meta?.lookalikeDomains) && meta.lookalikeDomains.length > 0) {
		return meta.lookalikeDomains.some((d) => typeof d === 'string' && d.trim() !== '' && normalizeDomain(d) !== seedNorm);
	}
	if (typeof meta?.domain === 'string') {
		const v = meta.domain.trim();
		return v !== '' && normalizeDomain(v) !== seedNorm;
	}
	return false;
}

/**
 * Amendment (1) — THE positive-assertion rule. Returns violations rather than
 * throwing immediately so a single sweep can report every offender at once.
 * `seedDomain` is required (F4) so the named-candidate check can reject a
 * self-referential match.
 */
function findSeverityViolations(tool: string, seedDomain: string, findings: readonly Finding[]): Violation[] {
	const seedNorm = normalizeDomain(seedDomain);
	const violations: Violation[] = [];
	for (const f of findings) {
		if (f.severity === 'info') continue;
		const meta = f.metadata as Record<string, unknown> | undefined;
		const verdict = meta?.ownershipVerdict;
		if (verdict === 'owned_by_seed') continue;

		const axis = meta?.findingAxis;
		if (axis === 'threat_observation' && verdict !== undefined && verdict !== 'owned_by_seed') {
			if (namesNonSeedCandidate(meta, seedNorm)) continue;
			violations.push({
				tool,
				title: f.title,
				severity: f.severity,
				reason: 'threat_observation above info names no candidate domain distinct from the seed',
			});
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

function assertSeverityJustified(tool: string, seedDomain: string, findings: readonly Finding[]) {
	assertNonEmpty(tool, findings);
	const violations = findSeverityViolations(tool, seedDomain, findings);
	expect(violations, `${tool}: unjustified above-info findings:\n${JSON.stringify(violations, null, 2)}`).toEqual([]);
}

const BANNED_FRAMING = [/shadow domain/i, /\byour\b/i, /owned by same entity/i];

function framingViolations(title: string, detail: string): string[] {
	return BANNED_FRAMING.filter((re) => re.test(title) || re.test(detail)).map((re) => re.source);
}

/**
 * F2 (fix round 1) — framing sweep across EVERY finding whose stamped
 * verdict is present and `!== 'owned_by_seed'`, regardless of `findingAxis`.
 * `carveOutTitle`, when supplied, exempts exactly one title
 * (`check-shadow-domains.ts`'s `AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE`) — never
 * a pattern, never a prefix, so it cannot silently widen.
 */
function findFramingViolations(tool: string, findings: readonly Finding[], carveOutTitle?: string): Violation[] {
	const violations: Violation[] = [];
	for (const f of findings) {
		const verdict = (f.metadata as Record<string, unknown> | undefined)?.ownershipVerdict;
		if (verdict === undefined || verdict === 'owned_by_seed') continue;
		if (carveOutTitle !== undefined && f.title === carveOutTitle) continue;
		const hits = framingViolations(f.title, f.detail);
		if (hits.length > 0) {
			violations.push({ tool, title: f.title, severity: f.severity, reason: `ownership-framed prose: ${hits.join(', ')}` });
		}
	}
	return violations;
}

/**
 * F3 (fix round 1) — EXPECTED-VERDICT map. Asserts every finding that names a
 * fixture-known candidate (via one of `domainKeys`, checked in priority
 * order) carries the REQUIRED stamped verdict for that candidate. This is
 * the check that survives a mutation stamping `owned_by_seed` on every
 * finding: such a mutation trivially satisfies `findSeverityViolations` (the
 * exemption fires) AND `findFramingViolations` (the framing filter exits
 * early on `owned_by_seed`) simultaneously — only a check that TRUSTS NOTHING
 * about the stamped verdict and instead compares it against an independently
 * declared expectation can catch it.
 */
function assertExpectedVerdicts(
	tool: string,
	findings: readonly Finding[],
	domainKeys: readonly string[],
	mustBeOwned: ReadonlySet<string>,
	mustNotBeOwned: ReadonlySet<string>,
) {
	for (const f of findings) {
		const meta = f.metadata as Record<string, unknown> | undefined;
		let candidate: string | undefined;
		for (const key of domainKeys) {
			const v = meta?.[key];
			if (typeof v === 'string' && v.trim() !== '') {
				candidate = v;
				break;
			}
		}
		if (candidate === undefined) continue;
		const norm = normalizeDomain(candidate);
		const verdict = meta?.ownershipVerdict;
		if (mustBeOwned.has(norm)) {
			expect(verdict, `${tool}: "${f.title}" for ${candidate} must be stamped owned_by_seed`).toBe('owned_by_seed');
		}
		if (mustNotBeOwned.has(norm)) {
			expect(verdict, `${tool}: "${f.title}" for ${candidate} must NOT be stamped owned_by_seed`).not.toBe('owned_by_seed');
		}
	}
}

// =============================================================================
// Fixture A — checkShadowDomains, one combined scan carrying every required
// scenario: owned (in-bailiwick), third-party with active-MX threat signals,
// the shared-provider (Akamai) partial-overlap trap, and the "registered,
// records not observed" unattributed carve-out branch.
// =============================================================================

const SHADOW_SEED = 'bnz.co.nz';
const SHADOW_MUST_BE_OWNED = new Set(['bnz.com']);
const SHADOW_MUST_NOT_BE_OWNED = new Set(['bnz.de', 'bnz.eu', 'bnz.ca', 'bnz.jp']);

async function runShadowDomainsFixture() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const q = parseDohQuery(input);
		if (!q) return Promise.resolve(empty());
		const { name, type } = q;

		if (name === SHADOW_SEED) {
			if (type === 'NS' || type === '2') return Promise.resolve(nsRecords(SHADOW_SEED, SEED_AKAMAI_NS));
			if (type === 'MX' || type === '15') return Promise.resolve(mxRecords(SHADOW_SEED, ['10 mail.bnz.co.nz.']));
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
	return checkShadowDomains(SHADOW_SEED);
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

const LOOKALIKES_SEED = 'testco.com';
const LOOKALIKES_MUST_BE_OWNED = new Set(['testc0.com']);
const LOOKALIKES_MUST_NOT_BE_OWNED = new Set(['twstco.com', 'trstco.com']);

/** DNS mock shared by every checkLookalikes fixture below (recon options vary per caller). */
function mockLookalikesFixtureDns() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const q = parseDohQuery(input);
		if (!q) return Promise.resolve(empty());
		const { name, type } = q;

		if (name === LOOKALIKES_SEED && (type === 'NS' || type === '2')) return Promise.resolve(nsRecords(LOOKALIKES_SEED, SEED_AKAMAI_NS));

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
}

async function runLookalikesFixture() {
	mockLookalikesFixtureDns();
	const { checkLookalikes } = await import('../../src/tools/check-lookalikes');
	return checkLookalikes(LOOKALIKES_SEED);
}

/** A fully clean scan: nothing registered anywhere. Sanity + vacuous-green guard target. */
async function runLookalikesCleanFixture() {
	globalThis.fetch = vi.fn().mockImplementation(() => Promise.resolve(empty()));
	const { checkLookalikes } = await import('../../src/tools/check-lookalikes');
	return checkLookalikes('nomatch918273brand.com');
}

/**
 * F1 (fix round 1) — the recon-binding fixture. Stubs `BV_RECON` (the
 * operator-deploy-only enrichment binding — this code path ships in prod)
 * returning a CT_LOOKALIKE hit naming `twstco.com` as `metadata.matchedDomain`
 * — a candidate ALSO generated/probed locally by this same scan (so
 * `ownershipByDomain` genuinely resolves it, exercising the "reuse the local
 * assessment" branch of the source fix, not just its null-fallback branch).
 * This keeps the recon emission site permanently INSIDE the sweep.
 */
async function runLookalikesReconFixture() {
	mockLookalikesFixtureDns();
	const reconBinding = {
		fetch: vi.fn(
			async () =>
				new Response(
					JSON.stringify({
						checkType: 'CT_LOOKALIKE',
						status: 'warning',
						details: 'Certificate transparency logs show lookalike activity for twstco.com',
						metadata: { matchedDomain: 'twstco.com' },
					}),
					{ status: 200, headers: { 'Content-Type': 'application/json' } },
				),
		),
	};
	const { checkLookalikes } = await import('../../src/tools/check-lookalikes');
	return checkLookalikes(LOOKALIKES_SEED, { reconBinding, reconAuthToken: 'tok' });
}

/**
 * A5 re-run target — the post-loop `if (findings.length === 0)` scan_status
 * notice (`check-lookalikes.ts` ~line 793) is reachable ONLY when at least
 * one permutation is registered (so the tool doesn't early-return before
 * reaching the main classification loop) AND every registered permutation
 * has neither an A nor an MX record (so the loop's
 * `if (!result.hasMX && !result.hasA) continue;` guard skips it, pushing
 * NOTHING). `tstco.com` here is registered (NS only) with no A/MX — the
 * ONLY registered permutation in this fixture — so `findings` is genuinely
 * empty when the loop exits.
 */
async function runLookalikesPostLoopScanStatusFixture() {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const q = parseDohQuery(input);
		if (!q) return Promise.resolve(empty());
		const { name, type } = q;
		if (name === LOOKALIKES_SEED && (type === 'NS' || type === '2')) return Promise.resolve(nsRecords(LOOKALIKES_SEED, SEED_AKAMAI_NS));
		if (name === 'tstco.com' && (type === 'NS' || type === '2')) return Promise.resolve(nsRecords(name, ['ns1.registrar.com.']));
		return Promise.resolve(empty());
	});
	const { checkLookalikes } = await import('../../src/tools/check-lookalikes');
	return checkLookalikes(LOOKALIKES_SEED);
}

// =============================================================================
// Tests
// =============================================================================

describe('ownership severity gate (audit) — load-bearing safety property', () => {
	it('checkShadowDomains: no above-info finding without ownership justification (positive-assertion sweep, exhaustive)', async () => {
		const result = await runShadowDomainsFixture();
		assertSeverityJustified('checkShadowDomains', SHADOW_SEED, result.findings);
		assertExpectedVerdicts('checkShadowDomains', result.findings, ['variant'], SHADOW_MUST_BE_OWNED, SHADOW_MUST_NOT_BE_OWNED);

		// Sanity the fixture actually exercised both directions, not just a
		// uniformly-info result that would make the sweep trivially green.
		expect(result.findings.some((f) => f.severity !== 'info')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
	});

	it('checkShadowDomains: clean scan sweeps green and is never vacuously empty', async () => {
		const result = await runShadowDomainsCleanFixture();
		assertSeverityJustified('checkShadowDomains (clean)', 'cleanbrand9182.com', result.findings);
		expect(result.findings.every((f) => f.severity === 'info')).toBe(true);
	});

	it('checkShadowDomains: ownership framing absent from non-owned findings (all axes — shadow-domains has none — so this is unconditional), except the exactly-one audit-pinned carve-out', async () => {
		const { AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE } = await import('../../src/tools/check-shadow-domains');
		expect(AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE).toBe('Shadow domain registered, records not observed');

		const result = await runShadowDomainsFixture();
		const nonOwnedCount = result.findings.filter((f) => {
			const v = f.metadata?.ownershipVerdict;
			return v !== undefined && v !== 'owned_by_seed';
		}).length;
		expect(nonOwnedCount).toBeGreaterThan(0);

		const violations = findFramingViolations('checkShadowDomains', result.findings, AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE);
		expect(violations, `framed titles: ${JSON.stringify(violations, null, 2)}`).toEqual([]);

		// The carve-out itself must actually have been exercised by this
		// fixture (bnz.ca) — otherwise "exactly one" is an unverified claim.
		expect(result.findings.some((f) => f.title === AUDIT_PINNED_OWNERSHIP_FRAMED_TITLE)).toBe(true);
	});

	it('checkLookalikes: no above-info finding without ownership justification (positive-assertion sweep, exhaustive)', async () => {
		const result = await runLookalikesFixture();
		assertSeverityJustified('checkLookalikes', LOOKALIKES_SEED, result.findings);
		assertExpectedVerdicts('checkLookalikes', result.findings, ['lookalikeDomain'], LOOKALIKES_MUST_BE_OWNED, LOOKALIKES_MUST_NOT_BE_OWNED);

		expect(result.findings.some((f) => f.severity === 'high')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(true);
		expect(result.findings.some((f) => f.metadata?.ownershipVerdict === 'third_party')).toBe(true);
	});

	it('checkLookalikes: clean scan sweeps green and is never vacuously empty', async () => {
		const result = await runLookalikesCleanFixture();
		assertSeverityJustified('checkLookalikes (clean)', 'nomatch918273brand.com', result.findings);
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
			expect(
				namesNonSeedCandidate(f.metadata as Record<string, unknown> | undefined, normalizeDomain(LOOKALIKES_SEED)),
				`threat_observation "${f.title}" names no candidate distinct from the seed`,
			).toBe(true);
		}

		// F2: framing sweep across EVERY axis for this fixture set — not just
		// 'attribution'. checkLookalikes carries no carve-out.
		const violations = findFramingViolations('checkLookalikes', result.findings);
		expect(violations, `framed findings: ${JSON.stringify(violations, null, 2)}`).toEqual([]);
	});

	it('checkLookalikes: an owned_by_seed candidate gets no threat_observation finding at all', async () => {
		const result = await runLookalikesFixture();
		const ownedThreat = result.findings.filter(
			(f) => f.metadata?.findingAxis === 'threat_observation' && f.metadata?.lookalikeDomain === 'testc0.com',
		);
		expect(ownedThreat).toEqual([]);
	});

	// F1 (fix round 1) — the recon-corroboration emission site, permanently
	// inside the sweep. Runs the FULL invariant battery (severity
	// justification, expected-verdict map, and framing) against a fixture
	// whose ONLY new finding relative to `runLookalikesFixture()` is the
	// recon-corroboration one, so a regression at that specific emission
	// site cannot hide behind the other candidates' correct output.
	it('checkLookalikes: the recon-corroboration finding (CT_LOOKALIKE) carries a real ownershipVerdict and names the matched candidate, not the seed', async () => {
		const result = await runLookalikesReconFixture();
		assertSeverityJustified('checkLookalikes (recon)', LOOKALIKES_SEED, result.findings);
		assertExpectedVerdicts(
			'checkLookalikes (recon)',
			result.findings,
			['lookalikeDomain'],
			LOOKALIKES_MUST_BE_OWNED,
			LOOKALIKES_MUST_NOT_BE_OWNED,
		);
		const framingHits = findFramingViolations('checkLookalikes (recon)', result.findings);
		expect(framingHits).toEqual([]);

		const reconFindings = result.findings.filter((f) => f.metadata?.reconEnriched === true);
		expect(reconFindings).toHaveLength(1);
		const reconFinding = reconFindings[0];
		expect(reconFinding.severity).toBe('medium');
		expect(reconFinding.metadata?.findingAxis).toBe('threat_observation');
		expect(reconFinding.metadata?.lookalikeDomain).toBe('twstco.com');
		expect(reconFinding.metadata?.domain).toBeUndefined();
		expect(reconFinding.metadata?.ownershipVerdict).toBe('third_party');
	});

	// A5 re-run (fix round 1) — this branch was UNREACHABLE by either the
	// main or clean fixture before this dedicated fixture was added (the main
	// fixture always has findings before reaching it; the clean fixture
	// early-returns before it). Proves it is now reachable AND swept.
	it('checkLookalikes: the previously-unreachable post-loop scan_status notice fires and is swept', async () => {
		const result = await runLookalikesPostLoopScanStatusFixture();
		assertNonEmpty('checkLookalikes (post-loop scan_status)', result.findings);
		const notice = result.findings.find((f) => f.title === 'No active lookalike domains detected');
		expect(notice, 'the post-loop scan_status notice did not fire — the fixture no longer reaches it').toBeDefined();
		expect(notice!.metadata?.findingAxis).toBe('scan_status');
		expect(notice!.severity).toBe('info');
		assertSeverityJustified('checkLookalikes (post-loop scan_status)', LOOKALIKES_SEED, result.findings);
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
