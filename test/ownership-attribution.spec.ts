// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect, afterEach } from 'vitest';
import { isSharedNsHost } from '../src/tenants/discovery/shared-ns-hosts';
import { UNKNOWN_REASON_PHRASES } from '../src/lib/registration-state';
import type { RegistrationState } from '../src/lib/registration-state';

function registered(ns: string[]): RegistrationState {
	return { state: 'registered', ns, evidence: ['ns'] };
}
const unregistered: RegistrationState = { state: 'unregistered' };
function unknown(reason: RegistrationState extends { state: 'unknown'; reason: infer R } ? R : never): RegistrationState {
	return { state: 'unknown', reason } as RegistrationState;
}

const SEED = 'bnz.co.nz';
const SEED_NS = ['a1-97.akam.net', 'a3-67.akam.net', 'a8-66.akam.net', 'a9-65.akam.net', 'a16-65.akam.net', 'a24-64.akam.net'];
const BNZ_APEX_NS = ['ns1.bnz.co.nz', 'ns2.bnz.co.nz', 'ns3.bnz.co.nz', 'ns4.bnz.co.nz'];

async function loadModule() {
	return import('../src/lib/ownership-attribution');
}

describe('classifyOwnership — §4 fixture corpus (2026-07-26 correctness-defects design)', () => {
	it('classifies in-bailiwick NZ/global variants as owned_by_seed (strong)', async () => {
		const { classifyOwnership } = await loadModule();
		for (const domain of ['bnz.nz', 'bnz.co', 'bnz.org.nz', 'bnz.net.nz', 'bnz.sg']) {
			const result = classifyOwnership({
				seedDomain: SEED,
				seedNs: SEED_NS,
				candidateDomain: domain,
				registration: registered(BNZ_APEX_NS),
				isSharedNsHost,
			});
			expect(result.verdict).toBe('owned_by_seed');
			expect(result.strength).toBe('strong');
			expect(result.signals).toContain('ns_in_bailiwick');
		}
	});

	it('classifies bankofnewzealand.co.nz / .com as owned_by_seed via in-bailiwick NS', async () => {
		const { classifyOwnership } = await loadModule();
		for (const domain of ['bankofnewzealand.co.nz', 'bankofnewzealand.com']) {
			const result = classifyOwnership({
				seedDomain: SEED,
				seedNs: SEED_NS,
				candidateDomain: domain,
				registration: registered(BNZ_APEX_NS),
				isSharedNsHost,
			});
			expect(result.verdict).toBe('owned_by_seed');
		}
	});

	it('classifies bnzpartners.co.nz as owned_by_seed via a complete (6/6) shared-provider match — medium strength', async () => {
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'bnzpartners.co.nz',
			registration: registered(SEED_NS.slice()),
			isSharedNsHost,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('medium');
		expect(result.signals).toContain('ns_shared_provider_complete');
	});

	it('does NOT attribute anz.co.nz or westpac.co.nz to the seed — the 1/6 Akamai trap (F5: tightened to exact verdict)', async () => {
		const { classifyOwnership } = await loadModule();
		const anzResult = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'anz.co.nz',
			registration: registered([
				'a1-6.akam.net',
				'a3-66.akam.net',
				'a6-65.akam.net',
				'a9-65.akam.net',
				'a12-66.akam.net',
				'a28-67.akam.net',
			]),
			isSharedNsHost,
		});
		expect(anzResult.verdict).toBe('third_party');

		const westpacResult = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'westpac.co.nz',
			registration: registered([
				'a1-55.akam.net',
				'a3-67.akam.net',
				'a6-65.akam.net',
				'a7-64.akam.net',
				'a14-65.akam.net',
				'a28-64.akam.net',
			]),
			isSharedNsHost,
		});
		expect(westpacResult.verdict).toBe('third_party');
	});

	it('a 3-of-6 overlap confined entirely to shared-provider NS hosts is NOT treated as dedicated-NS evidence', async () => {
		// Isolates the shared-host EXCLUSION step from the count/ratio threshold:
		// 3 shared hosts clears both DEDICATED_NS_MATCH_MIN_COUNT (>=2) and
		// DEDICATED_NS_MATCH_RATIO (3/6 = 0.5 >= 0.5), so if the implementation
		// ever computed "dedicated" overlap from the raw shared-NS set instead of
		// the set with shared-provider hosts excluded, this would wrongly flip to
		// owned_by_seed. The ANZ/Westpac fixtures (1/6) cannot catch this
		// specific defect because they never clear the count/ratio threshold in
		// the first place, regardless of exclusion.
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'shared-akamai-only.co.nz',
			registration: registered([SEED_NS[0], SEED_NS[1], SEED_NS[2], 'x1-1.akam.net', 'x2-2.akam.net', 'x3-3.akam.net']),
			isSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('a 1-of-4 overlap on DEDICATED (non-shared-provider) nameservers is below the >=50%-AND->=2 threshold and stays third_party', async () => {
		// Isolates the count/ratio threshold itself, using hosts that are NOT on
		// a SHARED_NS_APEXES provider (so the exclusion step in the previous
		// test cannot be what's protecting this one — only the
		// DEDICATED_NS_MATCH_MIN_COUNT/DEDICATED_NS_MATCH_RATIO check can). A
		// threshold weakened from ">=2 AND >=50%" down to a bare ">=1" would
		// wrongly flip this to owned_by_seed.
		const { classifyOwnership } = await loadModule();
		const dedicatedSeedNs = ['ns1.bnzcorp-dns.example', 'ns2.bnzcorp-dns.example', 'ns3.bnzcorp-dns.example', 'ns4.bnzcorp-dns.example'];
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: dedicatedSeedNs,
			candidateDomain: 'unrelated-dedicated-overlap.co.nz',
			registration: registered([
				'ns1.bnzcorp-dns.example',
				'ns1.someothercompany.example',
				'ns2.someothercompany.example',
				'ns3.someothercompany.example',
			]),
			isSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
	});

	it('classifies distinctly-hosted lookalikes as third_party', async () => {
		const { classifyOwnership } = await loadModule();
		for (const domain of ['bnz.de', 'bnz.jp', 'bnz.ca', 'bnz.ac.nz', 'hnz.co.nz', 'bbnz.co.nz']) {
			const result = classifyOwnership({
				seedDomain: SEED,
				seedNs: SEED_NS,
				candidateDomain: domain,
				registration: registered(['ns1.unrelated-registrar.example', 'ns2.unrelated-registrar.example']),
				isSharedNsHost,
			});
			expect(result.verdict).toBe('third_party');
		}
	});

	it('classifies an unregistered candidate as unattributed, with a distinguishing rationale', async () => {
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'bnz.kiwi',
			registration: unregistered,
			isSharedNsHost,
		});
		expect(result.verdict).toBe('unattributed');
		expect(result.rationale).toMatch(/not registered/i);
	});

	it('classifies a registration-unknown (SERVFAIL) candidate as unattributed, rendering the human-readable phrase (not the raw enum token)', async () => {
		const { classifyOwnership } = await loadModule();
		for (const domain of ['bnz.com', 'bnz.net']) {
			const result = classifyOwnership({
				seedDomain: SEED,
				seedNs: SEED_NS,
				candidateDomain: domain,
				registration: unknown('servfail'),
				isSharedNsHost,
			});
			expect(result.verdict).toBe('unattributed');
			expect(result.rationale).toMatch(/could not be determined/i);
			// Amendment (3): must render UNKNOWN_REASON_PHRASES.servfail verbatim,
			// not the bare internal token 'servfail' in parentheses. A prose sentence
			// containing ONLY the raw enum (e.g. "(servfail)") would satisfy the
			// /could not be determined/i check above but leak an internal token into
			// customer-facing text — this assertion is what actually discriminates.
			expect(result.rationale).toContain(UNKNOWN_REASON_PHRASES.servfail);
			expect(result.rationale).not.toMatch(/\(servfail\)/);
		}
	});

	it('renders the distinct phrase for a different UnknownReason (refused), proving the map is consulted per-reason and not hardcoded to servfail', async () => {
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'bnz.info',
			registration: unknown('refused'),
			isSharedNsHost,
		});
		expect(result.verdict).toBe('unattributed');
		expect(result.rationale).toContain(UNKNOWN_REASON_PHRASES.refused);
		expect(result.rationale).not.toContain(UNKNOWN_REASON_PHRASES.servfail);
	});
});

describe('isInBailiwick', () => {
	it('matches the apex itself and any subdomain', async () => {
		const { isInBailiwick } = await loadModule();
		expect(isInBailiwick('bnz.co.nz', 'bnz.co.nz')).toBe(true);
		expect(isInBailiwick('ns1.bnz.co.nz', 'bnz.co.nz')).toBe(true);
		expect(isInBailiwick('ns1.notbnz.co.nz', 'bnz.co.nz')).toBe(false);
		expect(isInBailiwick('bnz.co.nz.evil.example', 'bnz.co.nz')).toBe(false);
	});

	it('SECURITY PIN: does not match a lookalike label that merely ends with the seed apex as a substring (no dot boundary)', async () => {
		const { isInBailiwick } = await loadModule();
		// The real-world shape this guards: an attacker registers evilbnz.co.nz
		// and delegates ns1.evilbnz.co.nz. A bare `.endsWith(seedApex)` (no dot
		// prefix) would wrongly treat that as "under bnz.co.nz".
		expect(isInBailiwick('evilbnz.co.nz', 'bnz.co.nz')).toBe(false);
		expect(isInBailiwick('ns1.evilbnz.co.nz', 'bnz.co.nz')).toBe(false);
	});

	it('a malicious NS host shaped like the seed-apex-as-suffix does not flip classifyOwnership to owned_by_seed', async () => {
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'evilbnz.co.nz',
			registration: registered(['ns1.evilbnz.co.nz', 'ns2.evilbnz.co.nz']),
			isSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
	});
});

describe('Ruling B (2026-07-27 task-7c): in-bailiwick NS requires resolution evidence (the lame-delegation trap)', () => {
	// The attack: an attacker sets NS = ns1.bnz.co.nz in THEIR OWN parent-zone
	// delegation, but the seed's server never actually serves that zone (a
	// lame delegation). `RegistrationState` is a discriminated union — only
	// the `registered` arm carries an `ns` field, and `registered.ns` is
	// populated ONLY from an actually-resolved NS answer set (see
	// `resolveRegistrationUncached()` in `src/lib/registration-state.ts`,
	// which SERVFAILs/returns 'unknown' rather than fabricating `ns` data
	// when the delegation is broken). So the in-bailiwick verdict is
	// structurally unreachable without resolution evidence — this is a
	// PINNING test of that structural guarantee, not a behaviour change.
	it('the in-bailiwick verdict never fires for an unregistered candidate (no ns field exists on that arm)', async () => {
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'lame-delegation.co.nz',
			registration: unregistered,
			isSharedNsHost,
		});
		expect(result.verdict).not.toBe('owned_by_seed');
		expect(result.signals).not.toContain('ns_in_bailiwick');
	});

	it('the in-bailiwick verdict never fires for a registration-unknown (SERVFAIL) candidate, even if an in-bailiwick NS host is force-attached to the object', async () => {
		// Simulates the exact regression class the mandatory mutation targets:
		// something upstream (a bug, or a future refactor) forces NS data onto
		// an `unknown` registration state. The type system already forbids this
		// (`{ state: 'unknown'; reason }` has no `ns` member) — the cast below
		// is the only way to construct the malformed object at all, proving the
		// guard is the early `state === 'unknown'` return, not the type system
		// alone protecting runtime callers who bypass it (e.g. via `as any`
		// from an untyped boundary).
		const { classifyOwnership } = await loadModule();
		const forcedUnknownWithNs = {
			state: 'unknown',
			reason: 'servfail',
			ns: ['ns1.bnz.co.nz'],
		} as unknown as RegistrationState;
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'lame-delegation.co.nz',
			registration: forcedUnknownWithNs,
			isSharedNsHost,
		});
		expect(result.verdict).toBe('unattributed');
		expect(result.signals).not.toContain('ns_in_bailiwick');
	});

	it('a registered candidate whose only positive evidence is an A record (ns: []) cannot in-bailiwick-match, even against a seed apex it would otherwise nest under', async () => {
		// registration-state.ts's A-record escalation path returns `ns: []`
		// (evidence: ['a']) precisely because NS/SOA never resolved — this is
		// the "registered but no NS observed" shape a lame delegation produces
		// once the A-record fallback succeeds. There is no candidate NS to
		// filter for bailiwick, so the arm cannot fire.
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'a-only-lame.co.nz',
			registration: { state: 'registered', ns: [], evidence: ['a'] },
			isSharedNsHost,
		});
		expect(result.verdict).not.toBe('owned_by_seed');
		expect(result.signals).not.toContain('ns_in_bailiwick');
	});
});

// Ruling A (2026-07-27 task-7c) established that candidate-side signals
// (SOA RNAME, SPF `include:` target, HTTP redirect target) are corroborating
// only, NEVER verdict-bearing — an attacker who registers `evilbnz.co.nz`
// controls all three unilaterally, with no cooperation from the seed's
// owner. This file used to pin that rule with a `describe('Ruling A ...')`
// block driving `classifyOwnership()` via the (then-existing)
// `soaInBailiwick` / `spfIncludesSeedApex` / `httpRedirectToSeedApex` fields
// on `ClassifyOwnershipInput`.
//
// 2026-07-27 (ownership-attribution followups, item 2, "delete them" ruling):
// those three fields were DELETED from `ClassifyOwnershipInput` — they were
// accepted but never read by `classifyOwnership()`, and no production caller
// (`check-lookalikes.ts` / `check-shadow-domains.ts`) ever populated them, so
// they existed only as an attacker-influenceable footgun. That makes the
// block above UNCONSTRUCTIBLE (the fields no longer exist on the type) and it
// was removed rather than left disabled or type-cast around. The underlying
// rule is now enforced at the TYPE level — there is no input surface left
// for a candidate-side signal to reach `classifyOwnership()` at all — and is
// recorded in full in the `OWNERSHIP RULE` JSDoc on `ClassifyOwnershipInput`
// (`src/lib/ownership-attribution.ts`). A future author wiring a real
// SOA/SPF/redirect probe must read that note and re-derive the
// corroboration-only rule before reintroducing any such field.

describe('attributionConfidence — D4 minimum label length (WORDING classifier, renamed from passesAttributionGuard, never a severity gate)', () => {
	it('always corroborated for owned_by_seed regardless of label length', async () => {
		const { attributionConfidence } = await loadModule();
		expect(attributionConfidence('owned_by_seed', 'bnz', false)).toBe('corroborated');
	});

	it('uncorroborated for a short-label non-owned candidate with no corroboration', async () => {
		const { attributionConfidence } = await loadModule();
		expect(attributionConfidence('third_party', 'hnz', false)).toBe('uncorroborated');
	});

	it('corroborated for a short-label non-owned candidate when the caller supplies corroboration', async () => {
		const { attributionConfidence } = await loadModule();
		expect(attributionConfidence('third_party', 'hnz', true)).toBe('corroborated');
	});

	it('corroborated for a non-owned candidate at or above the minimum length with no corroboration needed', async () => {
		const { attributionConfidence } = await loadModule();
		expect(attributionConfidence('third_party', 'bankof', false)).toBe('corroborated');
	});
});

describe('capAttributionSeverity — F1 FIX: severity gates on ownership FIRST, never on label length/corroboration', () => {
	it('never caps owned_by_seed', async () => {
		const { capAttributionSeverity } = await loadModule();
		expect(capAttributionSeverity('owned_by_seed')).toBe('unbounded');
	});

	it("caps a SHORT-label non-owned candidate at 'info' (bnz is the campaign's own seed brand, 3 chars — demote never delete)", async () => {
		const { capAttributionSeverity } = await loadModule();
		expect(capAttributionSeverity('third_party')).toBe('info');
		expect(capAttributionSeverity('unattributed')).toBe('info');
	});

	it("F1 REGRESSION PIN: caps a LONG-label (>= MIN_ATTRIBUTION_LABEL_LENGTH) non-owned candidate at 'info' too — e.g. a competing bank like westpac must NEVER come back unbounded merely because its label is long enough to pass the D4 wording guard", async () => {
		// This is the exact defect F1 flagged: the first implementation
		// consulted attributionConfidence('third_party', 'westpac', false) —
		// which is 'corroborated' because 'westpac'.length (7) >=
		// MIN_ATTRIBUTION_LABEL_LENGTH (5) — and returned 'unbounded'. Label
		// length must NEVER be able to lift the ceiling off a non-owned verdict.
		const { capAttributionSeverity, MIN_ATTRIBUTION_LABEL_LENGTH } = await loadModule();
		expect('westpac'.length).toBeGreaterThanOrEqual(MIN_ATTRIBUTION_LABEL_LENGTH);
		expect(capAttributionSeverity('third_party')).toBe('info');
	});

	it('the return type structurally cannot represent "no finding" — only a Severity or the unbounded sentinel', async () => {
		const { capAttributionSeverity } = await loadModule();
		const capped = capAttributionSeverity('third_party');
		const uncapped = capAttributionSeverity('owned_by_seed');
		// Both are truthy, non-null strings — a caller cannot `if (!cap) continue`
		// their way into suppressing a finding, because there is no falsy value
		// this function can ever return.
		expect(capped).toBeTruthy();
		expect(uncapped).toBeTruthy();
		expect(typeof capped).toBe('string');
		expect(typeof uncapped).toBe('string');
	});
});

describe('load-bearing safety property (controller amendment 2): severity gates ONLY on owned_by_seed vs everything else', () => {
	it('third_party and unattributed are equally non-owned for capping purposes — the distinction is wording-only', async () => {
		const { capAttributionSeverity } = await loadModule();
		const thirdPartyCap = capAttributionSeverity('third_party');
		const unattributedCap = capAttributionSeverity('unattributed');
		expect(thirdPartyCap).toBe(unattributedCap);
		expect(thirdPartyCap).toBe('info');
	});
});

describe('buildNonOwnedGateFinding — cross-tool wording parity (F1, 2026-07-27 fix round 2)', () => {
	let restoreAfterThisTest: (() => void) | undefined;
	afterEach(() => {
		restoreAfterThisTest?.();
		restoreAfterThisTest = undefined;
	});

	/**
	 * F1: check-lookalikes.ts and check-shadow-domains.ts each used to
	 * hand-roll their own copy of the non-owned hedge sentence and had
	 * already drifted apart within a single slice ("Its DNS/mail posture" +
	 * no brand quote in lookalikes vs "Its mail posture" + quoted `"${brand}"`
	 * in shadow-domains) before review caught it. Both now call the SAME
	 * `buildNonOwnedGateFinding()` (`src/lib/ownership-attribution.ts`) with
	 * the same `postureNoun`. This is a UNIT-level pin on the shared function
	 * itself: if the two call sites ever again pass different `postureNoun`
	 * values, this test does not catch that (it can't see call-site source —
	 * see the end-to-end pin below for that). What it pins is that the shared
	 * function, given the SAME inputs, produces byte-identical output
	 * regardless of category/domain-key — i.e. there is no per-tool special
	 * casing hiding inside the shared function that could reintroduce drift.
	 */
	it('produces byte-identical hedge wording for two different (category, domainMetadataKey) callers given the same postureNoun', async () => {
		const { buildNonOwnedGateFinding, classifyOwnership } = await loadModule();
		const ownership = classifyOwnership({
			seedDomain: 'contoso.com',
			seedNs: ['ns1.primary-dns.com'],
			candidateDomain: 'contos0.com',
			registration: registered(['ns1.attacker-dns.com']),
			isSharedNsHost,
		});
		expect(ownership.verdict).toBe('third_party');

		const rawFinding = {
			category: 'lookalikes' as const,
			title: 'raw',
			severity: 'medium' as const,
			detail: 'raw detail',
			metadata: { lookalikeDomain: 'contos0.com' },
		};
		const lookalikeStyle = buildNonOwnedGateFinding(rawFinding, ownership, 'contoso', false, 'info', {
			category: 'lookalikes',
			domainMetadataKey: 'lookalikeDomain',
			postureNoun: 'DNS/mail posture',
		});

		const shadowStyleRaw = { ...rawFinding, category: 'shadow_domains' as const, metadata: { variant: 'contos0.com' } };
		const shadowStyle = buildNonOwnedGateFinding(shadowStyleRaw, ownership, 'contoso', false, 'info', {
			category: 'shadow_domains',
			domainMetadataKey: 'variant',
			postureNoun: 'DNS/mail posture',
		});

		// Only the finding category differs (each tool's own CheckCategory) —
		// the title and detail (the customer-facing legal-hedge sentence) are
		// byte-for-byte identical, since both resolve to the same candidate
		// domain string and the same postureNoun.
		expect(lookalikeStyle.title).toBe(shadowStyle.title);
		expect(lookalikeStyle.detail).toBe(shadowStyle.detail);
		expect(lookalikeStyle.category).toBe('lookalikes');
		expect(shadowStyle.category).toBe('shadow_domains');
	});

	/**
	 * End-to-end pin (proves the REAL call sites, not just the shared
	 * function, agree): runs both `checkLookalikes` and `checkShadowDomains`
	 * against a third_party MX-having candidate and asserts their emitted
	 * findings share the exact fixed frame around the posture noun. This is
	 * what catches a FUTURE regression where one tool's call site is edited
	 * to pass a different `postureNoun` while the other is not — the unit
	 * test above cannot see that (it calls the shared function directly with
	 * matched arguments), but this test exercises the actual production call
	 * sites in `check-lookalikes.ts` and `check-shadow-domains.ts`.
	 */
	it('check-lookalikes.ts and check-shadow-domains.ts emit the same fixed posture-noun frame end-to-end', async () => {
		const { setupFetchMock, createDohResponse } = await import('./helpers/dns-mock');
		const { restore } = setupFetchMock();
		restoreAfterThisTest = restore;
		{
			function parseDohQuery(input: string | URL | Request): { name: string; type: string } {
				const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
				const parsed = new URL(url);
				return { name: parsed.searchParams.get('name') ?? '', type: parsed.searchParams.get('type') ?? '' };
			}

			// --- check_lookalikes: seed contoso.com, third-party candidate with MX ---
			globalThis.fetch = (async (input: string | URL | Request) => {
				const { name, type } = parseDohQuery(input);
				if (name === 'contoso.com') {
					if (type === 'NS' || type === '2') {
						return createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]);
					}
				}
				if (name === 'contos0.com') {
					if (type === 'NS' || type === '2') {
						return createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.attacker-dns.com.' }]);
					}
					if (type === 'MX' || type === '15') {
						return createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.evil.com.' }]);
					}
				}
				return createDohResponse([], []);
			}) as unknown as typeof fetch;
			const { checkLookalikes } = await import('../src/tools/check-lookalikes');
			const lookalikeResult = await checkLookalikes('contoso.com');
			// Task 7b fix round 1 (F4): select on the AXIS, not on the verdict. Since
			// 7b the verdict travels on the threat-observation finding too, so the
			// old `ownershipVerdict === 'third_party'` selector matched BOTH axes and
			// landed on the attribution finding only by push order — the parity
			// contract is about the ATTRIBUTION wording, so say so structurally.
			const lookalikeFinding = lookalikeResult.findings.find((f) => f.metadata?.findingAxis === 'attribution');
			expect(lookalikeFinding).toBeDefined();

			// --- check_shadow_domains: seed example.com, third-party variant with MX, no SPF/DMARC ---
			globalThis.fetch = (async (input: string | URL | Request) => {
				const { name, type } = parseDohQuery(input);
				if (name === 'example.com' && (type === 'MX' || type === '15')) {
					return createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.example.com.' }]);
				}
				if (name === 'example.net') {
					if (type === 'NS' || type === '2') {
						return createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.registrar.com.' }]);
					}
					if (type === 'A' || type === '1') {
						return createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.1' }]);
					}
					if (type === 'MX' || type === '15') {
						return createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.shadow.com.' }]);
					}
				}
				return createDohResponse([], []);
			}) as unknown as typeof fetch;
			const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
			const shadowResult = await checkShadowDomains('example.com');
			const shadowFinding = shadowResult.findings.find(
				(f) =>
					(f.metadata as { variant?: string } | undefined)?.variant === 'example.net' && f.metadata?.ownershipVerdict === 'third_party',
			);
			expect(shadowFinding).toBeDefined();

			// The fixed frame around the posture noun — everything except the
			// noun itself and the candidate-domain substitutions — must be
			// byte-identical between the two tools.
			const FRAME =
				'is reported for awareness only: no action by the scanned organisation is implied, and this finding asserts no control over';
			expect(lookalikeFinding!.detail).toContain(`DNS/mail posture ${FRAME}`);
			expect(shadowFinding!.detail).toContain(`DNS/mail posture ${FRAME}`);
		}
	});
});

/**
 * DEFECT: OWNERSHIP INFERRED FROM NAMESERVER DELEGATION ALONE.
 *
 * `classifyOwnership()` is driven entirely by NS delegation — in-bailiwick NS,
 * dedicated NS-set match, or a complete shared-provider match. Anything else
 * registered with its own nameservers becomes `third_party`, and the report
 * then tells the customer the domain "is registered to a different
 * organisation" and offers to "report it to its registrar".
 *
 * A brand's OWN defensive registration routinely fails every one of those
 * tests: brand-protection registrars park defensive names on their own
 * infrastructure, not on the brand's production DNS. So a brand and its own
 * defensive misspelling, both held at the same corporate registrar, get split
 * apart — and the customer is advised to report their own domain for takedown.
 *
 * Two things make it worse than a wording bug:
 *   (a) the tool never even LOOKED. `computeSameEntityCandidates()` gates the
 *       RDAP fetch on a calibrated severity of medium-or-high, and a parked
 *       defensive registration (web-only, aged, no mail) calibrates LOW. The
 *       non-ownership claim is therefore asserted from an evidence set that
 *       was deliberately not gathered;
 *   (b) a downstream candidate generator depends on identifying brand-held
 *       registrations, so a false `third_party` propagates.
 *
 * THE SIGNAL USED HERE IS THE IANA REGISTRAR ID, NOT THE REGISTRANT ORG. The
 * registrant org is free text the registrant types (the reason Ruling A / F2
 * bars it from `classifyOwnership()`); the IANA registrar ID is assigned by
 * ICANN and published by the REGISTRY, so a registrant cannot set it. It still
 * only ever corroborates — no path here can produce `owned_by_seed`.
 */
describe('brand-held defensive registration — NS delegation is not the only ownership evidence', () => {
	let restoreThisTest: (() => void) | undefined;
	afterEach(() => {
		restoreThisTest?.();
		restoreThisTest = undefined;
	});

	/** IANA registrar IDs: CSC Corporate Domains = 299 (corporate-only), GoDaddy = 146 (retail). */
	const CSC_IANA_ID = '299';
	const GODADDY_IANA_ID = '146';

	function rdapDoc(opts: { ianaId: string; registrarName: string; registrationDaysAgo?: number; registrantOrg?: string }) {
		const days = opts.registrationDaysAgo ?? 3000;
		return {
			events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - days * 86_400_000).toISOString() }],
			entities: [
				{
					objectClassName: 'entity',
					roles: ['registrar'],
					publicIds: [{ type: 'IANA Registrar ID', identifier: opts.ianaId }],
					vcardArray: [
						'vcard',
						[
							['version', {}, 'text', '4.0'],
							['fn', {}, 'text', opts.registrarName],
						],
					],
				},
				// Registrant is REDACTED, as it is for most gTLD registrations
				// post-GDPR — so the existing registrant-org correlation cannot
				// fire and the registrar signal is doing all the work.
				{
					objectClassName: 'entity',
					roles: ['registrant'],
					vcardArray: [
						'vcard',
						[
							['version', {}, 'text', '4.0'],
							['fn', {}, 'text', opts.registrantOrg ?? 'REDACTED FOR PRIVACY'],
						],
					],
				},
			],
		};
	}

	/**
	 * Seed `contoso.com` + one candidate. The candidate always resolves to its
	 * OWN nameservers, so `classifyOwnership()` returns `third_party` in every
	 * variant below — the NS evidence is identical throughout and only the
	 * REGISTRATION RECORD and the infrastructure shape change.
	 */
	async function runFixture(opts: {
		candidate: string;
		candidateRdap: object;
		seedRdap: object;
		/** Defensive shape = parked: A record, no mail. Set true to give it live mail instead. */
		withMx?: boolean;
	}) {
		const { setupFetchMock, createDohResponse } = await import('./helpers/dns-mock');
		const { restore } = setupFetchMock();
		restoreThisTest = restore;
		globalThis.fetch = (async (input: string | URL | Request) => {
			const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
			if (url.includes('cloudflare-dns.com')) {
				const parsed = new URL(url);
				const name = parsed.searchParams.get('name') ?? '';
				const type = parsed.searchParams.get('type') ?? '';
				if (name === 'contoso.com' && (type === 'NS' || type === '2')) {
					return createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.primary-dns.com.' }]);
				}
				if (name === opts.candidate) {
					if (type === 'NS' || type === '2') {
						return createDohResponse([{ name, type: 2 }], [{ name, type: 2, TTL: 300, data: 'ns1.cscdns.net.' }]);
					}
					if (type === 'A' || type === '1') {
						return createDohResponse([{ name, type: 1 }], [{ name, type: 1, TTL: 300, data: '192.0.2.10' }]);
					}
					if ((type === 'MX' || type === '15') && opts.withMx) {
						return createDohResponse([{ name, type: 15 }], [{ name, type: 15, TTL: 300, data: '10 mail.contoso.com.' }]);
					}
				}
				return createDohResponse([], []);
			}
			if (url.includes('rdap') && url.includes(`/domain/${opts.candidate}`)) {
				return { ok: true, status: 200, json: () => Promise.resolve(opts.candidateRdap) } as unknown as Response;
			}
			if (url.includes('rdap') && url.includes('/domain/contoso.com')) {
				return { ok: true, status: 200, json: () => Promise.resolve(opts.seedRdap) } as unknown as Response;
			}
			// HEAD web probe — reachable (a parked redirect page).
			return { ok: true, status: 200, headers: new Headers(), json: () => Promise.resolve({}) } as unknown as Response;
		}) as unknown as typeof fetch;

		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		return checkLookalikes('contoso.com');
	}

	/** The defensive registration: parked at CSC, same corporate registrar as the seed. */
	const DEFENSIVE = {
		candidate: 'cont0so.com',
		candidateRdap: rdapDoc({ ianaId: CSC_IANA_ID, registrarName: 'CSC Corporate Domains, Inc.' }),
		seedRdap: rdapDoc({ ianaId: CSC_IANA_ID, registrarName: 'CSC Corporate Domains, Inc.' }),
	};

	function findingsFor(result: { findings: Array<{ metadata?: Record<string, unknown> }> }, domain: string) {
		return result.findings.filter((f) => f.metadata?.lookalikeDomain === domain);
	}

	it('recognises a defensive registration held at the same brand-protection registrar as the seed', async () => {
		const result = await runFixture(DEFENSIVE);
		const attribution = findingsFor(result, 'cont0so.com').find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution).toBeDefined();
		// THE DEFECT: this used to read "is registered to a different organisation".
		expect(attribution!.detail).not.toContain('is registered to a different organisation');
		expect(attribution!.metadata?.brandHeldRegistration).toBe(true);
		expect(attribution!.metadata?.sharedRegistrarIanaId).toBe(CSC_IANA_ID);
	});

	it('stops advising the customer to report their own domain to its registrar', async () => {
		const result = await runFixture(DEFENSIVE);
		const threat = findingsFor(result, 'cont0so.com').find((f) => f.metadata?.findingAxis === 'threat_observation');
		expect(threat).toBeDefined();
		expect(threat!.detail).not.toContain('report it to its registrar');
		expect(threat!.detail).not.toContain('takedown provider');
	});

	it('CONTROL — a shared RETAIL registrar is not ownership evidence and changes nothing', async () => {
		// Millions of unrelated registrants share GoDaddy. If this fixture ever
		// starts reading as brand-held, the predicate has stopped discriminating.
		const result = await runFixture({
			candidate: 'cont0so.com',
			candidateRdap: rdapDoc({ ianaId: GODADDY_IANA_ID, registrarName: 'GoDaddy.com, LLC' }),
			seedRdap: rdapDoc({ ianaId: GODADDY_IANA_ID, registrarName: 'GoDaddy.com, LLC' }),
		});
		const attribution = findingsFor(result, 'cont0so.com').find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution).toBeDefined();
		expect(attribution!.metadata?.brandHeldRegistration).toBeUndefined();
		expect(attribution!.detail).toContain('is registered to a different organisation');
	});

	it('CONTROL — a DIFFERENT registrar on each side is not ownership evidence', async () => {
		const result = await runFixture({
			candidate: 'cont0so.com',
			candidateRdap: rdapDoc({ ianaId: '1234', registrarName: 'Bulk Register LLC' }),
			seedRdap: rdapDoc({ ianaId: CSC_IANA_ID, registrarName: 'CSC Corporate Domains, Inc.' }),
		});
		const attribution = findingsFor(result, 'cont0so.com').find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution!.metadata?.brandHeldRegistration).toBeUndefined();
		expect(attribution!.detail).toContain('is registered to a different organisation');
	});

	it('CONTROL — TWO DIFFERENT brand-protection registrars are not a match either', async () => {
		// The discriminating case for the registrar-EQUALITY check specifically.
		// The variant above cannot test it: its candidate registrar is not in the
		// brand-protection set, so the set-membership check rejects the candidate
		// even when the equality check is deleted. Here BOTH sides are corporate
		// registrars, so equality is the only thing standing between this fixture
		// and a false brand-held verdict — as a mutation run confirmed (deleting
		// the equality line left the variant above green and only this one red).
		const result = await runFixture({
			candidate: 'cont0so.com',
			candidateRdap: rdapDoc({ ianaId: CSC_IANA_ID, registrarName: 'CSC Corporate Domains, Inc.' }),
			seedRdap: rdapDoc({ ianaId: '292', registrarName: 'MarkMonitor Inc.' }),
		});
		const attribution = findingsFor(result, 'cont0so.com').find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution!.metadata?.brandHeldRegistration).toBeUndefined();
		expect(attribution!.detail).toContain('is registered to a different organisation');
	});

	it('CONTROL — an absent registrar ID on either side is never treated as a match', async () => {
		// `null === null` must not read as "same registrar". Pins the fail-soft
		// direction: no registration evidence means no corroboration, never
		// corroboration by default.
		const noRegistrar = {
			events: [{ eventAction: 'registration', eventDate: new Date(Date.now() - 3000 * 86_400_000).toISOString() }],
			entities: [],
		};
		const result = await runFixture({
			candidate: 'cont0so.com',
			candidateRdap: noRegistrar,
			seedRdap: noRegistrar,
		});
		const attribution = findingsFor(result, 'cont0so.com').find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution!.metadata?.brandHeldRegistration).toBeUndefined();
		expect(attribution!.detail).toContain('is registered to a different organisation');
	});

	it('CONTROL — a shared corporate registrar does NOT excuse live mail infrastructure', async () => {
		// An attacker who somehow lands at the same corporate registrar still
		// gets the full threat treatment: the registrar corroborates ownership
		// only for a candidate whose INFRASTRUCTURE is also defensively shaped.
		const result = await runFixture({ ...DEFENSIVE, withMx: true });
		const attribution = findingsFor(result, 'cont0so.com').find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution!.metadata?.brandHeldRegistration).toBeUndefined();
		const threat = findingsFor(result, 'cont0so.com').find((f) => f.metadata?.findingAxis === 'threat_observation');
		expect(threat!.detail).toContain('report it to its registrar');
	});

	it('never manufactures owned_by_seed — the structural verdict stays third_party on registrar evidence alone', async () => {
		// Ruling A: only SEED-SIDE nameserver evidence may produce owned_by_seed.
		// A registry-published registrar ID is stronger than a registrant-typed
		// org string but it is still not proof of common ownership.
		const result = await runFixture(DEFENSIVE);
		for (const finding of findingsFor(result, 'cont0so.com')) {
			expect(finding.metadata?.ownershipVerdict).toBe('third_party');
		}
	});

	/**
	 * THE LOAD-BEARING BOUNDARY. This fix is allowed to change WHICH DOMAINS ARE
	 * FOUND and what the report SAYS about them. It is not allowed to change how
	 * a found domain SCORES — per-check scores are locked downstream against the
	 * vendored scoring package.
	 *
	 * `computeCategoryScore` is a pure function of finding severities (plus an
	 * optional `penaltyOverride`), and `buildCheckResult` additionally zeroes the
	 * category when `scoreIndicatesMissingControl()` matches finding TEXT on a
	 * critical/high finding — which is the one way a WORDING change could move a
	 * score. Both are pinned here.
	 */
	it('BOUNDARY: rewording the brand-held case moves no score', async () => {
		const brandHeld = await runFixture(DEFENSIVE);
		const retail = await runFixture({
			candidate: 'cont0so.com',
			candidateRdap: rdapDoc({ ianaId: GODADDY_IANA_ID, registrarName: 'GoDaddy.com, LLC' }),
			seedRdap: rdapDoc({ ianaId: GODADDY_IANA_ID, registrarName: 'GoDaddy.com, LLC' }),
		});
		// Same probe inputs, same severities, therefore the same category score —
		// only the prose and the attribution metadata differ.
		expect(brandHeld.score).toBe(retail.score);
		expect(brandHeld.passed).toBe(retail.passed);
		const severities = (r: typeof brandHeld) => r.findings.map((f) => f.severity).sort();
		expect(severities(brandHeld)).toEqual(severities(retail));
	});

	it('BOUNDARY: no wording this path emits trips the missing-control text rule', async () => {
		const { scoreIndicatesMissingControl } = await import('@blackveil/dns-checks/scoring');
		const result = await runFixture(DEFENSIVE);
		expect(scoreIndicatesMissingControl(result.findings)).toBe(false);

		// The assertion above alone is VACUOUS: `scoreIndicatesMissingControl`
		// only inspects critical/high findings, and this fixture calibrates
		// `low`/`info`. Re-run it with every finding forced to `high` so the
		// predicate is decided by the TEXT — the actual risk, since a phrase
		// like "no MX records" inside a high-severity finding zeroes the whole
		// category score. This is the trap the wording of the new brand-held
		// finding and DEFENSIVE_REASON_PHRASES is written to avoid.
		const asHigh = result.findings.map((f) => ({ ...f, severity: 'high' as const }));
		expect(scoreIndicatesMissingControl(asHigh)).toBe(false);
	});
});
