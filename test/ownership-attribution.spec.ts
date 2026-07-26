// SPDX-License-Identifier: BUSL-1.1
import { describe, it, expect } from 'vitest';
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

describe('F4 (security, flagged not fixed): attacker-influenceable evidence branches — pinning CURRENT behaviour', () => {
	// These three flags are NOT gathered by any caller in this slice, but the
	// branches exist and were previously untested. Per the reviewer's F4
	// instruction, the verdict mapping itself is NOT being changed here (that
	// call belongs to the design owner) — these tests only pin what the
	// current code does, so a future change to the mapping is a deliberate,
	// visible diff here rather than a silent behaviour change.
	it('soaInBailiwick ALONE (no NS evidence at all) currently produces owned_by_seed/strong', async () => {
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'evilbnz.co.nz',
			registration: registered(['ns1.totally-unrelated-registrar.example']),
			isSharedNsHost,
			soaInBailiwick: true,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('strong');
		expect(result.signals).toContain('soa_in_bailiwick');
	});

	it('spfIncludesSeedApex ALONE currently produces owned_by_seed/strong — attacker-controllable, unresolved', async () => {
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'evilbnz.co.nz',
			registration: registered(['ns1.totally-unrelated-registrar.example']),
			isSharedNsHost,
			spfIncludesSeedApex: true,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('strong');
		expect(result.signals).toContain('spf_include_seed');
	});

	it('httpRedirectToSeedApex ALONE currently produces owned_by_seed/strong — attacker-controllable, unresolved', async () => {
		const { classifyOwnership } = await loadModule();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: SEED_NS,
			candidateDomain: 'evilbnz.co.nz',
			registration: registered(['ns1.totally-unrelated-registrar.example']),
			isSharedNsHost,
			httpRedirectToSeedApex: true,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('strong');
		expect(result.signals).toContain('http_redirect_seed');
	});
});

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
