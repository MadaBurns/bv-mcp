// SPDX-License-Identifier: BUSL-1.1

/**
 * #929 (mirror of #263 / #864) — a SHARED-PLATFORM nameserver pair is not
 * ownership evidence, in any quantity.
 *
 * `check_lookalikes`, `check_shadow_domains` and `discover_brand_domains` all
 * attributed every one.com tenant to a one.com-hosted seed at
 * `owned_by_seed` / `strong` / confidence 1 on `ns_set_match` alone, and
 * worded it as "shares 2/2 DEDICATED nameservers". Live (DoH, 2026-09-09):
 *
 *   net-agents.dk   NS ns01.one.com, ns02.one.com   (seed, one.com shared hosting)
 *   net-agent.dk    NS ns01.one.com, ns02.one.com   (lookalike permutation)
 *   net-agents.com  NS ns01.one.com, ns02.one.com   (TLD shadow variant)
 *   one.com         NS auth.g1-dns.com, auth.g1-dns.one
 *
 * one.com hands EVERY tenant the identical `ns01`/`ns02` pair, so a complete
 * 2/2 match is the default relationship between any two unrelated one.com
 * customers — and, worse, a squatter who hosts a lookalike at one.com would
 * have its own threat finding capped at `info` by the seed's platform choice.
 * `#897`'s rule applies: a verdict may rest only on something the SEED alone
 * can publish. A platform-assigned NS set is not that.
 *
 * Two classes of shared-tenant provider now exist in
 * `src/tenants/discovery/shared-ns-hosts.ts`:
 *   - POOLED (`akam.net`): hostnames drawn per zone from a large pool, so a
 *     COMPLETE set match still implies one account (design §3.3, 2026-07-26;
 *     `ns_shared_provider_complete`, medium). The only members that earn that.
 *   - everything else (parking, registrar defaults, one.com): every tenant
 *     receives the same set, so a complete match declines with the new
 *     `ns_shared_platform` signal — `unattributed` when the two whole sets
 *     are identical (nothing distinct was observed, so the report must not
 *     call the customer's own alias "a different organisation"), `third_party`
 *     when the candidate also carries its own distinct hosts (the squatter's
 *     cheapest shape). Severity ceiling unchanged (D4: non-owned → `info`).
 *
 * `classifyOwnership()` takes the pooled predicate as an OPTIONAL injected
 * input and defaults it to "nothing is pooled": a caller that forgets it
 * fails SAFE (no platform is credited), never open.
 */

import { describe, it, expect, afterEach, vi } from 'vitest';
import { setupFetchMock, createDohResponse } from './helpers/dns-mock';
import { isSharedNsHost, isPooledSharedNsHost, SHARED_NS_APEXES, POOLED_SHARED_NS_APEXES } from '../src/tenants/discovery/shared-ns-hosts';
import type { RegistrationState } from '../src/lib/registration-state';
import type { DmarcReportAuthorisation } from '../src/lib/ownership-attribution';
import type { DohResponse } from '../src/lib/dns-types';

const { restore } = setupFetchMock();
afterEach(() => restore());

// ---------------------------------------------------------------------------
// Live-transcribed records (2026-09-09)
// ---------------------------------------------------------------------------

const SEED = 'net-agents.dk';
const ONE_COM_NS = ['ns01.one.com', 'ns02.one.com'];
const AKAMAI_NS = ['a1-97.akam.net', 'a3-67.akam.net', 'a8-66.akam.net', 'a9-65.akam.net', 'a16-65.akam.net', 'a24-64.akam.net'];

function registered(ns: string[]): RegistrationState {
	return { state: 'registered', ns, evidence: ['ns'] };
}

async function loadAttribution() {
	return import('../src/lib/ownership-attribution');
}

// ---------------------------------------------------------------------------
// Provider classification
// ---------------------------------------------------------------------------

describe('shared-ns-hosts — one.com is a shared platform, and pooled ⊆ shared (#929)', () => {
	it('classifies ns01/ns02.one.com as shared-tenant hosts', () => {
		for (const host of ONE_COM_NS) expect(isSharedNsHost(host)).toBe(true);
		expect(isSharedNsHost('auth.g1-dns.com')).toBe(false);
	});

	it('does NOT class one.com as pooled — a complete pair match earns nothing', () => {
		for (const host of ONE_COM_NS) expect(isPooledSharedNsHost(host)).toBe(false);
	});

	it('classes Akamai as pooled — the one shared provider where a complete set match is evidence', () => {
		expect(isPooledSharedNsHost('a1-97.akam.net')).toBe(true);
		expect(isSharedNsHost('a1-97.akam.net')).toBe(true);
	});

	it('every pooled apex is also a shared apex (a pooled host must never reach the dedicated arm)', () => {
		for (const apex of POOLED_SHARED_NS_APEXES) expect(SHARED_NS_APEXES.has(apex)).toBe(true);
	});

	it('returns false for empty input and for hosts on no known provider', () => {
		expect(isPooledSharedNsHost('')).toBe(false);
		expect(isPooledSharedNsHost('ns1.example.com')).toBe(false);
		expect(isPooledSharedNsHost('alice.ns.cloudflare.com')).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// Unit — classifyOwnership()
// ---------------------------------------------------------------------------

describe('classifyOwnership — a complete match on a shared PLATFORM pair is not ownership (#929)', () => {
	it('net-agent.dk on the same one.com pair as the seed is unattributed, never owned_by_seed / strong', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: ONE_COM_NS,
			candidateDomain: 'net-agent.dk',
			registration: registered(ONE_COM_NS.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		// `unattributed`, not `third_party`: identical whole sets on the platform
		// observe NO distinct infrastructure, and the gate template words
		// `third_party` as "registered to a different organisation" — false for
		// the customer's own alias hosted at the same provider.
		expect(result.verdict).toBe('unattributed');
		expect(result.strength).toBe('none');
		expect(result.signals).toEqual(['ns_shared_platform']);
		expect(result.rationale).toContain('one.com');
		expect(result.rationale).not.toContain('dedicated');
		expect(result.rationale).not.toContain('no ownership signal links it');
	});

	it('a candidate carrying ONLY the platform half of a seed that also has its own hosts is unattributed (candidate ⊂ seed)', async () => {
		// Seed = 2 own hosts + the one.com pair; candidate = the one.com pair
		// alone. The candidate has NO remaining nameservers, so the `third_party`
		// sentence ("its remaining nameservers are distinct") would be false and
		// the gate would call a possible alias "a different organisation"
		// (PR #937 re-verification). The seed's total must not enter the test.
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: ['ns1.net-agents.dk', 'ns2.net-agents.dk', ...ONE_COM_NS],
			candidateDomain: 'net-agent.dk',
			registration: registered(ONE_COM_NS.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('unattributed');
		expect(result.signals).toEqual(['ns_shared_platform']);
		expect(result.rationale).not.toContain('remaining nameservers');
	});

	it("the squatter's cheapest shape — the seed's one.com pair PLUS its own ns1.attacker host — is third_party, never owned", async () => {
		// Step 4 used to accept this: `sharedNs.length === seedTotal` held and
		// every shared host was on a shared provider, so the extra attacker host
		// was invisible to the arm.
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: ONE_COM_NS,
			candidateDomain: 'net-agent.dk',
			registration: registered([...ONE_COM_NS, 'ns1.attacker.example']),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.strength).toBe('none');
		expect(result.signals).toEqual(['ns_shared_platform']);
		expect(result.rationale).toContain('remaining nameservers are distinct');
	});

	it('the pooled predicate defaults CLOSED: without it even a complete 6/6 Akamai match declines', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'bnz.co.nz',
			seedNs: AKAMAI_NS,
			candidateDomain: 'bnzpartners.co.nz',
			registration: registered(AKAMAI_NS.slice()),
			isSharedNsHost,
		});
		expect(result.verdict).toBe('unattributed');
		expect(result.signals).toEqual(['ns_shared_platform']);
	});

	it('with the pooled predicate the Akamai 6/6 arm still yields owned_by_seed (medium) — unchanged behaviour', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'bnz.co.nz',
			seedNs: AKAMAI_NS,
			candidateDomain: 'bnzpartners.co.nz',
			registration: registered(AKAMAI_NS.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('medium');
		expect(result.signals).toEqual(['ns_shared_provider_complete']);
	});

	it('a partial overlap confined to platform hosts is worded as platform plumbing, not "distinct infrastructure"', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'bnz.co.nz',
			seedNs: AKAMAI_NS,
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
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.signals).toEqual(['ns_shared_platform']);
		expect(result.rationale).toContain('1/6');
		expect(result.rationale).toContain('remaining nameservers are distinct');
	});

	it('a candidate on the same platform that ALSO holds the seed-published DMARC grant is still owned_by_seed via step 5b', async () => {
		const { classifyOwnership } = await loadAttribution();
		const authorised: DmarcReportAuthorisation = {
			status: 'authorised',
			seedReceivers: ['dmarc.net-agents.dk'],
			receiverDomain: 'dmarc.net-agents.dk',
			authorisationRecord: 'net-agents.com._report._dmarc.dmarc.net-agents.dk',
		};
		const result = classifyOwnership({
			seedDomain: SEED,
			seedNs: ONE_COM_NS,
			candidateDomain: 'net-agents.com',
			registration: registered(ONE_COM_NS.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
			candidateMx: ['mail.net-agents.dk'],
			dmarcReportAuthorisation: authorised,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('medium');
		expect(result.signals).toEqual(['mx_in_bailiwick', 'dmarc_report_authorised_by_seed']);
	});

	it('the dedicated arm no longer claims "dedicated" — it says what was measured', async () => {
		const { classifyOwnership } = await loadAttribution();
		const dedicated = ['ns1.corp-dns.example', 'ns2.corp-dns.example'];
		const result = classifyOwnership({
			seedDomain: 'corp.example',
			seedNs: dedicated,
			candidateDomain: 'corp-sibling.example',
			registration: registered(dedicated.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('strong');
		expect(result.rationale).toContain('2/2 nameservers');
		expect(result.rationale).toContain('none on a known shared-tenant provider');
	});
});

// ---------------------------------------------------------------------------
// #1039 — the exact-set match that mixes dedicated and shared-provider hosts
// ---------------------------------------------------------------------------

/**
 * Live (DoH, 2026-09-18): `barclays.com` delegates to nine hosts — six on
 * Akamai (a shared, pooled platform) and three `ns*.barcap.com` of its own.
 * `barclays.co.uk` carries the byte-identical set, and was still reported
 * `third_party` with "no ownership signal links it": the off-platform three
 * are 3/9 = 33%, under step 3's ratio, and step 4's every-matched-host-is-
 * shared test fails on those same three.
 *
 * The exact-set arm (step 3b) requires BOTH set identity and at least two
 * DISTINCT matched hosts on no known shared provider. The last case below is
 * what defends the second guard against a future loosening to one.
 */
describe('classifyOwnership — an EXACT set match mixing dedicated and platform hosts (#1039)', () => {
	const BARCAP_NS = ['ns2.barcap.com', 'ns3.barcap.com', 'ns7.barcap.com'];
	const BARCLAYS_AKAMAI_NS = [
		'a1-71.akam.net',
		'a9-66.akam.net',
		'a10-66.akam.net',
		'a11-67.akam.net',
		'a12-64.akam.net',
		'a18-65.akam.net',
	];
	const BARCLAYS_NS = [...BARCLAYS_AKAMAI_NS, ...BARCAP_NS];

	it('barclays.co.uk on the identical 9/9 mixed set is owned_by_seed / strong, not "no ownership signal links it"', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'barclays.com',
			seedNs: BARCLAYS_NS,
			candidateDomain: 'barclays.co.uk',
			registration: registered(BARCLAYS_NS.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('owned_by_seed');
		expect(result.strength).toBe('strong');
		expect(result.signals).toEqual(['ns_set_match']);
		expect(result.rationale).toContain('complete 9-nameserver set');
		for (const host of BARCAP_NS) expect(result.rationale).toContain(host);
		expect(result.rationale).not.toContain('no ownership signal links it');
	});

	it('an ALL-shared exact set of the same size stays unattributed — #929 is not regressed', async () => {
		// Same nine-host shape, but the three off-platform hosts are replaced by
		// hosts on a listed shared platform: nothing off-platform is matched, so
		// the new arm must decline exactly as before.
		const { classifyOwnership } = await loadAttribution();
		const allShared = [...BARCLAYS_AKAMAI_NS, 'ns33.domaincontrol.com', 'ns34.domaincontrol.com', 'ns35.domaincontrol.com'];
		for (const host of allShared) expect(isSharedNsHost(host)).toBe(true);
		const result = classifyOwnership({
			seedDomain: 'tenant-seed.example',
			seedNs: allShared,
			candidateDomain: 'tenant-lookalike.example',
			registration: registered(allShared.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('unattributed');
		expect(result.signals).toEqual(['ns_shared_platform']);
	});

	it('an 8-of-9 near miss is not a set match — still third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'barclays.com',
			seedNs: BARCLAYS_NS,
			candidateDomain: 'barclays-secure-login.example',
			registration: registered([...BARCLAYS_AKAMAI_NS.slice(1), ...BARCAP_NS]),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.signals).toEqual(['distinct_infrastructure']);
	});

	it('a candidate SUPERSET — the whole seed set plus one attacker host — is not a set match, still third_party', async () => {
		const { classifyOwnership } = await loadAttribution();
		const result = classifyOwnership({
			seedDomain: 'barclays.com',
			seedNs: BARCLAYS_NS,
			candidateDomain: 'barclays-secure-login.example',
			registration: registered([...BARCLAYS_NS, 'ns1.attacker.example']),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).toBe('third_party');
		expect(result.signals).toEqual(['distinct_infrastructure']);
	});

	it('two listed-shared hosts plus ONE unlisted host, exactly matched, stays non-owned — the pin that holds the bar at two', async () => {
		// A squatter buys the same self-service platform pair and adds one host
		// of its own; the seed happens to be shaped the same way. Only one
		// matched host is off-platform, which is under
		// `DEDICATED_NS_MATCH_MIN_COUNT` — do not loosen that bar to one.
		const { classifyOwnership } = await loadAttribution();
		const pairPlusOne = ['ns33.domaincontrol.com', 'ns34.domaincontrol.com', 'ns1.small-host.example'];
		expect(isSharedNsHost('ns33.domaincontrol.com')).toBe(true);
		expect(isSharedNsHost('ns1.small-host.example')).toBe(false);
		const result = classifyOwnership({
			seedDomain: 'smallbiz.example',
			seedNs: pairPlusOne,
			candidateDomain: 'smallbizz.example',
			registration: registered(pairPlusOne.slice()),
			isSharedNsHost,
			isPooledSharedNsHost,
		});
		expect(result.verdict).not.toBe('owned_by_seed');
		expect(result.verdict).toBe('third_party');
	});
});

// ---------------------------------------------------------------------------
// discover_brand_domains — the NS correlator
// ---------------------------------------------------------------------------

function nsResponse(name: string, hosts: string[]): DohResponse {
	return {
		Status: 0,
		TC: false,
		RD: true,
		RA: true,
		AD: false,
		CD: false,
		Question: [{ name, type: 2 }],
		Answer: hosts.map((data) => ({ name, type: 2, TTL: 3600, data: `${data}.` })),
	};
}

describe('correlateNs — a one.com pair contributes no co-ownership signal (#929)', () => {
	it('drops net-agent.dk / net-agents.com entirely instead of reporting confidence 1 set_overlap', async () => {
		const { correlateNs } = await import('../src/tenants/discovery/ns-correlator');
		const zones: Record<string, string[]> = {
			[SEED]: ONE_COM_NS,
			'net-agent.dk': ONE_COM_NS,
			'net-agents.com': ONE_COM_NS,
		};
		const dnsQuery = vi.fn(async (name: string) => {
			const key = name.toLowerCase().replace(/\.$/, '');
			const hosts = zones[key];
			return hosts ? nsResponse(key, hosts) : { ...nsResponse(key, []), Answer: [] };
		});
		const result = await correlateNs(SEED, { dnsQuery, candidateDomains: ['net-agent.dk', 'net-agents.com'] });
		expect(result.queryStatus).toBe('ok');
		expect(result.coOwnedDomains).toEqual([]);
	});
});

// ---------------------------------------------------------------------------
// End-to-end — checkLookalikes() and checkShadowDomains()
// ---------------------------------------------------------------------------

type RecordName = 'NS' | 'A' | 'MX' | 'SOA' | 'TXT';
const TYPE_CODE: Record<RecordName, number> = { NS: 2, A: 1, MX: 15, SOA: 6, TXT: 16 };
const CODE_TYPE: Record<string, RecordName> = {
	'2': 'NS',
	NS: 'NS',
	'1': 'A',
	A: 'A',
	'15': 'MX',
	MX: 'MX',
	'6': 'SOA',
	SOA: 'SOA',
	'16': 'TXT',
	TXT: 'TXT',
};
type Zone = Partial<Record<RecordName, string[]>>;

function dohAnswer(name: string, type: RecordName, records: string[]) {
	return createDohResponse(
		[{ name, type: TYPE_CODE[type] }],
		records.map((data) => ({ name, type: TYPE_CODE[type], TTL: 300, data: type === 'TXT' ? `"${data}"` : data })),
	);
}

/** DoH from `zones`; a registrar-only RDAP document (`.dk` has no RDAP live, so nothing is asserted on it); 200 for HEAD probes. */
function installMock(zones: Record<string, Zone>): void {
	globalThis.fetch = vi.fn().mockImplementation((input: string | URL | Request) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const parsed = new URL(url);
		const qName = parsed.searchParams.get('name');
		const qType = parsed.searchParams.get('type');
		if (qName !== null && qType !== null) {
			const name = qName.toLowerCase().replace(/\.$/, '');
			const type = CODE_TYPE[qType.toUpperCase()];
			const records = type ? zones[name]?.[type] : undefined;
			if (records && type) return Promise.resolve(dohAnswer(name, type, records));
			return Promise.resolve(createDohResponse([], []));
		}
		if (url.includes('rdap')) {
			const body = {
				objectClassName: 'domain',
				entities: [{ roles: ['registrar'], vcardArray: ['vcard', [['fn', {}, 'text', 'Registrar Inc']]] }],
			};
			return Promise.resolve(new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/rdap+json' } }));
		}
		return Promise.resolve(new Response('', { status: 200 }));
	});
}

/** The live shape: one.com pair, null MX, DMARC reject on both seed and candidates. */
const ONE_COM_ZONE: Zone = { NS: ONE_COM_NS.map((h) => `${h}.`), A: ['46.30.211.1'], MX: ['0 .'] };
const DMARC_REJECT: Zone = { TXT: ['v=DMARC1; p=reject'] };

describe('checkLookalikes — net-agents.dk → net-agent.dk on the same one.com pair (#929)', () => {
	it('does not attribute the candidate to the seed, and never says "dedicated"', async () => {
		installMock({
			[SEED]: ONE_COM_ZONE,
			[`_dmarc.${SEED}`]: DMARC_REJECT,
			'net-agent.dk': ONE_COM_ZONE,
			'_dmarc.net-agent.dk': DMARC_REJECT,
		});
		const { checkLookalikes } = await import('../src/tools/check-lookalikes');
		const result = await checkLookalikes(SEED);

		const own = result.findings.filter((f) => f.metadata?.lookalikeDomain === 'net-agent.dk');
		expect(own.length).toBeGreaterThan(0);
		expect(own.some((f) => f.metadata?.ownershipVerdict === 'owned_by_seed')).toBe(false);
		expect(own.some((f) => f.metadata?.ownershipStrength === 'strong')).toBe(false);
		const attribution = own.find((f) => f.metadata?.findingAxis === 'attribution');
		expect(attribution).toBeDefined();
		expect(attribution!.metadata?.ownershipVerdict).toBe('unattributed');
		// The attribution finding carries the verdict's rationale (the gate
		// template does not surface `signals`): it must name the platform hosts,
		// and neither its title nor its detail may claim the domain is someone
		// else's — ground truth is unknown, and it may be the customer's own.
		expect(attribution!.metadata?.ownershipRationale).toContain('ns01.one.com');
		expect(attribution!.metadata?.ownershipRationale).toContain('shared-tenant DNS platform');
		expect(attribution!.title).toBe('Confusable label, ownership not established: net-agent.dk');
		expect(attribution!.detail).toContain('could not be attributed to the scanned organisation');
		expect(attribution!.detail).not.toContain('registered to a different organisation');
		expect(attribution!.title).not.toContain('Unrelated');
		// D4 ceiling on the ATTRIBUTION axis: a non-owned candidate's attribution
		// finding is capped at info. The observed-threat axis (Task 7b) is a
		// separate, uncapped finding — it must still be emitted, and it must
		// carry the same non-owned verdict.
		expect(attribution!.severity).toBe('info');
		const threat = own.find((f) => f.metadata?.findingAxis === 'threat_observation');
		expect(threat).toBeDefined();
		expect(threat!.metadata?.ownershipVerdict).toBe('unattributed');

		const serialised = JSON.stringify(result.findings);
		expect(serialised).not.toContain('dedicated');
		expect(serialised).not.toContain('likely owned by same entity');
		expect(result.partial).not.toBe(true);
	});
});

describe('checkShadowDomains — net-agents.dk → net-agents.com on the same one.com pair (#929)', () => {
	it('marks the .com variant unattributed (info-capped), not owned_by_seed', async () => {
		installMock({
			[SEED]: ONE_COM_ZONE,
			[`_dmarc.${SEED}`]: DMARC_REJECT,
			'net-agents.com': ONE_COM_ZONE,
			'_dmarc.net-agents.com': DMARC_REJECT,
		});
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains(SEED);

		const com = result.findings.filter((f) => (f.metadata as { variant?: string } | undefined)?.variant === 'net-agents.com');
		expect(com.length).toBeGreaterThan(0);
		for (const f of com) {
			expect(f.metadata?.ownershipVerdict).not.toBe('owned_by_seed');
			expect(f.severity).toBe('info');
		}
		expect(com.some((f) => f.metadata?.ownershipVerdict === 'unattributed')).toBe(true);
		const serialised = JSON.stringify(result.findings);
		expect(serialised).not.toContain('dedicated nameservers');
		expect(serialised).not.toContain('registered to a different organisation');
		// Before the fix this variant took the OWNED ladder: `high` "Shadow domain
		// fully spoofable … Likely same owner" for a squatter on the seed's
		// platform. Now nothing above info is emitted about it.
		expect(serialised).not.toContain('Likely same owner');
	});

	it('the "Shared NS across shadow domains" rollup does not suggest common ownership for a platform pair', async () => {
		installMock({
			[SEED]: ONE_COM_ZONE,
			[`_dmarc.${SEED}`]: DMARC_REJECT,
			'net-agents.com': ONE_COM_ZONE,
			'_dmarc.net-agents.com': DMARC_REJECT,
			'net-agents.org': ONE_COM_ZONE,
			'_dmarc.net-agents.org': DMARC_REJECT,
		});
		const { checkShadowDomains } = await import('../src/tools/check-shadow-domains');
		const result = await checkShadowDomains(SEED);
		const rollup = result.findings.find((f) => f.title === 'Shared NS across shadow domains');
		expect(rollup).toBeDefined();
		expect(rollup!.severity).toBe('info');
		expect(rollup!.metadata?.sharedPlatform).toBe(true);
		expect(rollup!.detail).toContain('not evidence of common ownership');
		expect(rollup!.detail).not.toContain('suggesting common ownership');
	});
});
